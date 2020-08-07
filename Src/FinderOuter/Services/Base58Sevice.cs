// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.Encoders;
using FinderOuter.Backend;
using FinderOuter.Backend.Cryptography.Hashing;
using FinderOuter.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using System.Threading;
using System.Threading.Tasks;

namespace FinderOuter.Services
{
    public class Base58Sevice
    {
        public Base58Sevice(IReport rep)
        {
            inputService = new InputService();
            encoder = new Base58();
            report = rep;
        }


        private readonly IReport report;
        private readonly InputService inputService;
        private readonly Base58 encoder;
        private uint[] powers58, precomputed;
        private int[] missingIndexes;
        private int missCount;
        private string keyToCheck;


        public enum InputType
        {
            PrivateKey,
            Address,
            Bip38
        }

        private void Initialize(char[] key, char missingChar, InputType keyType)
        {
            // Compute 58^n for n from 0 to inputLength as uint[]

            byte[] padded;
            int uLen = keyType switch
            {
                InputType.PrivateKey => 10, // Maximum result (58^52) is 39 bytes = 39/4 = 10 uint
                InputType.Address => 7, // Maximum result (58^35) is 26 bytes = 26/4 = 7 uint
                InputType.Bip38 => 11, // Maximum result (58^58) is 43 bytes = 43/4 = 11 uint
                _ => throw new ArgumentException("Input type is not defined yet."),
            };
            powers58 = new uint[key.Length * uLen];
            padded = new byte[4 * uLen];
            precomputed = new uint[uLen];

            for (int i = 0, j = 0; i < key.Length; i++)
            {
                BigInteger val = BigInteger.Pow(58, i);
                byte[] temp = val.ToByteArrayExt(false, true);

                Array.Clear(padded, 0, padded.Length);
                Buffer.BlockCopy(temp, 0, padded, 0, temp.Length);

                for (int k = 0; k < padded.Length; j++, k += 4)
                {
                    powers58[j] = (uint)(padded[k] << 0 | padded[k + 1] << 8 | padded[k + 2] << 16 | padded[k + 3] << 24);
                }
            }

            // calculate what we already have and store missing indexes
            int mis = 0;
            for (int i = key.Length - 1, j = 0; i >= 0; i--)
            {
                if (key[i] != missingChar)
                {
                    ulong carry = 0;
                    ulong val = (ulong)ConstantsFO.Base58Chars.IndexOf(key[i]);
                    for (int k = uLen - 1; k >= 0; k--, j++)
                    {
                        ulong result = checked((powers58[j] * val) + precomputed[k] + carry);
                        precomputed[k] = (uint)result;
                        carry = (uint)(result >> 32);
                    }
                }
                else
                {
                    missingIndexes[mis] = key.Length - i - 1;
                    mis++;
                    j += uLen;
                }
            }
        }


        private BigInteger GetTotalCount(int missCount) => BigInteger.Pow(58, missCount);

        private void SetResultParallel(IEnumerable<int> missingItems, int firstItem)
        {
            report.AddMessageSafe($"Found a possible result (will continue checking the rest):");

            char[] temp = keyToCheck.ToCharArray();
            int i = 0;
            if (firstItem != -1)
            {
                temp[temp.Length - missingIndexes[i++] - 1] = ConstantsFO.Base58Chars[firstItem];
            }
            foreach (var index in missingItems)
            {
                temp[temp.Length - missingIndexes[i++] - 1] = ConstantsFO.Base58Chars[index];
            }

            report.AddMessageSafe(new string(temp));
            report.FoundAnyResult = true;
            return;
        }


        private unsafe void LoopComp(uint[] precomputed, int firstItem, int misStart, IEnumerable<IEnumerable<int>> cartesian)
        {
            using Sha256Fo sha = new Sha256Fo();

            uint[] temp = new uint[precomputed.Length];
            fixed (uint* hPt = &sha.hashState[0], wPt = &sha.w[0])
            fixed (uint* pow = &powers58[0], pre = &precomputed[0], tmp = &temp[0])
            fixed (int* mi = &missingIndexes[misStart])
            {
                foreach (var item in cartesian)
                {
                    Buffer.MemoryCopy(pre, tmp, 40, 40);
                    int mis = 0;
                    foreach (var keyItem in item)
                    {
                        ulong carry = 0;
                        for (int k = 9, j = 0; k >= 0; k--, j++)
                        {
                            ulong result = (pow[(mi[mis] * 10) + j] * (ulong)keyItem) + tmp[k] + carry;
                            tmp[k] = (uint)result;
                            carry = (uint)(result >> 32);
                        }
                        mis++;
                    }

                    if (((tmp[0] & 0x0000ff00) | (tmp[8] & 0x000000ff)) != 0x00008001)
                    {
                        continue;
                    }

                    wPt[0] = (tmp[0] << 16) | (tmp[1] >> 16);
                    wPt[1] = (tmp[1] << 16) | (tmp[2] >> 16);
                    wPt[2] = (tmp[2] << 16) | (tmp[3] >> 16);
                    wPt[3] = (tmp[3] << 16) | (tmp[4] >> 16);
                    wPt[4] = (tmp[4] << 16) | (tmp[5] >> 16);
                    wPt[5] = (tmp[5] << 16) | (tmp[6] >> 16);
                    wPt[6] = (tmp[6] << 16) | (tmp[7] >> 16);
                    wPt[7] = (tmp[7] << 16) | (tmp[8] >> 16);
                    wPt[8] = (tmp[8] << 16) | 0b00000000_00000000_10000000_00000000U;
                    // from 9 to 14 =0
                    wPt[15] = 272; // 34 *8 = 272

                    sha.Init(hPt);
                    sha.CompressDouble34(hPt, wPt);

                    if (hPt[0] == tmp[9])
                    {
                        SetResultParallel(item, firstItem);
                    }
                }
            }

            report.IncrementProgress();
        }
        private unsafe uint[] ParallelPre(int firstItem)
        {
            uint[] localPre = new uint[precomputed.Length];
            fixed (uint* lpre = &localPre[0], pre = &precomputed[0], pow = &powers58[0])
            {
                Buffer.MemoryCopy(pre, lpre, 40, 40);
                int index = missingIndexes[0];
                ulong carry = 0;
                for (int k = 9, j = 0; k >= 0; k--, j++)
                {
                    ulong result = (pow[(index * 10) + j] * (ulong)firstItem) + lpre[k] + carry;
                    lpre[k] = (uint)result;
                    carry = (uint)(result >> 32);
                }
            }

            return localPre;
        }
        private unsafe void LoopComp()
        {
            if (missCount >= 5)
            {
                // 4 missing chars is 11,316,496 cases and it takes <2 seconds to run.
                // That makes 5 the optimal number for using parallelization
                report.SetProgressStep(58);
                report.AddMessageSafe("Running in parallel.");
                var cartesian = CartesianProduct.Create(Enumerable.Repeat(Enumerable.Range(0, 58), missCount - 1));
                Parallel.For(0, 58, (firstItem) => LoopComp(ParallelPre(firstItem), firstItem, 1, cartesian));
            }
            else
            {
                var cartesian = CartesianProduct.Create(Enumerable.Repeat(Enumerable.Range(0, 58), missCount));
                LoopComp(precomputed, -1, 0, cartesian);
            }
        }

        private unsafe void LoopUncomp(uint[] precomputed, int firstItem, int misStart, IEnumerable<IEnumerable<int>> cartesian)
        {
            using Sha256Fo sha = new Sha256Fo();

            uint[] temp = new uint[precomputed.Length];
            fixed (uint* hPt = &sha.hashState[0], wPt = &sha.w[0])
            fixed (uint* pow = &powers58[0], pre = &precomputed[0], tmp = &temp[0])
            fixed (int* mi = &missingIndexes[misStart])
            {
                foreach (var item in cartesian)
                {
                    Buffer.MemoryCopy(pre, tmp, 40, 40);
                    int mis = 0;
                    foreach (var keyItem in item)
                    {
                        ulong carry = 0;
                        for (int k = 9, j = 0; k >= 0; k--, j++)
                        {
                            ulong result = (pow[(mi[mis] * 10) + j] * (ulong)keyItem) + tmp[k] + carry;
                            tmp[k] = (uint)result;
                            carry = (uint)(result >> 32);
                        }
                        mis++;
                    }

                    if (tmp[0] != 0x00000080)
                    {
                        continue;
                    }

                    wPt[0] = (tmp[0] << 24) | (tmp[1] >> 8);
                    wPt[1] = (tmp[1] << 24) | (tmp[2] >> 8);
                    wPt[2] = (tmp[2] << 24) | (tmp[3] >> 8);
                    wPt[3] = (tmp[3] << 24) | (tmp[4] >> 8);
                    wPt[4] = (tmp[4] << 24) | (tmp[5] >> 8);
                    wPt[5] = (tmp[5] << 24) | (tmp[6] >> 8);
                    wPt[6] = (tmp[6] << 24) | (tmp[7] >> 8);
                    wPt[7] = (tmp[7] << 24) | (tmp[8] >> 8);
                    wPt[8] = (tmp[8] << 24) | 0b00000000_10000000_00000000_00000000U;
                    // from 9 to 14 = 0
                    wPt[15] = 264; // 33 *8 = 264

                    sha.Init(hPt);
                    sha.CompressDouble33(hPt, wPt);

                    if (hPt[0] == tmp[9])
                    {
                        SetResultParallel(item, firstItem);
                    }
                }
            }

            report.IncrementProgress();
        }
        private unsafe void LoopUncomp()
        {
            if (missCount >= 5)
            {
                report.SetProgressStep(58);
                report.AddMessageSafe("Running in parallel.");
                var cartesian = CartesianProduct.Create(Enumerable.Repeat(Enumerable.Range(0, 58), missCount - 1));
                Parallel.For(0, 58, (firstItem) => LoopUncomp(ParallelPre(firstItem), firstItem, 1, cartesian));
            }
            else
            {
                var cartesian = CartesianProduct.Create(Enumerable.Repeat(Enumerable.Range(0, 58), missCount));
                LoopUncomp(precomputed, -1, 0, cartesian);
            }
        }

        private unsafe bool SpecialLoopComp(string key)
        {
            byte[] padded;
            int uLen;

            // Maximum result (58^52) is 39 bytes = 39/4 = 10 uint
            uLen = 10;
            uint[] powers58 = new uint[ConstantsFO.PrivKeyCompWifLen * uLen];
            padded = new byte[4 * uLen];

            for (int i = 0, j = 0; i < ConstantsFO.PrivKeyCompWifLen; i++)
            {
                BigInteger val = BigInteger.Pow(58, i);
                byte[] temp = val.ToByteArray(true, false);

                Array.Clear(padded, 0, padded.Length);
                Buffer.BlockCopy(temp, 0, padded, 0, temp.Length);

                for (int k = 0; k < padded.Length; j++, k += 4)
                {
                    powers58[j] = (uint)(padded[k] << 0 | padded[k + 1] << 8 | padded[k + 2] << 16 | padded[k + 3] << 24);
                }
            }

            int[] values = new int[key.Length];
            for (int i = 0; i < values.Length; i++)
            {
                values[i] = ConstantsFO.Base58Chars.IndexOf(key[i]);
            }

            uint[] precomputed = new uint[uLen];

            fixed (uint* pre = &precomputed[0], pow = &powers58[0])
            {
                // i starts from 1 becaue it is compressed (K or L)
                for (int i = 1; i < ConstantsFO.PrivKeyCompWifLen - 2; i++)
                {
                    for (int j = i + 1; j < ConstantsFO.PrivKeyCompWifLen - 1; j++)
                    {
                        for (int k = j + 1; k < ConstantsFO.PrivKeyCompWifLen; k++)
                        {
                            ((Span<uint>)precomputed).Clear();

                            for (int index = 0; index < i; index++)
                            {
                                ulong carry = 0;
                                ulong val = (ulong)values[index];
                                int powIndex = (ConstantsFO.PrivKeyCompWifLen - 1 - index) * uLen;
                                for (int m = uLen - 1; m >= 0; m--, powIndex++)
                                {
                                    ulong result = (pow[powIndex] * val) + pre[m] + carry;
                                    pre[m] = (uint)result;
                                    carry = (uint)(result >> 32);
                                }
                            }

                            for (int index = i + 1; index < j; index++)
                            {
                                ulong carry = 0;
                                ulong val = (ulong)values[index - 1];
                                int powIndex = (ConstantsFO.PrivKeyCompWifLen - 1 - index) * uLen;
                                for (int m = uLen - 1; m >= 0; m--, powIndex++)
                                {
                                    ulong result = (pow[powIndex] * val) + pre[m] + carry;
                                    pre[m] = (uint)result;
                                    carry = (uint)(result >> 32);
                                }
                            }

                            for (int index = j + 1; index < k; index++)
                            {
                                ulong carry = 0;
                                ulong val = (ulong)values[index - 2];
                                int powIndex = (ConstantsFO.PrivKeyCompWifLen - 1 - index) * uLen;
                                for (int m = uLen - 1; m >= 0; m--, powIndex++)
                                {
                                    ulong result = (pow[powIndex] * val) + pre[m] + carry;
                                    pre[m] = (uint)result;
                                    carry = (uint)(result >> 32);
                                }
                            }

                            for (int index = k + 1; index < ConstantsFO.PrivKeyCompWifLen; index++)
                            {
                                ulong carry = 0;
                                ulong val = (ulong)values[index - 3];
                                int powIndex = (ConstantsFO.PrivKeyCompWifLen - 1 - index) * uLen;
                                for (int m = uLen - 1; m >= 0; m--, powIndex++)
                                {
                                    ulong result = (pow[powIndex] * val) + pre[m] + carry;
                                    pre[m] = (uint)result;
                                    carry = (uint)(result >> 32);
                                }
                            }

                            var cancelToken = new CancellationTokenSource();
                            var options = new ParallelOptions
                            {
                                CancellationToken = cancelToken.Token,
                            };

                            try
                            {
                                Parallel.For(0, 58, options, (c1, loopState) =>
                                {
                                    for (int c2 = 0; c2 < 58; c2++)
                                    {
                                        for (int c3 = 0; c3 < 58; c3++)
                                        {
                                            options.CancellationToken.ThrowIfCancellationRequested();

                                            Span<uint> temp = new uint[uLen];
                                            ((ReadOnlySpan<uint>)precomputed).CopyTo(temp);

                                            ulong carry = 0;
                                            ulong val = (ulong)c1;
                                            int powIndex = (ConstantsFO.PrivKeyCompWifLen - 1 - i) * uLen;
                                            for (int m = uLen - 1; m >= 0; m--, powIndex++)
                                            {
                                                ulong result = (powers58[powIndex] * val) + temp[m] + carry;
                                                temp[m] = (uint)result;
                                                carry = (uint)(result >> 32);
                                            }

                                            carry = 0;
                                            val = (ulong)c2;
                                            powIndex = (ConstantsFO.PrivKeyCompWifLen - 1 - j) * uLen;
                                            for (int m = uLen - 1; m >= 0; m--, powIndex++)
                                            {
                                                ulong result = (powers58[powIndex] * val) + temp[m] + carry;
                                                temp[m] = (uint)result;
                                                carry = (uint)(result >> 32);
                                            }

                                            carry = 0;
                                            val = (ulong)c3;
                                            powIndex = (ConstantsFO.PrivKeyCompWifLen - 1 - k) * uLen;
                                            for (int m = uLen - 1; m >= 0; m--, powIndex++)
                                            {
                                                ulong result = (powers58[powIndex] * val) + temp[m] + carry;
                                                temp[m] = (uint)result;
                                                carry = (uint)(result >> 32);
                                            }

                                            if (ComputeSpecialHash(temp))
                                            {
                                                string foundRes = key.Insert(i, $"{ConstantsFO.Base58Chars[c1]}")
                                                                     .Insert(j, $"{ConstantsFO.Base58Chars[c2]}")
                                                                     .Insert(k, $"{ConstantsFO.Base58Chars[c3]}");
                                                report.AddMessageSafe($"Found a key: {foundRes}");
                                                //Task.Run(() => cancelToken.Cancel());
                                                report.FoundAnyResult = true;
                                            }
                                        }
                                    }
                                });
                            }
                            catch (Exception)
                            {
                                return true;
                            }
                        }
                    }
                }
            }
            return false;
        }

        private unsafe bool ComputeSpecialHash(Span<uint> keyValueInts)
        {
            if (((keyValueInts[0] & 0xffffff00) | (keyValueInts[^2] & 0x000000ff)) != 0x00008001)
            {
                return false;
            }

            // SHA must be defined here for this method to be thread safe
            using Sha256Fo sha = new Sha256Fo();

            fixed (uint* hPt = &sha.hashState[0], wPt = &sha.w[0])
            fixed (uint* keyPt = &keyValueInts[0])
            {
                wPt[0] = (keyPt[0] << 16) | (keyPt[1] >> 16);
                wPt[1] = (keyPt[1] << 16) | (keyPt[2] >> 16);
                wPt[2] = (keyPt[2] << 16) | (keyPt[3] >> 16);
                wPt[3] = (keyPt[3] << 16) | (keyPt[4] >> 16);
                wPt[4] = (keyPt[4] << 16) | (keyPt[5] >> 16);
                wPt[5] = (keyPt[5] << 16) | (keyPt[6] >> 16);
                wPt[6] = (keyPt[6] << 16) | (keyPt[7] >> 16);
                wPt[7] = (keyPt[7] << 16) | (keyPt[8] >> 16);
                wPt[8] = (keyPt[8] << 16) | 0b00000000_00000000_10000000_00000000U;
                // from 9 to 14 =0
                wPt[15] = 272; // 34 *8 = 272

                sha.Init(hPt);
                sha.CompressDouble34(hPt, wPt);

                return hPt[0] == keyPt[9];
            }
        }


        private unsafe bool Loop21()
        {
            var cartesian = CartesianProduct.Create(Enumerable.Repeat(Enumerable.Range(0, 58), missCount));
            using Sha256Fo sha = new Sha256Fo();
            bool success = false;

            uint[] temp = new uint[precomputed.Length];
            fixed (uint* hPt = &sha.hashState[0], wPt = &sha.w[0])
            fixed (uint* pow = &powers58[0], res = &precomputed[0], tmp = &temp[0])
            fixed (int* mi = &missingIndexes[0])
            {
                foreach (var item in cartesian)
                {
                    Buffer.MemoryCopy(res, tmp, 28, 28);
                    int mis = 0;
                    foreach (var keyItem in item)
                    {
                        ulong carry = 0;
                        for (int k = 6, j = 0; k >= 0; k--, j++)
                        {
                            ulong result = (pow[(mi[mis] * 7) + j] * (ulong)keyItem) + tmp[k] + carry;
                            tmp[k] = (uint)result;
                            carry = (uint)(result >> 32);
                        }
                        mis++;
                    }

                    wPt[0] = (tmp[0] << 24) | (tmp[1] >> 8);
                    wPt[1] = (tmp[1] << 24) | (tmp[2] >> 8);
                    wPt[2] = (tmp[2] << 24) | (tmp[3] >> 8);
                    wPt[3] = (tmp[3] << 24) | (tmp[4] >> 8);
                    wPt[4] = (tmp[4] << 24) | (tmp[5] >> 8);
                    wPt[5] = (tmp[5] << 24) | 0b00000000_10000000_00000000_00000000U;
                    wPt[6] = 0;
                    wPt[7] = 0;
                    wPt[8] = 0;
                    // from 6 to 14 = 0
                    wPt[15] = 168; // 21 *8 = 168

                    sha.Init(hPt);
                    sha.CompressDouble21(hPt, wPt);

                    if (hPt[0] == tmp[6])
                    {
                        SetResult(item);
                        success = true;
                    }
                }
            }

            return success;
        }


        private void SetResult(IEnumerable<int> item)
        {
            report.AddMessageSafe($"Found a possible result (still running):");

            char[] temp = keyToCheck.ToCharArray();
            int i = 0;
            foreach (var index in item)
            {
                temp[temp.Length - missingIndexes[i++] - 1] = ConstantsFO.Base58Chars[index];
            }

            report.AddMessageSafe(new string(temp));
            report.FoundAnyResult = true;
            return;
        }

        private unsafe bool Loop58()
        {
            var cartesian = CartesianProduct.Create(Enumerable.Repeat(Enumerable.Range(0, 58), missCount));
            using Sha256Fo sha = new Sha256Fo();
            bool success = false;

            uint[] temp = new uint[precomputed.Length];
            fixed (uint* hPt = &sha.hashState[0], wPt = &sha.w[0])
            fixed (uint* pow = &powers58[0], res = &precomputed[0], tmp = &temp[0])
            fixed (int* mi = &missingIndexes[0])
            {
                foreach (var item in cartesian)
                {
                    Buffer.MemoryCopy(res, tmp, 44, 44);
                    int mis = 0;
                    foreach (var keyItem in item)
                    {
                        ulong carry = 0;
                        for (int k = 10, j = 0; k >= 0; k--, j++)
                        {
                            ulong result = (pow[(mi[mis] * 11) + j] * (ulong)keyItem) + tmp[k] + carry;
                            tmp[k] = (uint)result;
                            carry = (uint)(result >> 32);
                        }
                        mis++;
                    }

                    wPt[0] = (tmp[0] << 8) | (tmp[1] >> 24);
                    wPt[1] = (tmp[1] << 8) | (tmp[2] >> 24);
                    wPt[2] = (tmp[2] << 8) | (tmp[3] >> 24);
                    wPt[3] = (tmp[3] << 8) | (tmp[4] >> 24);
                    wPt[4] = (tmp[4] << 8) | (tmp[5] >> 24);
                    wPt[5] = (tmp[5] << 8) | (tmp[6] >> 24);
                    wPt[6] = (tmp[6] << 8) | (tmp[7] >> 24);
                    wPt[7] = (tmp[7] << 8) | (tmp[8] >> 24);
                    wPt[8] = (tmp[8] << 8) | (tmp[9] >> 24);
                    wPt[9] = (tmp[9] << 8) | 0b00000000_00000000_00000000_10000000U;
                    // from 10 to 14 = 0
                    wPt[15] = 312; // 39 *8 = 168

                    sha.Init(hPt);
                    sha.CompressDouble39(hPt, wPt);

                    if (hPt[0] == tmp[10])
                    {
                        SetResult(item);
                        success = true;
                    }
                }
            }

            return success;
        }



        public async Task<bool> FindUnknownLocation3(string key)
        {
            // 51! / 3! *((51-3)!)
            BigInteger total = ((51 * 50 * 49) / (3 * 2 * 1)) * BigInteger.Pow(58, 3);
            report.AddMessageSafe($"Start searching.{Environment.NewLine}Total number of keys to check: {total:n0}");

            Stopwatch watch = Stopwatch.StartNew();
            bool success = await Task.Run(() =>
            {
                return SpecialLoopComp(key);
            }
            );

            watch.Stop();
            report.AddMessageSafe($"Elapsed time: {watch.Elapsed}");
            report.SetKeyPerSecSafe(total, watch.Elapsed.TotalSeconds);

            return success;
        }


        private async Task FindPrivateKey(string key, char missingChar)
        {
            if (key.Contains(missingChar)) // Length must be correct then
            {
                missCount = key.Count(c => c == missingChar);
                if (inputService.CanBePrivateKey(key, out string error))
                {
                    missingIndexes = new int[missCount];
                    bool isComp = key.Length == ConstantsFO.PrivKeyCompWifLen;
                    report.AddMessageSafe($"{(isComp ? "Compressed" : "Uncompressed")} private key missing {missCount} " +
                                          $"characters was detected.");
                    report.AddMessageSafe($"Total number of keys to test: {GetTotalCount(missCount):n0}");

                    Initialize(key.ToCharArray(), missingChar, InputType.PrivateKey);

                    Stopwatch watch = Stopwatch.StartNew();

                    await Task.Run(() =>
                    {
                        if (isComp)
                        {
                            report.AddMessageSafe("Running compressed loop. Please wait.");
                            LoopComp();
                        }
                        else
                        {
                            report.AddMessageSafe("Running uncompressed loop. Please wait.");
                            LoopUncomp();
                        }
                    }
                    );

                    watch.Stop();
                    report.AddMessageSafe($"Elapsed time: {watch.Elapsed}");
                    report.SetKeyPerSecSafe(GetTotalCount(missCount), watch.Elapsed.TotalSeconds);
                }
                else
                {
                    report.AddMessageSafe(error);
                }
            }
            else // Doesn't have any missing chars so length must be <= max key len
            {
                if (key[0] == ConstantsFO.PrivKeyCompChar1 || key[0] == ConstantsFO.PrivKeyCompChar2)
                {
                    if (key.Length == ConstantsFO.PrivKeyCompWifLen)
                    {
                        report.AddMessageSafe("No character is missing, checking validity of the key itself.");
                        report.AddMessageSafe(inputService.CheckPrivateKey(key));
                    }
                    else if (key.Length == ConstantsFO.PrivKeyCompWifLen - 3)
                    {
                        await FindUnknownLocation3(key);
                    }
                    else
                    {
                        report.AddMessageSafe("Only 3 missing characters at unkown locations is supported for now.");
                    }
                }
                else if (key[0] == ConstantsFO.PrivKeyUncompChar)
                {
                    if (key.Length == ConstantsFO.PrivKeyUncompWifLen)
                    {
                        report.AddMessageSafe("No character is missing, checking validity of the key itself.");
                        report.AddMessageSafe(inputService.CheckPrivateKey(key));
                    }
                    else
                    {
                        report.AddMessageSafe("Recovering uncompressed private keys with missing characters at unknown locations " +
                                              "is not supported yet.");
                    }
                }
                else
                {
                    report.AddMessageSafe("The given key has an invalid first character.");
                }
            }
        }

        private async Task FindAddress(string address, char missingChar)
        {
            missCount = address.Count(c => c == missingChar);
            if (missCount == 0)
            {
                report.AddMessageSafe("The given input has no missing characters, verifying it as a complete address.");
                report.AddMessageSafe(inputService.CheckBase58Address(address));
            }
            else if (!address.StartsWith(ConstantsFO.B58AddressChar1) && !address.StartsWith(ConstantsFO.B58AddressChar2))
            {
                report.AddMessageSafe($"Base-58 address should start with {ConstantsFO.B58AddressChar1} or " +
                                      $"{ConstantsFO.B58AddressChar2}.");
            }
            else if (address.Length < ConstantsFO.B58AddressMinLen || address.Length > ConstantsFO.B58AddressMaxLen)
            {
                report.AddMessageSafe($"Address length must be between {ConstantsFO.B58AddressMinLen} and " +
                                      $"{ConstantsFO.B58AddressMaxLen} (but it is {address.Length}).");
            }
            else
            {
                missingIndexes = new int[missCount];
                Initialize(address.ToCharArray(), missingChar, InputType.Address);

                Stopwatch watch = Stopwatch.StartNew();

                await Task.Run(() =>
                {
                    report.AddMessageSafe($"Total number of addresses to test: {GetTotalCount(missCount):n0}");
                    report.AddMessageSafe("Going throgh each case. Please wait...");
                    Loop21();
                }
                );

                watch.Stop();
                report.AddMessageSafe($"Elapsed time: {watch.Elapsed}");
                report.SetKeyPerSecSafe(GetTotalCount(missCount), watch.Elapsed.TotalSeconds);
            }
        }

        private async Task FindBip38(string bip38, char missingChar)
        {
            missCount = bip38.Count(c => c == missingChar);
            if (missCount == 0)
            {
                report.AddMessageSafe("The given BIP38 key has no missing characters, verifying it as a complete key.");
                report.AddMessageSafe(inputService.CheckBase58Bip38(bip38));
            }
            else if (!bip38.StartsWith(ConstantsFO.Bip38Start))
            {
                report.AddMessageSafe($"Base-58 encoded BIP-38 should start with {ConstantsFO.Bip38Start}.");
            }
            else if (bip38.Length != ConstantsFO.Bip38Base58Len)
            {
                report.AddMessageSafe($"Base-58 encoded BIP-38 length must be between {ConstantsFO.Bip38Base58Len}.");
            }
            else
            {
                missingIndexes = new int[missCount];
                Initialize(bip38.ToCharArray(), missingChar, InputType.Bip38);

                Stopwatch watch = Stopwatch.StartNew();

                await Task.Run(() =>
                {
                    report.AddMessageSafe($"Total number of addresses to test: {GetTotalCount(missCount):n0}");
                    report.AddMessageSafe("Going throgh each case. Please wait...");
                    Loop58();
                }
                );

                watch.Stop();
                report.AddMessageSafe($"Elapsed time: {watch.Elapsed}");
                report.SetKeyPerSecSafe(GetTotalCount(missCount), watch.Elapsed.TotalSeconds);
            }
        }

        public async void Find(string key, char missingChar, InputType t)
        {
            report.Init();

            if (!inputService.IsMissingCharValid(missingChar))
                report.Fail("Invalid missing character.");
            else if (string.IsNullOrWhiteSpace(key) || !key.All(c => ConstantsFO.Base58Chars.Contains(c) || c == missingChar))
                report.Fail("Input contains invalid base-58 character(s).");
            else
            {
                keyToCheck = key;

                switch (t)
                {
                    case InputType.PrivateKey:
                        await FindPrivateKey(key, missingChar);
                        break;
                    case InputType.Address:
                        await FindAddress(key, missingChar);
                        break;
                    case InputType.Bip38:
                        await FindBip38(key, missingChar);
                        break;
                    default:
                        report.Fail("Given input type is not defined.");
                        return;
                }

                report.Finalize();
            }
        }
    }
}
