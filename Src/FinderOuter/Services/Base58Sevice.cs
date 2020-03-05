// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend;
using FinderOuter.Backend.Cryptography.Hashing;
using FinderOuter.Backend.Encoders;
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
    public class Base58Sevice : ServiceBase
    {
        public Base58Sevice(Report rep) : base(rep)
        {
            inputService = new InputService();
            encoder = new Base58();
            sha = new Sha256(true);
        }



        private readonly InputService inputService;
        private readonly Base58 encoder;
        private uint[] powers58, precomputed;
        private int[] missingIndexes;
        private readonly Sha256 sha;
        private int missCount;


        private void Initialize(char[] key, char missingChar)
        {
            // Compute 58^n from n from 0 to inputLength as uint[]

            byte[] padded;
            int uLen;
            if (key.Length <= Constants.CompPrivKeyLen)
            {
                // Maximum result (58^52) is 39 bytes = 39/4 = 10 uint
                uLen = 10;
                powers58 = new uint[key.Length * uLen];
                padded = new byte[4 * uLen];
                precomputed = new uint[uLen];
            }
            else
            {
                throw new ArgumentException("Input length for setting Pow58 is not yet deifined");
            }


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
                    ulong val = (ulong)Constants.Base58Chars.IndexOf(key[i]);
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


        public bool IsMissingCharValid(char c) => Constants.Symbols.Contains(c);

        public bool IsInputValid(string key, char missingChar)
        {
            return !string.IsNullOrEmpty(key) && key.All(c => c == missingChar || Constants.Base58Chars.Contains(c));
        }

        private BigInteger GetTotalCount(int missCount) => BigInteger.Pow(58, missCount);

        readonly List<IEnumerable<int>> Final = new List<IEnumerable<int>>();
        private void SetResult(IEnumerable<int> item)
        {
            // TODO: add lock?
            Final.Add(item);
        }

        private unsafe bool LoopComp()
        {
            var cartesian = CartesianProduct.Create(Enumerable.Repeat(Enumerable.Range(0, 58), missCount));

            bool success = false;

            uint[] temp = new uint[precomputed.Length];
            fixed (uint* hPt = &sha.hashState[0], wPt = &sha.w[0])
            fixed (uint* pow = &powers58[0], res = &precomputed[0], tmp = &temp[0])
            fixed (int* mi = &missingIndexes[0])
            {
                foreach (var item in cartesian)
                {
                    Buffer.MemoryCopy(res, tmp, 40, 40);
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
                        SetResult(item);
                        success = true;
                    }
                }
            }

            return success;
        }

        private unsafe bool LoopUncomp()
        {
            var cartesian = CartesianProduct.Create(Enumerable.Repeat(Enumerable.Range(0, 58), missCount));

            bool success = false;

            uint[] temp = new uint[precomputed.Length];
            fixed (uint* hPt = &sha.hashState[0], wPt = &sha.w[0])
            fixed (uint* pow = &powers58[0], res = &precomputed[0], tmp = &temp[0])
            fixed (int* mi = &missingIndexes[0])
            {
                foreach (var item in cartesian)
                {
                    Buffer.MemoryCopy(res, tmp, 40, 40);
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
                        SetResult(item);
                        success = true;
                    }
                }
            }

            AddQueue(success ? "Found some keys" : "Could not find anything");
            return success;
        }

        private unsafe bool SpecialLoopComp(string key)
        {
            byte[] padded;
            int uLen;

            // Maximum result (58^52) is 39 bytes = 39/4 = 10 uint
            uLen = 10;
            uint[] powers58 = new uint[Constants.CompPrivKeyLen * uLen];
            padded = new byte[4 * uLen];

            for (int i = 0, j = 0; i < Constants.CompPrivKeyLen; i++)
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
                values[i] = Constants.Base58Chars.IndexOf(key[i]);
            }

            uint[] precomputed = new uint[uLen];

            fixed (uint* pre = &precomputed[0], pow = &powers58[0])
            {
                // i starts from 1 becaue it is compressed (K or L)
                for (int i = 1; i < Constants.CompPrivKeyLen - 2; i++)
                {
                    for (int j = i + 1; j < Constants.CompPrivKeyLen - 1; j++)
                    {
                        for (int k = j + 1; k < Constants.CompPrivKeyLen; k++)
                        {
                            ((Span<uint>)precomputed).Clear();

                            for (int index = 0; index < i; index++)
                            {
                                ulong carry = 0;
                                ulong val = (ulong)values[index];
                                int powIndex = (Constants.CompPrivKeyLen - 1 - index) * uLen;
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
                                int powIndex = (Constants.CompPrivKeyLen - 1 - index) * uLen;
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
                                int powIndex = (Constants.CompPrivKeyLen - 1 - index) * uLen;
                                for (int m = uLen - 1; m >= 0; m--, powIndex++)
                                {
                                    ulong result = (pow[powIndex] * val) + pre[m] + carry;
                                    pre[m] = (uint)result;
                                    carry = (uint)(result >> 32);
                                }
                            }

                            for (int index = k + 1; index < Constants.CompPrivKeyLen; index++)
                            {
                                ulong carry = 0;
                                ulong val = (ulong)values[index - 3];
                                int powIndex = (Constants.CompPrivKeyLen - 1 - index) * uLen;
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
                                            int powIndex = (Constants.CompPrivKeyLen - 1 - i) * uLen;
                                            for (int m = uLen - 1; m >= 0; m--, powIndex++)
                                            {
                                                ulong result = (powers58[powIndex] * val) + temp[m] + carry;
                                                temp[m] = (uint)result;
                                                carry = (uint)(result >> 32);
                                            }

                                            carry = 0;
                                            val = (ulong)c2;
                                            powIndex = (Constants.CompPrivKeyLen - 1 - j) * uLen;
                                            for (int m = uLen - 1; m >= 0; m--, powIndex++)
                                            {
                                                ulong result = (powers58[powIndex] * val) + temp[m] + carry;
                                                temp[m] = (uint)result;
                                                carry = (uint)(result >> 32);
                                            }

                                            carry = 0;
                                            val = (ulong)c3;
                                            powIndex = (Constants.CompPrivKeyLen - 1 - k) * uLen;
                                            for (int m = uLen - 1; m >= 0; m--, powIndex++)
                                            {
                                                ulong result = (powers58[powIndex] * val) + temp[m] + carry;
                                                temp[m] = (uint)result;
                                                carry = (uint)(result >> 32);
                                            }

                                            if (Compute(temp))
                                            {
                                                string foundRes = key.Insert(i, $"{Constants.Base58Chars[c1]}")
                                                                     .Insert(j, $"{Constants.Base58Chars[c2]}")
                                                                     .Insert(k, $"{Constants.Base58Chars[c3]}");
                                                AddQueue($"Found a key: {foundRes}");
                                                Task.Run(() => cancelToken.Cancel());
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


        private unsafe bool Compute(Span<uint> keyValueInts)
        {
            if (((keyValueInts[0] & 0xffffff00) | (keyValueInts[^2] & 0x000000ff)) != 0x00008001)
            {
                return false;
            }

            // SHA must be defined here for this method to be thread safe
            Sha256 sha = new Sha256();

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



        public async Task<bool> Find(string key, char missingChar)
        {
            InitReport();

            if (!IsMissingCharValid(missingChar))
                return Fail("Missing character can not be among base-58 characters.");
            if (!IsInputValid(key, missingChar))
                return Fail("Input contains invalid base-58 character(s).");


            bool success = false;
            if (inputService.CanBePrivateKey(key))
            {
                missCount = key.Count(c => c == missingChar);
                if (missCount == 0)
                {
                    AddMessage("No character is missing, checking validity of the key itself.");
                    // TODO: use Backend.KeyPairs.PrivateKey instead
                    if (!encoder.HasValidChars(key))
                    {
                        return Fail("The given key contains invalid base-58 characters.");
                    }
                    if (!encoder.HasValidCheckSum(key))
                    {
                        return Fail("The given key has an invalid checksum.");
                    }

                    byte[] keyBa = encoder.DecodeWithCheckSum(key);
                    if (keyBa[0] != Constants.PrivKeyFirstByte)
                    {
                        return Fail($"Invalid first key byte (actual={keyBa[0]}, expected={Constants.PrivKeyFirstByte})");
                    }
                    if (keyBa.Length == 33)
                    {
                        if (!inputService.IsPrivateKeyInRange(keyBa.SubArray(1)))
                        {
                            return Fail("Invalid key integer value (outside of the range defined by secp256k1 curve).");
                        }

                        return Pass("The given key is a valid uncompressed private key.");
                    }
                    else if (keyBa.Length == 34)
                    {
                        if (keyBa[^1] != Constants.CompPrivKeyLastByte)
                        {
                            return Fail($"Invalid compressed key last byte (actual={keyBa[^1]}, " +
                                $"expected={Constants.CompPrivKeyLastByte})");
                        }
                        if (!inputService.IsPrivateKeyInRange(keyBa.SubArray(1, 32)))
                        {
                            return Fail("Invalid key integer value (outside of the range defined by secp256k1 curve).");
                        }

                        return Pass("The given key is a valid compressed private key.");
                    }
                    else
                    {
                        return Fail($"The given key length is invalid. actual = {keyBa.Length}, " +
                            $"expected = 33 (uncomp) or 34 (comp))");
                    }
                }

                missingIndexes = new int[missCount];
                bool isComp = key.Length == Constants.CompPrivKeyLen;
                AddMessage($"{(isComp ? "Compressed" : "Uncompressed")} private key missing {missCount} characters was detected.");
                AddMessage($"Total number of keys to test: {GetTotalCount(missCount):n0}");

                Initialize(key.ToCharArray(), missingChar);

                Stopwatch watch = Stopwatch.StartNew();

                success = await Task.Run(() =>
                {
                    if (isComp)
                    {
                        AddQueue("Running compressed loop.");
                        return LoopComp();
                    }
                    else
                    {
                        AddQueue("Running uncompressed loop.");
                        return LoopUncomp();
                    }
                }
                );

                watch.Stop();
                AddQueue($"Elapsed time: {watch.Elapsed}");
                AddQueue($"k/s= {(int)GetTotalCount(missCount) / watch.Elapsed.TotalSeconds:n0}");
            }
            else
            {
                success = false;
                AddQueue("Not yet defined.");
            }

            if (success)
            {
                await Task.Run(() =>
                {
                    AddQueue($"Found {Final.Count} key{(Final.Count > 1 ? "s" : "")}:");

                    foreach (var item in Final)
                    {
                        char[] temp = key.ToCharArray();
                        int i = 0;
                        foreach (var index in item)
                        {
                            temp[temp.Length - missingIndexes[i++] - 1] = Constants.Base58Chars[index];
                        }

                        AddQueue(new string(temp));
                    }

                    Final.Clear();
                    return;
                }
                );
            }

            return CopyQueueToMessage(success);
        }


        public async Task<bool> FindUnknownLocation(string key)
        {
            InitReport();

            if (string.IsNullOrEmpty(key) || key.Any(c => !Constants.Base58Chars.Contains(c)))
                return Fail("Input contains invalid base-58 character(s).");
            if (key.Length != Constants.CompPrivKeyLen - 3 ||
                (!key.StartsWith(Constants.CompPrivKeyChar2) && key.StartsWith(Constants.CompPrivKeyChar2)))
            {
                // Only this special case is supported for now
                return Fail("This option is only defined for compressed private keys that " +
                            "have 3 missing characters with unknown locations.");
            }

            // 51! / 3! *((51-3)!)
            BigInteger total = ((51 * 50 * 49) / (3 * 2 * 1)) * BigInteger.Pow(58, 3);
            AddMessage($"Start searching.{Environment.NewLine}Total number of keys to check: {total:n0}");

            Stopwatch watch = Stopwatch.StartNew();
            bool success = await Task.Run(() =>
            {
                return SpecialLoopComp(key);
            }
            );

            watch.Stop();
            AddQueue($"Elapsed time: {watch.Elapsed}");
            AddQueue(GetKeyPerSec(total, watch.Elapsed.TotalSeconds));

            return CopyQueueToMessage(success);
        }
    }
}
