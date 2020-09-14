// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend;
using FinderOuter.Backend.Cryptography.Hashing;
using FinderOuter.Models;
using FinderOuter.Services.Comparers;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace FinderOuter.Services
{
    public class MiniKeyService
    {
        public MiniKeyService(IReport rep)
        {
            inputService = new InputService();
            report = rep;
        }


        private readonly IReport report;
        private readonly InputService inputService;
        private byte[] precomputed;
        private int[] missingIndexes;
        private int missCount;
        private string keyToCheck;
        private ICompareService comparer;


        private BigInteger GetTotalCount(int missCount) => BigInteger.Pow(58, missCount);

        private unsafe void SetResultParallel(byte* keyBytes, int len)
        {
            // This method is called once and after it is called the execution stops so GUI update is not a problem.
            report.AddMessageSafe($"Found the correct key: {Encoding.UTF8.GetString(keyBytes, len)}");
            report.FoundAnyResult = true;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe bool MoveNext(int* items, int len)
        {
            for (int i = len - 1; i >= 0; --i)
            {
                items[i] += 1;

                if (items[i] == 58)
                {
                    items[i] = 0;
                }
                else
                {
                    return true;
                }
            }

            return false;
        }


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe bool Loop23Hash(Sha256Fo sha, uint* wPt, uint* hPt, byte* tmp, ICompareService comparer)
        {
            // The added value below is the fixed first char('S')=0x53 shifted left 24 places
            wPt[0] = 0b01010011_00000000_00000000_00000000U | (uint)tmp[1] << 16 | (uint)tmp[2] << 8 | tmp[3];
            wPt[1] = (uint)tmp[4] << 24 | (uint)tmp[5] << 16 | (uint)tmp[6] << 8 | tmp[7];
            wPt[2] = (uint)tmp[8] << 24 | (uint)tmp[9] << 16 | (uint)tmp[10] << 8 | tmp[11];
            wPt[3] = (uint)tmp[12] << 24 | (uint)tmp[13] << 16 | (uint)tmp[14] << 8 | tmp[15];
            wPt[4] = (uint)tmp[16] << 24 | (uint)tmp[17] << 16 | (uint)tmp[18] << 8 | tmp[19];
            // The added value below is the SHA padding and the last added ? char equal to 0x3f shifted right 8 places
            wPt[5] = (uint)tmp[20] << 24 | (uint)tmp[21] << 16 | 0b00000000_00000000_00111111_10000000U;
            // from 6 to 14 = 0
            wPt[15] = 184; // 23 *8 = 184

            sha.Init(hPt);
            sha.Compress23(hPt, wPt);

            if ((hPt[0] & 0b11111111_00000000_00000000_00000000U) == 0)
            {
                // The actual key is SHA256 of 22 char key (without '?')
                // SHA working vector is already set, only the last 2 bytes ('?' and pad) and the length have to change
                wPt[5] ^= 0b00000000_00000000_10111111_10000000U;
                // from 6 to 14 (remain) = 0
                wPt[15] = 176; // 22 *8 = 176

                sha.Init(hPt);
                sha.Compress22(hPt, wPt);

                return comparer.Compare(sha.GetBytes(hPt));
            }
            else
            {
                return false;
            }
        }
        private unsafe void Loop23(int firstItem, ICompareService comparer, ParallelLoopState loopState)
        {
            // There are 2 steps here:
            // First to compute hash of the mini-key + an extra byte (char('?')=0x3f) and accept those that have a hash[0] == 0
            // Second to compute hash of the mini-key (without ?) to use as the private key
            // The mini-key here is 22 bytes. All hashes are single SHA256.
            // All characters are decoded using UTF-8
            using Sha256Fo sha = new Sha256Fo();
            byte[] allBytes = Encoding.UTF8.GetBytes(ConstantsFO.Base58Chars);
            int[] missingItems = new int[missCount - 1];
            int firstIndex = missingIndexes[0];

            // tmp has 2 equal parts, first part is the byte[] value that keeps changing and
            // second part is the precomputed value that is supposed to be copied each round.
            byte* tmp = stackalloc byte[44];
            fixed (uint* hPt = &sha.hashState[0], wPt = &sha.w[0])
            fixed (byte* pre = &precomputed[0], allPt = &allBytes[0])
            fixed (int* miPt = &missingIndexes[1], itemsPt = &missingItems[0])
            {
                Buffer.MemoryCopy(pre, tmp, 44, 22);
                Buffer.MemoryCopy(pre, tmp + 22, 44, 22);
                tmp[firstIndex] = allPt[firstItem];
                tmp[firstIndex + 22] = allPt[firstItem];

                do
                {
                    if (loopState.IsStopped)
                    {
                        return;
                    }

                    Buffer.MemoryCopy(tmp + 22, tmp, 44, 22);
                    int i = 0;
                    foreach (var keyItem in missingItems)
                    {
                        tmp[miPt[i]] = allPt[keyItem];
                        i++;
                    }

                    if (Loop23Hash(sha, wPt, hPt, tmp, comparer))
                    {
                        SetResultParallel(tmp, 22);
                        loopState.Stop();
                        return;
                    }

                } while (MoveNext(itemsPt, missingItems.Length));
            }

            report.IncrementProgress();
        }
        private unsafe void Loop23()
        {
            if (missCount >= 4)
            {
                // 4 missing chars is 11,316,496 cases and due to EC mult it takes longer to run
                // which makes it the optimal number for using parallelization
                report.SetProgressStep(58);
                report.AddMessageSafe("Running in parallel.");
                Parallel.For(0, 58, (firstItem, state) => Loop23(firstItem, comparer.Clone(), state));
            }
            else
            {
                using Sha256Fo sha = new Sha256Fo();
                byte[] allBytes = Encoding.UTF8.GetBytes(ConstantsFO.Base58Chars);
                int[] missingItems = new int[missCount];

                byte* tmp = stackalloc byte[22];
                fixed (uint* hPt = &sha.hashState[0], wPt = &sha.w[0])
                fixed (byte* pre = &precomputed[0], allPt = &allBytes[0])
                fixed (int* miPt = &missingIndexes[0], itemsPt = &missingItems[0])
                {
                    do
                    {
                        Buffer.MemoryCopy(pre, tmp, 22, 22);
                        int i = 0;
                        foreach (int keyItem in missingItems)
                        {
                            tmp[miPt[i]] = allPt[keyItem];
                            i++;
                        }

                        if (Loop23Hash(sha, wPt, hPt, tmp, comparer))
                        {
                            SetResultParallel(tmp, 22);
                            return;
                        }
                    } while (MoveNext(itemsPt, missingItems.Length));
                }
            }
        }


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe bool Loop27Hash(Sha256Fo sha, uint* wPt, uint* hPt, byte* tmp, ICompareService comparer)
        {
            wPt[0] = 0b01010011_00000000_00000000_00000000U | (uint)tmp[1] << 16 | (uint)tmp[2] << 8 | tmp[3];
            wPt[1] = (uint)tmp[4] << 24 | (uint)tmp[5] << 16 | (uint)tmp[6] << 8 | tmp[7];
            wPt[2] = (uint)tmp[8] << 24 | (uint)tmp[9] << 16 | (uint)tmp[10] << 8 | tmp[11];
            wPt[3] = (uint)tmp[12] << 24 | (uint)tmp[13] << 16 | (uint)tmp[14] << 8 | tmp[15];
            wPt[4] = (uint)tmp[16] << 24 | (uint)tmp[17] << 16 | (uint)tmp[18] << 8 | tmp[19];
            wPt[5] = (uint)tmp[20] << 24 | (uint)tmp[21] << 16 | (uint)tmp[22] << 8 | tmp[23];
            wPt[6] = (uint)tmp[24] << 24 | (uint)tmp[25] << 16 | 0b00000000_00000000_00111111_10000000U;
            // from 7 to 14 = 0
            wPt[15] = 216; // 27 *8 = 216

            sha.Init(hPt);
            sha.Compress27(hPt, wPt);

            if ((hPt[0] & 0b11111111_00000000_00000000_00000000U) == 0)
            {
                wPt[6] ^= 0b00000000_00000000_10111111_10000000U;
                // from 7 to 14 (remain) = 0
                wPt[15] = 208; // 26 *8 = 208

                sha.Init(hPt);
                sha.Compress26(hPt, wPt);

                return comparer.Compare(sha.GetBytes(hPt));
            }
            else
            {
                return false;
            }
        }
        private unsafe void Loop27(int firstItem, ICompareService comparer, ParallelLoopState loopState)
        {
            // Same as above but key is 26 chars (26 bytes)
            using Sha256Fo sha = new Sha256Fo();
            byte[] allBytes = Encoding.UTF8.GetBytes(ConstantsFO.Base58Chars);
            int[] missingItems = new int[missCount - 1];
            int firstIndex = missingIndexes[0];

            byte* tmp = stackalloc byte[52];
            fixed (uint* hPt = &sha.hashState[0], wPt = &sha.w[0])
            fixed (byte* pre = &precomputed[0], allPt = &allBytes[0])
            fixed (int* miPt = &missingIndexes[1], itemsPt = &missingItems[0])
            {
                Buffer.MemoryCopy(pre, tmp, 52, 26);
                Buffer.MemoryCopy(pre, tmp + 26, 52, 26);
                tmp[firstIndex] = allPt[firstItem];
                tmp[firstIndex + 26] = allPt[firstItem];

                do
                {
                    if (loopState.IsStopped)
                    {
                        return;
                    }

                    Buffer.MemoryCopy(tmp + 26, tmp, 52, 26);
                    int i = 0;
                    foreach (var keyItem in missingItems)
                    {
                        tmp[miPt[i]] = allPt[keyItem];
                        i++;
                    }

                    if (Loop27Hash(sha, wPt, hPt, tmp, comparer))
                    {
                        SetResultParallel(tmp, 26);
                        loopState.Stop();
                        return;
                    }
                } while (MoveNext(itemsPt, missingItems.Length));
            }

            report.IncrementProgress();
        }
        private unsafe void Loop27()
        {
            if (missCount >= 4)
            {
                report.SetProgressStep(58);
                report.AddMessageSafe("Running in parallel.");
                Parallel.For(0, 58, (firstItem, state) => Loop27(firstItem, comparer.Clone(), state));
            }
            else
            {
                using Sha256Fo sha = new Sha256Fo();
                byte[] allBytes = Encoding.UTF8.GetBytes(ConstantsFO.Base58Chars);
                int[] missingItems = new int[missCount];

                byte* tmp = stackalloc byte[26];
                fixed (uint* hPt = &sha.hashState[0], wPt = &sha.w[0])
                fixed (byte* pre = &precomputed[0], allPt = &allBytes[0])
                fixed (int* miPt = &missingIndexes[0], itemsPt = &missingItems[0])
                {
                    do
                    {
                        Buffer.MemoryCopy(pre, tmp, 26, 26);
                        int i = 0;
                        foreach (var keyItem in missingItems)
                        {
                            tmp[miPt[i]] = allPt[keyItem];
                            i++;
                        }

                        if (Loop27Hash(sha, wPt, hPt, tmp, comparer))
                        {
                            SetResultParallel(tmp, 26);
                            return;
                        }
                    } while (MoveNext(itemsPt, missingItems.Length));
                }
            }
        }


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe bool Loop31Hash(Sha256Fo sha, uint* wPt, uint* hPt, byte* tmp, ICompareService comparer)
        {
            wPt[0] = 0b01010011_00000000_00000000_00000000U | (uint)tmp[1] << 16 | (uint)tmp[2] << 8 | tmp[3];
            wPt[1] = (uint)tmp[4] << 24 | (uint)tmp[5] << 16 | (uint)tmp[6] << 8 | tmp[7];
            wPt[2] = (uint)tmp[8] << 24 | (uint)tmp[9] << 16 | (uint)tmp[10] << 8 | tmp[11];
            wPt[3] = (uint)tmp[12] << 24 | (uint)tmp[13] << 16 | (uint)tmp[14] << 8 | tmp[15];
            wPt[4] = (uint)tmp[16] << 24 | (uint)tmp[17] << 16 | (uint)tmp[18] << 8 | tmp[19];
            wPt[5] = (uint)tmp[20] << 24 | (uint)tmp[21] << 16 | (uint)tmp[22] << 8 | tmp[23];
            wPt[6] = (uint)tmp[24] << 24 | (uint)tmp[25] << 16 | (uint)tmp[26] << 8 | tmp[27];
            wPt[7] = (uint)tmp[28] << 24 | (uint)tmp[29] << 16 | 0b00000000_00000000_00111111_10000000U;
            // from 8 to 14 = 0
            wPt[15] = 248; // 31 *8 = 184

            sha.Init(hPt);
            sha.Compress31(hPt, wPt);

            if ((hPt[0] & 0b11111111_00000000_00000000_00000000U) == 0)
            {
                wPt[7] ^= 0b00000000_00000000_10111111_10000000U;
                // from 8 to 14 (remain) = 0
                wPt[15] = 240; // 30 *8 = 240

                sha.Init(hPt);
                sha.Compress30(hPt, wPt);

                return comparer.Compare(sha.GetBytes(hPt));
            }
            else
            {
                return false;
            }
        }
        private unsafe void Loop31(int firstItem, ICompareService comparer, ParallelLoopState loopState)
        {
            // Same as above but key is 30 chars (30 bytes)
            using Sha256Fo sha = new Sha256Fo();
            byte[] allBytes = Encoding.UTF8.GetBytes(ConstantsFO.Base58Chars);
            int[] missingItems = new int[missCount - 1];
            int firstIndex = missingIndexes[0];

            byte* tmp = stackalloc byte[60];
            fixed (uint* hPt = &sha.hashState[0], wPt = &sha.w[0])
            fixed (byte* pre = &precomputed[0], allPt = &allBytes[0])
            fixed (int* miPt = &missingIndexes[1], itemsPt = &missingItems[0])
            {
                Buffer.MemoryCopy(pre, tmp, 60, 30);
                Buffer.MemoryCopy(pre, tmp + 30, 60, 30);
                tmp[firstIndex] = allPt[firstItem];
                tmp[firstIndex + 30] = allPt[firstItem];

                do
                {
                    if (loopState.IsStopped)
                    {
                        return;
                    }

                    Buffer.MemoryCopy(tmp + 30, tmp, 60, 30);
                    int i = 0;
                    foreach (var keyItem in missingItems)
                    {
                        tmp[miPt[i]] = allPt[keyItem];
                        i++;
                    }

                    if (Loop27Hash(sha, wPt, hPt, tmp, comparer))
                    {
                        SetResultParallel(tmp, 30);
                        loopState.Stop();
                        return;
                    }
                } while (MoveNext(itemsPt, missingItems.Length));
            }

            report.IncrementProgress();
        }
        private unsafe void Loop31()
        {
            if (missCount >= 4)
            {
                report.SetProgressStep(58);
                report.AddMessageSafe("Running in parallel.");
                Parallel.For(0, 58, (firstItem, state) => Loop31(firstItem, comparer.Clone(), state));
            }
            else
            {
                using Sha256Fo sha = new Sha256Fo();
                byte[] allBytes = Encoding.UTF8.GetBytes(ConstantsFO.Base58Chars);
                int[] missingItems = new int[missCount];
                int firstIndex = missingIndexes[0];

                byte* tmp = stackalloc byte[30];
                fixed (uint* hPt = &sha.hashState[0], wPt = &sha.w[0])
                fixed (byte* pre = &precomputed[0], allPt = &allBytes[0])
                fixed (int* miPt = &missingIndexes[0], itemsPt = &missingItems[0])
                {
                    do
                    {
                        Buffer.MemoryCopy(pre, tmp, 30, 30);
                        int i = 0;
                        foreach (var keyItem in missingItems)
                        {
                            tmp[miPt[i]] = allPt[keyItem];
                            i++;
                        }

                        if (Loop31Hash(sha, wPt, hPt, tmp, comparer))
                        {
                            SetResultParallel(tmp, 30);
                            return;
                        }
                    } while (MoveNext(itemsPt, missingItems.Length));
                }
            }
        }


        private void PreCompute(char missingChar)
        {
            int mis = 0;
            for (int i = 0; i < keyToCheck.Length; i++)
            {
                if (keyToCheck[i] == missingChar)
                {
                    missingIndexes[mis++] = i;
                }
                else
                {
                    precomputed[i] = (byte)keyToCheck[i];
                }
            }
        }

        public async void Find(string key, string extra, InputType extraType, char missingChar)
        {
            report.Init();

            if (!inputService.IsMissingCharValid(missingChar))
                report.Fail("Invalid missing character.");
            else if (string.IsNullOrWhiteSpace(key) || !key.All(c => ConstantsFO.Base58Chars.Contains(c) || c == missingChar))
                report.Fail("Input contains invalid base-58 character(s).");
            else if (!key.StartsWith(ConstantsFO.MiniKeyStart))
                report.Fail($"Minikey must start with {ConstantsFO.MiniKeyStart}.");
            else if (!inputService.TryGetCompareService(extraType, extra, out comparer))
                report.Fail("Invalid extra input or input type.");
            else
            {
                missCount = key.Count(c => c == missingChar);
                if (missCount == 0)
                {
                    report.AddMessageSafe("The given input has no missing characters, verifying it as a complete minikey.");
                    report.AddMessageSafe(inputService.CheckMiniKey(key));
                    report.FoundAnyResult = true;
                    return;
                }

                keyToCheck = key;
                missingIndexes = new int[missCount];

                report.AddMessageSafe($"A {key.Length} char long mini-key with {missCount} missing characters was detected." +
                                      $"{Environment.NewLine}" +
                                      $"Total number of minikeys to test: {GetTotalCount(missCount):n0}{Environment.NewLine}" +
                                      $"Going throgh each case. Please wait...");
                Stopwatch watch = Stopwatch.StartNew();

                if (key.Length == ConstantsFO.MiniKeyLen1)
                {
                    precomputed = new byte[ConstantsFO.MiniKeyLen1];
                    PreCompute(missingChar);
                    await Task.Run(Loop23);
                }
                else if (key.Length == ConstantsFO.MiniKeyLen2)
                {
                    precomputed = new byte[ConstantsFO.MiniKeyLen2];
                    PreCompute(missingChar);
                    await Task.Run(Loop27);
                }
                else if (key.Length == ConstantsFO.MiniKeyLen3)
                {
                    precomputed = new byte[ConstantsFO.MiniKeyLen3];
                    PreCompute(missingChar);
                    await Task.Run(Loop31);
                }
                else
                {
                    report.Fail($"Minikey length must be {ConstantsFO.MiniKeyLen1} or {ConstantsFO.MiniKeyLen3}.");
                }

                watch.Stop();
                report.AddMessageSafe($"Elapsed time: {watch.Elapsed}");
                report.SetKeyPerSecSafe(GetTotalCount(missCount), watch.Elapsed.TotalSeconds);

                report.Finalize();
            }
        }
    }
}
