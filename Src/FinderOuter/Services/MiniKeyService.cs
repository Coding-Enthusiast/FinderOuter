// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend;
using FinderOuter.Backend.Hashing;
using FinderOuter.Models;
using FinderOuter.Services.Comparers;
using FinderOuter.Services.SearchSpaces;
using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace FinderOuter.Services
{
    public class MiniKeyService
    {
        public MiniKeyService(IReport rep)
        {
            report = rep;
        }


        private readonly IReport report;
        private ICompareService comparer;
        private MiniKeySearchSpace searchSpace;


        private unsafe void SetResultParallel(byte* keyBytes, int len)
        {
            // This method is called once and after it is called the execution stops so GUI update is not a problem.
            report.AddMessageSafe($"Found the correct key: {Encoding.UTF8.GetString(keyBytes, len)}");
            report.FoundAnyResult = true;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe bool MoveNext(Permutation* items, int len)
        {
            for (int i = len - 1; i >= 0; i--)
            {
                if (items[i].Increment())
                {
                    return true;
                }
            }

            return false;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe bool MoveNext(int* items, int len)
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
        private static unsafe bool Loop23Hash(uint* pt, byte* tmp, ICompareService comparer)
        {
            // The added value below is the fixed first char('S')=0x53 shifted left 24 places
            pt[8] = 0b01010011_00000000_00000000_00000000U | (uint)tmp[1] << 16 | (uint)tmp[2] << 8 | tmp[3];
            pt[9] = (uint)tmp[4] << 24 | (uint)tmp[5] << 16 | (uint)tmp[6] << 8 | tmp[7];
            pt[10] = (uint)tmp[8] << 24 | (uint)tmp[9] << 16 | (uint)tmp[10] << 8 | tmp[11];
            pt[11] = (uint)tmp[12] << 24 | (uint)tmp[13] << 16 | (uint)tmp[14] << 8 | tmp[15];
            pt[12] = (uint)tmp[16] << 24 | (uint)tmp[17] << 16 | (uint)tmp[18] << 8 | tmp[19];
            // The added value below is the SHA padding and the last added ? char equal to 0x3f shifted right 8 places
            pt[13] = (uint)tmp[20] << 24 | (uint)tmp[21] << 16 | 0b00000000_00000000_00111111_10000000U;
            // from 6 to 14 = 0
            pt[23] = 184; // 23 *8 = 184

            Sha256Fo.Init(pt);
            Sha256Fo.Compress23(pt);

            if ((pt[0] & 0b11111111_00000000_00000000_00000000U) == 0)
            {
                // The actual key is SHA256 of 22 char key (without '?')
                // SHA working vector is already set, only the last 2 bytes ('?' and pad) and the length have to change
                pt[13] ^= 0b00000000_00000000_10111111_10000000U;
                // from 6 to 14 (remain) = 0
                pt[23] = 176; // 22 *8 = 176

                Sha256Fo.Init(pt);
                Sha256Fo.Compress22(pt);

                return comparer.Compare(pt);
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
            int firstIndex = searchSpace.MissingIndexes[0];
            Debug.Assert(searchSpace.MissCount - 1 >= 1);
            Permutation[] items = new Permutation[searchSpace.MissCount - 1];

            // tmp has 2 equal parts, first part is the byte[] value that keeps changing and
            // second part is the precomputed value that is supposed to be copied each round.
            byte* tmp = stackalloc byte[44];
            uint* pt = stackalloc uint[Sha256Fo.UBufferSize];
            fixed (byte* pre = &searchSpace.preComputed[0])
            fixed (int* miPt = &searchSpace.MissingIndexes[1])
            fixed (uint* valPt = &searchSpace.AllPermutationValues[0])
            fixed (Permutation* itemsPt = &items[0])
            {
                uint* tempPt = valPt;
                for (int i = 0; i < items.Length; i++)
                {
                    tempPt += searchSpace.PermutationCounts[i];
                    itemsPt[i] = new(searchSpace.PermutationCounts[i + 1], tempPt);
                }

                Buffer.MemoryCopy(pre, tmp, 44, 22);
                Buffer.MemoryCopy(pre, tmp + 22, 44, 22);
                tmp[firstIndex] = (byte)valPt[firstItem];
                tmp[firstIndex + 22] = (byte)valPt[firstItem];

                do
                {
                    if (loopState.IsStopped)
                    {
                        return;
                    }

                    Buffer.MemoryCopy(tmp + 22, tmp, 44, 22);
                    int i = 0;
                    foreach (Permutation keyItem in items)
                    {
                        tmp[miPt[i]] = (byte)keyItem.GetValue();
                        i++;
                    }

                    if (Loop23Hash(pt, tmp, comparer))
                    {
                        SetResultParallel(tmp, 22);
                        loopState.Stop();
                        return;
                    }

                } while (MoveNext(itemsPt, items.Length));
            }

            report.IncrementProgress();
        }
        private unsafe void Loop23()
        {
            if (searchSpace.MissCount >= 4)
            {
                // 4 missing chars is 11,316,496 cases and due to EC mult it takes longer to run
                // which makes it the optimal number for using parallelization
                int max = searchSpace.PermutationCounts[0];
                report.SetProgressStep(max);
                ParallelOptions opts = report.BuildParallelOptions();
                Parallel.For(0, max, opts, (firstItem, state) => Loop23(firstItem, comparer.Clone(), state));
            }
            else
            {
                Debug.Assert(searchSpace.MissCount != 0);
                Permutation[] items = new Permutation[searchSpace.MissCount];

                byte* tmp = stackalloc byte[22];
                uint* pt = stackalloc uint[Sha256Fo.UBufferSize];
                fixed (byte* pre = &searchSpace.preComputed[0])
                fixed (int* miPt = &searchSpace.MissingIndexes[0])
                fixed (uint* valPt = &searchSpace.AllPermutationValues[0])
                fixed (Permutation* itemsPt = &items[0])
                {
                    uint* tempPt = valPt;
                    for (int i = 0; i < items.Length; i++)
                    {
                        itemsPt[i] = new(searchSpace.PermutationCounts[i], tempPt);
                        tempPt += searchSpace.PermutationCounts[i];
                    }

                    do
                    {
                        Buffer.MemoryCopy(pre, tmp, 22, 22);
                        int i = 0;
                        foreach (Permutation keyItem in items)
                        {
                            tmp[miPt[i]] = (byte)keyItem.GetValue();
                            i++;
                        }

                        if (Loop23Hash(pt, tmp, comparer))
                        {
                            SetResultParallel(tmp, 22);
                            return;
                        }
                    } while (MoveNext(itemsPt, items.Length));
                }
            }
        }


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe bool Loop27Hash(uint* pt, byte* tmp, ICompareService comparer)
        {
            pt[8] = 0b01010011_00000000_00000000_00000000U | (uint)tmp[1] << 16 | (uint)tmp[2] << 8 | tmp[3];
            pt[9] = (uint)tmp[4] << 24 | (uint)tmp[5] << 16 | (uint)tmp[6] << 8 | tmp[7];
            pt[10] = (uint)tmp[8] << 24 | (uint)tmp[9] << 16 | (uint)tmp[10] << 8 | tmp[11];
            pt[11] = (uint)tmp[12] << 24 | (uint)tmp[13] << 16 | (uint)tmp[14] << 8 | tmp[15];
            pt[12] = (uint)tmp[16] << 24 | (uint)tmp[17] << 16 | (uint)tmp[18] << 8 | tmp[19];
            pt[13] = (uint)tmp[20] << 24 | (uint)tmp[21] << 16 | (uint)tmp[22] << 8 | tmp[23];
            pt[14] = (uint)tmp[24] << 24 | (uint)tmp[25] << 16 | 0b00000000_00000000_00111111_10000000U;
            // from 7 to 14 = 0
            pt[23] = 216; // 27 *8 = 216

            Sha256Fo.Init(pt);
            Sha256Fo.Compress27(pt);

            if ((pt[0] & 0b11111111_00000000_00000000_00000000U) == 0)
            {
                pt[14] ^= 0b00000000_00000000_10111111_10000000U;
                // from 7 to 14 (remain) = 0
                pt[23] = 208; // 26 *8 = 208

                Sha256Fo.Init(pt);
                Sha256Fo.Compress26(pt);

                return comparer.Compare(pt);
            }
            else
            {
                return false;
            }
        }
        private unsafe void Loop27(int firstItem, ICompareService comparer, ParallelLoopState loopState)
        {
            // Same as above but key is 26 chars (26 bytes)
            int firstIndex = searchSpace.MissingIndexes[0];
            Debug.Assert(searchSpace.MissCount - 1 >= 1);
            Permutation[] items = new Permutation[searchSpace.MissCount - 1];

            byte* tmp = stackalloc byte[52];
            uint* pt = stackalloc uint[Sha256Fo.UBufferSize];
            fixed (byte* pre = &searchSpace.preComputed[0])
            fixed (int* miPt = &searchSpace.MissingIndexes[1])
            fixed (uint* valPt = &searchSpace.AllPermutationValues[0])
            fixed (Permutation* itemsPt = &items[0])
            {
                uint* tempPt = valPt;
                for (int i = 0; i < items.Length; i++)
                {
                    tempPt += searchSpace.PermutationCounts[i];
                    itemsPt[i] = new(searchSpace.PermutationCounts[i + 1], tempPt);
                }

                Buffer.MemoryCopy(pre, tmp, 52, 26);
                Buffer.MemoryCopy(pre, tmp + 26, 52, 26);
                tmp[firstIndex] = (byte)valPt[firstItem];
                tmp[firstIndex + 26] = (byte)valPt[firstItem];

                do
                {
                    if (loopState.IsStopped)
                    {
                        return;
                    }

                    Buffer.MemoryCopy(tmp + 26, tmp, 52, 26);
                    int i = 0;
                    foreach (Permutation keyItem in items)
                    {
                        tmp[miPt[i]] = (byte)keyItem.GetValue();
                        i++;
                    }

                    if (Loop27Hash(pt, tmp, comparer))
                    {
                        SetResultParallel(tmp, 26);
                        loopState.Stop();
                        return;
                    }
                } while (MoveNext(itemsPt, items.Length));
            }

            report.IncrementProgress();
        }
        private unsafe void Loop27()
        {
            if (searchSpace.MissCount >= 4)
            {
                int max = searchSpace.PermutationCounts[0];
                report.SetProgressStep(max);
                ParallelOptions opts = report.BuildParallelOptions();
                Parallel.For(0, max, opts, (firstItem, state) => Loop27(firstItem, comparer.Clone(), state));
            }
            else
            {
                Debug.Assert(searchSpace.MissCount != 0);
                Permutation[] items = new Permutation[searchSpace.MissCount];

                byte* tmp = stackalloc byte[26];
                uint* pt = stackalloc uint[Sha256Fo.UBufferSize];
                fixed (byte* pre = &searchSpace.preComputed[0])
                fixed (int* miPt = &searchSpace.MissingIndexes[0])
                fixed (uint* valPt = &searchSpace.AllPermutationValues[0])
                fixed (Permutation* itemsPt = &items[0])
                {
                    uint* tempPt = valPt;
                    for (int i = 0; i < items.Length; i++)
                    {
                        itemsPt[i] = new(searchSpace.PermutationCounts[i], tempPt);
                        tempPt += searchSpace.PermutationCounts[i];
                    }

                    do
                    {
                        Buffer.MemoryCopy(pre, tmp, 26, 26);
                        int i = 0;
                        foreach (Permutation keyItem in items)
                        {
                            tmp[miPt[i]] = (byte)keyItem.GetValue();
                            i++;
                        }

                        if (Loop27Hash(pt, tmp, comparer))
                        {
                            SetResultParallel(tmp, 26);
                            return;
                        }
                    } while (MoveNext(itemsPt, items.Length));
                }
            }
        }


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe bool Loop31Hash(uint* pt, byte* tmp, ICompareService comparer)
        {
            pt[8] = 0b01010011_00000000_00000000_00000000U | (uint)tmp[1] << 16 | (uint)tmp[2] << 8 | tmp[3];
            pt[9] = (uint)tmp[4] << 24 | (uint)tmp[5] << 16 | (uint)tmp[6] << 8 | tmp[7];
            pt[10] = (uint)tmp[8] << 24 | (uint)tmp[9] << 16 | (uint)tmp[10] << 8 | tmp[11];
            pt[11] = (uint)tmp[12] << 24 | (uint)tmp[13] << 16 | (uint)tmp[14] << 8 | tmp[15];
            pt[12] = (uint)tmp[16] << 24 | (uint)tmp[17] << 16 | (uint)tmp[18] << 8 | tmp[19];
            pt[13] = (uint)tmp[20] << 24 | (uint)tmp[21] << 16 | (uint)tmp[22] << 8 | tmp[23];
            pt[14] = (uint)tmp[24] << 24 | (uint)tmp[25] << 16 | (uint)tmp[26] << 8 | tmp[27];
            pt[15] = (uint)tmp[28] << 24 | (uint)tmp[29] << 16 | 0b00000000_00000000_00111111_10000000U;
            // from 8 to 14 = 0
            pt[23] = 248; // 31 *8 = 184

            Sha256Fo.Init(pt);
            Sha256Fo.Compress31(pt);

            if ((pt[0] & 0b11111111_00000000_00000000_00000000U) == 0)
            {
                pt[15] ^= 0b00000000_00000000_10111111_10000000U;
                // from 8 to 14 (remain) = 0
                pt[23] = 240; // 30 *8 = 240

                Sha256Fo.Init(pt);
                Sha256Fo.Compress30(pt);

                return comparer.Compare(pt);
            }
            else
            {
                return false;
            }
        }
        private unsafe void Loop31(int firstItem, ICompareService comparer, ParallelLoopState loopState)
        {
            // Same as above but key is 30 chars (30 bytes)
            int firstIndex = searchSpace.MissingIndexes[0];
            Debug.Assert(searchSpace.MissCount - 1 >= 1);
            Permutation[] items = new Permutation[searchSpace.MissCount - 1];

            byte* tmp = stackalloc byte[60];
            uint* pt = stackalloc uint[Sha256Fo.UBufferSize];
            fixed (byte* pre = &searchSpace.preComputed[0])
            fixed (int* miPt = &searchSpace.MissingIndexes[1])
            fixed (uint* valPt = &searchSpace.AllPermutationValues[0])
            fixed (Permutation* itemsPt = &items[0])
            {
                uint* tempPt = valPt;
                for (int i = 0; i < items.Length; i++)
                {
                    tempPt += searchSpace.PermutationCounts[i];
                    itemsPt[i] = new(searchSpace.PermutationCounts[i + 1], tempPt);
                }

                Buffer.MemoryCopy(pre, tmp, 60, 30);
                Buffer.MemoryCopy(pre, tmp + 30, 60, 30);
                tmp[firstIndex] = (byte)valPt[firstItem];
                tmp[firstIndex + 30] = (byte)valPt[firstItem];

                do
                {
                    if (loopState.IsStopped)
                    {
                        return;
                    }

                    Buffer.MemoryCopy(tmp + 30, tmp, 60, 30);
                    int i = 0;
                    foreach (Permutation keyItem in items)
                    {
                        tmp[miPt[i]] = (byte)keyItem.GetValue();
                        i++;
                    }

                    if (Loop31Hash(pt, tmp, comparer))
                    {
                        SetResultParallel(tmp, 30);
                        loopState.Stop();
                        return;
                    }
                } while (MoveNext(itemsPt, items.Length));
            }

            report.IncrementProgress();
        }
        private unsafe void Loop31()
        {
            if (searchSpace.MissCount >= 4)
            {
                int max = searchSpace.PermutationCounts[0];
                report.SetProgressStep(max);
                ParallelOptions opts = report.BuildParallelOptions();
                Parallel.For(0, max, opts, (firstItem, state) => Loop31(firstItem, comparer.Clone(), state));
            }
            else
            {
                Debug.Assert(searchSpace.MissCount != 0);
                Permutation[] items = new Permutation[searchSpace.MissCount];

                byte* tmp = stackalloc byte[30];
                uint* pt = stackalloc uint[Sha256Fo.UBufferSize];
                fixed (byte* pre = &searchSpace.preComputed[0])
                fixed (int* miPt = &searchSpace.MissingIndexes[0])
                fixed (uint* valPt = &searchSpace.AllPermutationValues[0])
                fixed (Permutation* itemsPt = &items[0])
                {
                    uint* tempPt = valPt;
                    for (int i = 0; i < items.Length; i++)
                    {
                        itemsPt[i] = new(searchSpace.PermutationCounts[i], tempPt);
                        tempPt += searchSpace.PermutationCounts[i];
                    }

                    do
                    {
                        Buffer.MemoryCopy(pre, tmp, 30, 30);
                        int i = 0;
                        foreach (Permutation keyItem in items)
                        {
                            tmp[miPt[i]] = (byte)keyItem.GetValue();
                            i++;
                        }

                        if (Loop31Hash(pt, tmp, comparer))
                        {
                            SetResultParallel(tmp, 30);
                            return;
                        }
                    } while (MoveNext(itemsPt, items.Length));
                }
            }
        }


        public async void Find(MiniKeySearchSpace ss, string comp, CompareInputType compType)
        {
            report.Init();

            if (!InputService.TryGetCompareService(compType, comp, out comparer))
                report.Fail("Invalid compare input or type.");
            else
            {
                if (ss.MissCount == 0)
                {
                    report.AddMessageSafe("The given input has no missing characters, verifying it as a complete minikey.");
                    report.FoundAnyResult = ss.ProcessNoMissing(out string msg);
                    report.AddMessageSafe(msg);
                    report.Finalize();
                    return;
                }

                report.AddMessageSafe($"The given mini key is {ss.Input.Length} characters long and is missing " +
                                      $"{ss.MissCount} of them.");
                report.SetTotal(ss.GetTotal());
                report.Timer.Start();

                searchSpace = ss;
                if (ss.Input.Length == ConstantsFO.MiniKeyLen1)
                {
                    await Task.Run(Loop23);
                }
                else if (ss.Input.Length == ConstantsFO.MiniKeyLen2)
                {
                    await Task.Run(Loop27);
                }
                else if (ss.Input.Length == ConstantsFO.MiniKeyLen3)
                {
                    await Task.Run(Loop31);
                }
                else
                {
                    report.Fail($"Minikey length must be {ConstantsFO.MiniKeyLen1} or {ConstantsFO.MiniKeyLen2} or " +
                                $"{ConstantsFO.MiniKeyLen3}.");
                }

                report.Finalize();
            }
        }
    }
}
