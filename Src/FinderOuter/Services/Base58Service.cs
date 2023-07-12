// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using Autarkysoft.Bitcoin.Cryptography.EllipticCurve;
using Autarkysoft.Bitcoin.Encoders;
using FinderOuter.Backend;
using FinderOuter.Backend.Hashing;
using FinderOuter.Models;
using FinderOuter.Services.Comparers;
using FinderOuter.Services.SearchSpaces;
using System;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

namespace FinderOuter.Services
{
    public class Base58Service
    {
        public Base58Service(IReport rep)
        {
            report = rep;
        }


        private readonly IReport report;
        private ICompareService comparer;
        private B58SearchSpace searchSpace;


        private bool IsMissingFromEnd()
        {
            if (searchSpace.MissingIndexes[0] != searchSpace.Input.Length - 1)
            {
                return false;
            }

            if (searchSpace.MissingIndexes.Length != 1)
            {
                for (int i = 1; i < searchSpace.MissingIndexes.Length; i++)
                {
                    if (searchSpace.MissingIndexes[i - 1] - searchSpace.MissingIndexes[i] != 1)
                    {
                        return false;
                    }
                }
            }
            return true;
        }


        private const int WifEndDiv = 1_000_000;
        private bool isWifEndCompressed;
        private BigInteger wifEndStart;
        private void SetResultParallelWifEnd(int added)
        {
            using PrivateKey tempKey = new(wifEndStart + added);
            string tempWif = tempKey.ToWif(isWifEndCompressed);
            report.AddMessageSafe($"Found the key: {tempWif}");
            report.FoundAnyResult = true;
        }
        private void WifLoopMissingEnd(in Scalar8x32 smallKey, int start, long max,
                                       ICompareService comparer, ParallelLoopState loopState)
        {
            if (loopState.IsStopped)
            {
                return;
            }

            Scalar8x32 toAddSc = new((uint)(start * WifEndDiv), 0, 0, 0, 0, 0, 0, 0);
            Scalar8x32 initial = smallKey.Add(toAddSc, out bool overflow);
            if (overflow)
            {
                return;
            }
            PointJacobian pt = comparer.Calc.MultiplyByG(initial);
            Point g = Calc.G;

            for (int i = 0; i < max; i++)
            {
                // The first point is the smallKey * G the next is smallKey+1 * G
                // And there is one extra addition at the end which shouldn't matter speed-wise
                if (comparer.Compare(pt))
                {
                    SetResultParallelWifEnd((start * WifEndDiv) + i);

                    loopState.Stop();
                    break;
                }
                pt = pt.AddVar(g, out _);
            }

            report.IncrementProgress();
        }

        private void WifLoopMissingEnd(bool compressed)
        {
            // Numbers are approximates, values usually are ±1
            //         Uncompressed ;     Compressed
            // 1-5 ->             1 ;              1
            // 6   ->             9 ;              1
            // 7   ->           514 ;              3
            // 8   ->        29,817 ;            117
            // 9   ->     1,729,387 ;          6,756
            // 10  ->   100,304,420 ;        391,815
            // 11  -> 5,817,656,406 ;     22,725,222  <-- FinderOuter limits the search to 11
            // 12  ->               ;  1,318,062,780

            string baseWif = searchSpace.Input.Substring(0, searchSpace.Input.Length - searchSpace.MissCount);
            string smallWif = $"{baseWif}{new string(Enumerable.Repeat(ConstantsFO.Base58Chars[0], searchSpace.MissCount).ToArray())}";
            string bigWif = $"{baseWif}{new string(Enumerable.Repeat(ConstantsFO.Base58Chars[^1], searchSpace.MissCount).ToArray())}";
            BigInteger start = Base58.Decode(smallWif).SubArray(1, 32).ToBigInt(true, true);
            BigInteger end = Base58.Decode(bigWif).SubArray(1, 32).ToBigInt(true, true);

            // If the key (integer) value is so tiny that almost all of its higher bytes are zero, or too big that almost
            // all of its bytes are 0xff the smallWif string can end up being bigger in value than the bigWif string 
            // and in some cases withwith an invalid first byte.
            // Chances of a wallet producing such values is practically zero, so the following condition is only
            // to prevent program from crashing if someone used a _test_ key!
            if (end < start)
            {
                report.AddMessageSafe($"The given key is an edge case that can not be recovered. If this key was created by " +
                                      $"a wallet and not some puzzle or test,... please open an issue on GitHub." +
                                      $"{Environment.NewLine}" +
                                      $"Here are the upper and lower values of the given key (DO NOT SHARE THESE):" +
                                      $"{Environment.NewLine}" +
                                      $"Low:{Environment.NewLine}    {smallWif}{Environment.NewLine}" +
                                      $"    {Base58.Decode(smallWif).ToBase16()}" +
                                      $"{Environment.NewLine}" +
                                      $"High:{Environment.NewLine}    {bigWif}{Environment.NewLine}" +
                                      $"    {Base58.Decode(bigWif).ToBase16()}");
                return;
            }

            BigInteger diff = end - start + 1;
            report.AddMessageSafe($"Using an optimized method checking only {diff:n0} keys.");

            Autarkysoft.Bitcoin.Cryptography.Asymmetric.EllipticCurve.SecP256k1 curve = new();
            if (start == 0 || end >= curve.N)
            {
                report.AddMessageSafe("There is something wrong with the given key, it is outside of valid key range.");
                return;
            }

            // With small number of missing keys there is only 1 result or worse case 2 which is simply printed without
            // needing ICompareService. Instead all possible addresses are printed.
            if (diff < 3)
            {
                for (int i = 0; i < (int)diff; i++)
                {
                    using PrivateKey tempKey = new(start + i);
                    string tempWif = tempKey.ToWif(compressed);
                    if (tempWif.Contains(baseWif))
                    {
                        Point pub = tempKey.ToPublicKey(comparer.Calc);
                        string msg = $"Found the key: {tempWif}{Environment.NewLine}" +
                            $"     Compressed P2PKH address={Address.GetP2pkh(pub, true)}{Environment.NewLine}" +
                            $"     Uncompressed P2PKH address={Address.GetP2pkh(pub, false)}{Environment.NewLine}" +
                            $"     Compressed P2WPKH address={Address.GetP2wpkh(pub)}{Environment.NewLine}" +
                            $"     Compressed P2SH-P2WPKH address={Address.GetP2sh_P2wpkh(pub)}";
                        report.AddMessageSafe(msg);
                        report.FoundAnyResult = true;
                    }
                }

                return;
            }

            if (comparer is null)
            {
                report.AddMessageSafe("You must enter address or pubkey to compare with results.");
                return;
            }

            Scalar8x32 sc = new(Base58.Decode(smallWif).SubArray(1, 32), out bool overflow);

            isWifEndCompressed = compressed;
            wifEndStart = start;

            int loopLastMax = (int)((long)diff % WifEndDiv);
            int loopCount = (int)((long)diff / WifEndDiv) + (loopLastMax == 0 ? 0 : 1);

            report.SetTotal(diff);
            report.SetProgressStep(loopCount);

            ParallelOptions opts = report.BuildParallelOptions();
            Parallel.For(0, loopCount, opts, (i, state) =>
                             WifLoopMissingEnd(sc, i, i == loopCount - 1 ? loopLastMax : WifEndDiv, comparer.Clone(), state));
        }

        private unsafe void SetResultParallel(Permutation* itemPt, int firstItem, int misStart)
        {
            // Chances of finding more than 1 correct result is very small in base-58 and even if it happened 
            // this method would be called in very long intervals, meaning UI updates here are not an issue.
            report.AddMessageSafe($"Found a possible result (will continue checking the rest):");

            char[] temp = searchSpace.Input.ToCharArray();
            if (misStart != 0)
            {
                temp[searchSpace.MissingIndexes[0]] = B58SearchSpace.AllChars[firstItem];
            }
            for (int i = misStart; i < searchSpace.MissCount; i++)
            {
                temp[searchSpace.MissingIndexes[i]] = B58SearchSpace.AllChars[itemPt[i - misStart].GetValue()];
            }

            report.AddMessageSafe(new string(temp));
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
        private static unsafe bool MoveNext(uint* itemPt, int len)
        {
            for (int i = len - 1; i >= 0; --i)
            {
                itemPt[i] += 1;

                if (itemPt[i] == 58)
                {
                    itemPt[i] = 0;
                }
                else
                {
                    return true;
                }
            }

            return false;
        }

        private unsafe void LoopComp(ulong[] precomputed, int firstItem, int misStart)
        {
            Debug.Assert(searchSpace.MissCount - misStart >= 1);
            Permutation[] items = new Permutation[searchSpace.MissCount - misStart];
            ICompareService localComp = comparer.Clone();

            ulong* tmp = stackalloc ulong[precomputed.Length];
            uint* pt = stackalloc uint[Sha256Fo.UBufferSize];
            fixed (ulong* pow = &searchSpace.multPow58[0], pre = &precomputed[0])
            fixed (int* mi = &searchSpace.multMissingIndexes[misStart])
            fixed (uint* valPt = &searchSpace.AllPermutationValues[0])
            fixed (Permutation* itemsPt = &items[0])
            {
                uint* tempPt = valPt;
                if (misStart > 0)
                {
                    tempPt += searchSpace.PermutationCounts[0];
                }
                for (int i = 0; i < items.Length; i++)
                {
                    itemsPt[i] = new(searchSpace.PermutationCounts[i + misStart], tempPt);
                    tempPt += searchSpace.PermutationCounts[i];
                }

                do
                {
                    Buffer.MemoryCopy(pre, tmp, 80, 80); // 10x 8-bytes
                    int i = 0;
                    foreach (Permutation keyItem in items)
                    {
                        int chunk = ((int)keyItem.GetValue() * 520) + mi[i++];

                        tmp[0] += pow[0 + chunk];
                        tmp[1] += pow[1 + chunk];
                        tmp[2] += pow[2 + chunk];
                        tmp[3] += pow[3 + chunk];
                        tmp[4] += pow[4 + chunk];
                        tmp[5] += pow[5 + chunk];
                        tmp[6] += pow[6 + chunk];
                        tmp[7] += pow[7 + chunk];
                        tmp[8] += pow[8 + chunk];
                        tmp[9] += pow[9 + chunk];
                    }

                    // Normalize:
                    tmp[1] += tmp[0] >> 32;
                    pt[16] = ((uint)tmp[1] & 0xffff0000) | 0b00000000_00000000_10000000_00000000U; tmp[2] += tmp[1] >> 32;
                    pt[15] = (uint)tmp[2]; tmp[3] += tmp[2] >> 32;
                    pt[14] = (uint)tmp[3]; tmp[4] += tmp[3] >> 32;
                    pt[13] = (uint)tmp[4]; tmp[5] += tmp[4] >> 32;
                    pt[12] = (uint)tmp[5]; tmp[6] += tmp[5] >> 32;
                    pt[11] = (uint)tmp[6]; tmp[7] += tmp[6] >> 32;
                    pt[10] = (uint)tmp[7]; tmp[8] += tmp[7] >> 32;
                    pt[9] = (uint)tmp[8]; tmp[9] += tmp[8] >> 32;
                    pt[8] = (uint)tmp[9];
                    Debug.Assert(tmp[9] >> 32 == 0);

                    if (((pt[8] & 0xff000000) | (pt[16] & 0x00ff0000)) == 0x80010000)
                    {
                        uint expectedCS = (uint)tmp[0] >> 16 | (uint)tmp[1] << 16;

                        // The following has to be set since second block compression changes it
                        pt[23] = 272; // 34 *8 = 272
                        Sha256Fo.Init(pt);
                        Sha256Fo.CompressDouble34(pt);

                        if (pt[0] == expectedCS)
                        {
                            SetResultParallel(itemsPt, firstItem, misStart);
                        }
                    }
                } while (MoveNext(itemsPt, items.Length));
            }

            report.IncrementProgress();
        }
        private unsafe ulong[] ParallelPre(int firstItem, int len)
        {
            ulong[] localPre = new ulong[searchSpace.preComputed.Length];
            fixed (ulong* lpre = &localPre[0], pre = &searchSpace.preComputed[0], pow = &searchSpace.multPow58[0])
            {
                Buffer.MemoryCopy(pre, lpre, 80, 80);
                int chunk = (firstItem * len * 10) + searchSpace.multMissingIndexes[0];

                lpre[0] += pow[0 + chunk];
                lpre[1] += pow[1 + chunk];
                lpre[2] += pow[2 + chunk];
                lpre[3] += pow[3 + chunk];
                lpre[4] += pow[4 + chunk];
                lpre[5] += pow[5 + chunk];
                lpre[6] += pow[6 + chunk];
                lpre[7] += pow[7 + chunk];
                lpre[8] += pow[8 + chunk];
                lpre[9] += pow[9 + chunk];
            }

            return localPre;
        }
        private unsafe void LoopComp()
        {
            if (IsMissingFromEnd() && searchSpace.MissCount <= 11)
            {
                WifLoopMissingEnd(true);
            }
            else if (searchSpace.MissCount >= 5)
            {
                // 4 missing chars is 11,316,496 cases and it takes <2 seconds to run.
                // That makes 5 the optimal number for using parallelization
                int max = searchSpace.PermutationCounts[0];
                report.SetProgressStep(max);
                ParallelOptions opts = report.BuildParallelOptions();
                Parallel.For(0, max, opts, (firstItem) => LoopComp(ParallelPre(firstItem, 52), firstItem, 1));
            }
            else
            {
                LoopComp(searchSpace.preComputed, 0, 0);
            }
        }

        private unsafe void LoopUncomp(ulong[] precomputed, int firstItem, int misStart)
        {
            Debug.Assert(searchSpace.MissCount - misStart >= 1);
            Permutation[] items = new Permutation[searchSpace.MissCount - misStart];

            ulong* tmp = stackalloc ulong[precomputed.Length];
            uint* pt = stackalloc uint[Sha256Fo.UBufferSize];
            fixed (ulong* pow = &searchSpace.multPow58[0], pre = &precomputed[0])
            fixed (int* mi = &searchSpace.multMissingIndexes[misStart])
            fixed (uint* valPt = &searchSpace.AllPermutationValues[0])
            fixed (Permutation* itemsPt = &items[0])
            {
                uint* tempPt = valPt;
                if (misStart > 0)
                {
                    tempPt += searchSpace.PermutationCounts[0];
                }
                for (int i = 0; i < items.Length; i++)
                {
                    itemsPt[i] = new(searchSpace.PermutationCounts[i + misStart], tempPt);
                    tempPt += searchSpace.PermutationCounts[i];
                }

                do
                {
                    Buffer.MemoryCopy(pre, tmp, 80, 80); // 10x 8-bytes
                    int i = 0;
                    foreach (Permutation keyItem in items)
                    {
                        int chunk = ((int)keyItem.GetValue() * 510) + mi[i++];

                        tmp[0] += pow[0 + chunk];
                        tmp[1] += pow[1 + chunk];
                        tmp[2] += pow[2 + chunk];
                        tmp[3] += pow[3 + chunk];
                        tmp[4] += pow[4 + chunk];
                        tmp[5] += pow[5 + chunk];
                        tmp[6] += pow[6 + chunk];
                        tmp[7] += pow[7 + chunk];
                        tmp[8] += pow[8 + chunk];
                        tmp[9] += pow[9 + chunk];
                    }

                    // Normalize:
                    tmp[1] += tmp[0] >> 32;
                    pt[16] = ((uint)tmp[1] & 0xff000000) | 0b00000000_10000000_00000000_00000000U; tmp[2] += tmp[1] >> 32;
                    pt[15] = (uint)tmp[2]; tmp[3] += tmp[2] >> 32;
                    pt[14] = (uint)tmp[3]; tmp[4] += tmp[3] >> 32;
                    pt[13] = (uint)tmp[4]; tmp[5] += tmp[4] >> 32;
                    pt[12] = (uint)tmp[5]; tmp[6] += tmp[5] >> 32;
                    pt[11] = (uint)tmp[6]; tmp[7] += tmp[6] >> 32;
                    pt[10] = (uint)tmp[7]; tmp[8] += tmp[7] >> 32;
                    pt[9] = (uint)tmp[8]; tmp[9] += tmp[8] >> 32;
                    pt[8] = (uint)tmp[9];
                    Debug.Assert(tmp[9] >> 32 == 0);

                    if ((pt[8] & 0xff000000) == 0x80000000)
                    {
                        uint expectedCS = (uint)tmp[0] >> 24 | (uint)tmp[1] << 8;

                        // The following has to be set since second block compression changes it
                        pt[23] = 264; // 33 *8 = 264

                        Sha256Fo.Init(pt);
                        Sha256Fo.CompressDouble33(pt);

                        if (pt[0] == expectedCS)
                        {
                            SetResultParallel(itemsPt, firstItem, misStart);
                        }
                    }
                } while (MoveNext(itemsPt, items.Length));
            }

            report.IncrementProgress();
        }
        private unsafe void LoopUncomp()
        {
            if (IsMissingFromEnd() && searchSpace.MissCount <= 11)
            {
                WifLoopMissingEnd(false);
            }
            else if (searchSpace.MissCount >= 5)
            {
                // Same as LoopComp()
                report.SetProgressStep(58);
                ParallelOptions opts = report.BuildParallelOptions();
                Parallel.For(0, 58, opts, (firstItem) => LoopUncomp(ParallelPre(firstItem, 51), firstItem, 1));
            }
            else
            {
                LoopUncomp(searchSpace.preComputed, 0, 0);
            }
        }


        private unsafe void Loop21(ulong[] precomputed, int firstItem, int misStart)
        {
            Debug.Assert(searchSpace.MissCount - misStart >= 1);
            Permutation[] items = new Permutation[searchSpace.MissCount - misStart];

            ulong[] temp = new ulong[precomputed.Length];
            uint* pt = stackalloc uint[Sha256Fo.UBufferSize];
            fixed (ulong* pow = &searchSpace.multPow58[0], tmp = &temp[0], pre = &precomputed[0])
            fixed (int* mi = &searchSpace.multMissingIndexes[misStart])
            fixed (uint* valPt = &searchSpace.AllPermutationValues[0])
            fixed (Permutation* itemsPt = &items[0])
            {
                uint* tempPt = valPt;
                if (misStart > 0)
                {
                    tempPt += searchSpace.PermutationCounts[0];
                }
                for (int i = 0; i < items.Length; i++)
                {
                    itemsPt[i] = new(searchSpace.PermutationCounts[i + misStart], tempPt);
                    tempPt += searchSpace.PermutationCounts[i];
                }

                do
                {
                    Buffer.MemoryCopy(pre, tmp, 56, 56); // 7x 8-bytes
                    int i = 0;
                    foreach (Permutation item in items)
                    {
                        // TODO: change 7 into a field from searchspace(?)
                        int chunk = ((int)item.GetValue() * searchSpace.Input.Length * 7) + mi[i++];

                        tmp[0] += pow[0 + chunk];
                        tmp[1] += pow[1 + chunk];
                        tmp[2] += pow[2 + chunk];
                        tmp[3] += pow[3 + chunk];
                        tmp[4] += pow[4 + chunk];
                        tmp[5] += pow[5 + chunk];
                        tmp[6] += pow[6 + chunk];
                    }

                    // Normalize
                    tmp[1] += tmp[0] >> 32;
                    pt[13] = ((uint)tmp[1] & 0xff000000) | 0b00000000_10000000_00000000_00000000U; tmp[2] += tmp[1] >> 32;
                    pt[12] = (uint)tmp[2]; tmp[3] += tmp[2] >> 32;
                    pt[11] = (uint)tmp[3]; tmp[4] += tmp[3] >> 32;
                    pt[10] = (uint)tmp[4]; tmp[5] += tmp[4] >> 32;
                    pt[9] = (uint)tmp[5]; tmp[6] += tmp[5] >> 32;
                    pt[8] = (uint)tmp[6];
                    Debug.Assert(tmp[6] >> 32 == 0);

                    pt[14] = 0;
                    pt[15] = 0;
                    pt[16] = 0;
                    // from 6 to 14 = 0
                    pt[23] = 168; // 21 *8 = 168

                    Sha256Fo.Init(pt);
                    Sha256Fo.CompressDouble21(pt);

                    uint expectedCS = (uint)tmp[0] >> 24 | (uint)tmp[1] << 8;
                    if (pt[0] == expectedCS)
                    {
                        SetResultParallel(itemsPt, firstItem, misStart);
                    }
                } while (MoveNext(itemsPt, items.Length));
            }

            report.IncrementProgress();
        }
        private unsafe ulong[] ParallelPre21(int firstItem)
        {
            ulong[] localPre = new ulong[searchSpace.preComputed.Length];
            fixed (ulong* lpre = &localPre[0], pre = &searchSpace.preComputed[0], pow = &searchSpace.multPow58[0])
            {
                Buffer.MemoryCopy(pre, lpre, 56, 56);
                int chunk = (firstItem * searchSpace.Input.Length * 7) + searchSpace.multMissingIndexes[0];

                lpre[0] += pow[0 + chunk];
                lpre[1] += pow[1 + chunk];
                lpre[2] += pow[2 + chunk];
                lpre[3] += pow[3 + chunk];
                lpre[4] += pow[4 + chunk];
                lpre[5] += pow[5 + chunk];
                lpre[6] += pow[6 + chunk];
            }

            return localPre;
        }
        private unsafe void Loop21()
        {
            if (searchSpace.MissCount >= 5)
            {
                int max = searchSpace.PermutationCounts[0];
                report.SetProgressStep(max);
                ParallelOptions opts = report.BuildParallelOptions();
                Parallel.For(0, max, opts, (firstItem) => Loop21(ParallelPre21(firstItem), firstItem, 1));
            }
            else
            {
                Loop21(searchSpace.preComputed, 0, 0);
            }
        }


        private unsafe void Loop58(ulong[] precomputed, int firstItem, int misStart)
        {
            Debug.Assert(searchSpace.MissCount - misStart >= 1);
            Permutation[] items = new Permutation[searchSpace.MissCount - misStart];

            ulong[] temp = new ulong[precomputed.Length];
            uint* pt = stackalloc uint[Sha256Fo.UBufferSize];
            fixed (ulong* pow = &searchSpace.multPow58[0], pre = &precomputed[0], tmp = &temp[0])
            fixed (int* mi = &searchSpace.multMissingIndexes[misStart])
            fixed (uint* valPt = &searchSpace.AllPermutationValues[0])
            fixed (Permutation* itemsPt = &items[0])
            {
                uint* tempPt = valPt;
                if (misStart > 0)
                {
                    tempPt += searchSpace.PermutationCounts[0];
                }
                for (int i = 0; i < items.Length; i++)
                {
                    itemsPt[i] = new(searchSpace.PermutationCounts[i + misStart], tempPt);
                    tempPt += searchSpace.PermutationCounts[i];
                }

                do
                {
                    Buffer.MemoryCopy(pre, tmp, 88, 88); // 11x 8-bytes
                    int i = 0;
                    foreach (Permutation item in items)
                    {
                        // TODO: change 11 into a field from searchspace(?)
                        int chunk = ((int)item.GetValue() * searchSpace.Input.Length * 11) + mi[i++];

                        tmp[0] += pow[0 + chunk];
                        tmp[1] += pow[1 + chunk];
                        tmp[2] += pow[2 + chunk];
                        tmp[3] += pow[3 + chunk];
                        tmp[4] += pow[4 + chunk];
                        tmp[5] += pow[5 + chunk];
                        tmp[6] += pow[6 + chunk];
                        tmp[7] += pow[7 + chunk];
                        tmp[8] += pow[8 + chunk];
                        tmp[9] += pow[9 + chunk];
                        tmp[10] += pow[10 + chunk];
                    }

                    // Normalize:
                    tmp[1] += tmp[0] >> 32;
                    pt[17] = ((uint)tmp[1] & 0xffffff00) | 0b00000000_00000000_00000000_10000000U; tmp[2] += tmp[1] >> 32;
                    pt[16] = (uint)tmp[2]; tmp[3] += tmp[2] >> 32;
                    pt[15] = (uint)tmp[3]; tmp[4] += tmp[3] >> 32;
                    pt[14] = (uint)tmp[4]; tmp[5] += tmp[4] >> 32;
                    pt[13] = (uint)tmp[5]; tmp[6] += tmp[5] >> 32;
                    pt[12] = (uint)tmp[6]; tmp[7] += tmp[6] >> 32;
                    pt[11] = (uint)tmp[7]; tmp[8] += tmp[7] >> 32;
                    pt[10] = (uint)tmp[8]; tmp[9] += tmp[8] >> 32;
                    pt[9] = (uint)tmp[9]; tmp[10] += tmp[9] >> 32;
                    pt[8] = (uint)tmp[10];
                    Debug.Assert(tmp[10] >> 32 == 0);

                    // TODO: are the following 2 numbers correct?!
                    // from 10 to 14 = 0
                    pt[23] = 312; // 39 *8 = 168

                    Sha256Fo.Init(pt);
                    Sha256Fo.CompressDouble39(pt);

                    uint expectedCS = (uint)tmp[0] >> 8 | (uint)tmp[1] << 24;
                    if (pt[0] == expectedCS)
                    {
                        SetResultParallel(itemsPt, firstItem, misStart);
                    }
                } while (MoveNext(itemsPt, items.Length));
            }

            report.IncrementProgress();
        }
        private unsafe ulong[] ParallelPre58(int firstItem)
        {
            ulong[] localPre = new ulong[searchSpace.preComputed.Length];
            fixed (ulong* lpre = &localPre[0], pre = &searchSpace.preComputed[0], pow = &searchSpace.multPow58[0])
            {
                Buffer.MemoryCopy(pre, lpre, 88, 88);
                int chunk = (firstItem * searchSpace.Input.Length * 11) + searchSpace.multMissingIndexes[0];

                lpre[0] += pow[0 + chunk];
                lpre[1] += pow[1 + chunk];
                lpre[2] += pow[2 + chunk];
                lpre[3] += pow[3 + chunk];
                lpre[4] += pow[4 + chunk];
                lpre[5] += pow[5 + chunk];
                lpre[6] += pow[6 + chunk];
                lpre[7] += pow[7 + chunk];
                lpre[8] += pow[8 + chunk];
                lpre[9] += pow[9 + chunk];
                lpre[10] += pow[10 + chunk];
            }

            return localPre;
        }
        private unsafe void Loop58()
        {
            if (searchSpace.MissCount >= 2)
            {
                int max = searchSpace.PermutationCounts[0];
                report.SetProgressStep(max);
                ParallelOptions opts = report.BuildParallelOptions();
                Parallel.For(0, max, opts, (firstItem) => Loop58(ParallelPre58(firstItem), firstItem, 1));
            }
            else
            {
                Loop58(searchSpace.preComputed, 0, 0);
            }
        }



        private unsafe bool SpecialLoopComp1(string key, bool comp)
        {
            int maxKeyLen = comp ? ConstantsFO.PrivKeyCompWifLen : ConstantsFO.PrivKeyUncompWifLen;

            byte[] padded;
            int uLen;

            // Maximum result (58^52) is 39 bytes = 39/4 = 10 uint
            uLen = 10;
            uint[] powers58 = new uint[maxKeyLen * uLen];
            padded = new byte[4 * uLen];

            for (int i = 0, j = 0; i < maxKeyLen; i++)
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

            Span<uint> precomputed = new uint[uLen];

            fixed (uint* pre = &precomputed[0], pow = &powers58[0])
            {
                // i starts from 1 becaue it is compressed (K or L)
                for (int i = 1; i < maxKeyLen; i++)
                {
                    precomputed.Clear();

                    for (int index = 0; index < i; index++)
                    {
                        ulong carry = 0;
                        ulong val = (ulong)values[index];
                        int powIndex = (maxKeyLen - 1 - index) * uLen;
                        for (int m = uLen - 1; m >= 0; m--, powIndex++)
                        {
                            ulong result = (pow[powIndex] * val) + pre[m] + carry;
                            pre[m] = (uint)result;
                            carry = (uint)(result >> 32);
                        }
                    }

                    for (int index = i + 1; index < maxKeyLen; index++)
                    {
                        ulong carry = 0;
                        ulong val = (ulong)values[index - 1];
                        int powIndex = (maxKeyLen - 1 - index) * uLen;
                        for (int m = uLen - 1; m >= 0; m--, powIndex++)
                        {
                            ulong result = (pow[powIndex] * val) + pre[m] + carry;
                            pre[m] = (uint)result;
                            carry = (uint)(result >> 32);
                        }
                    }

                    for (int c1 = 0; c1 < 58; c1++)
                    {
                        Span<uint> temp = new uint[precomputed.Length];
                        precomputed.CopyTo(temp);

                        ulong carry = 0;
                        ulong val = (ulong)c1;
                        int powIndex = (maxKeyLen - 1 - i) * uLen;
                        for (int m = uLen - 1; m >= 0; m--, powIndex++)
                        {
                            ulong result = (powers58[powIndex] * val) + temp[m] + carry;
                            temp[m] = (uint)result;
                            carry = (uint)(result >> 32);
                        }

                        bool checksum = comp ? ComputeSpecialCompHash(temp) : ComputeSpecialUncompHash(temp);
                        if (checksum)
                        {
                            string foundRes = key.Insert(i, $"{ConstantsFO.Base58Chars[c1]}");
                            report.AddMessageSafe($"Found a key: {foundRes}");
                            report.FoundAnyResult = true;
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        private unsafe bool SpecialLoopComp2(string key, bool comp)
        {
            int maxKeyLen = comp ? ConstantsFO.PrivKeyCompWifLen : ConstantsFO.PrivKeyUncompWifLen;

            byte[] padded;

            // Maximum result (58^52) is 39 bytes = 39/4 = 10 uint
            const int uLen = 10;
            uint[] powers58 = new uint[maxKeyLen * uLen];
            padded = new byte[4 * uLen];

            for (int i = 0, j = 0; i < maxKeyLen; i++)
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
                report.SetProgressStep(maxKeyLen);
                // i starts from 1 becaue it is compressed (K or L)
                for (int i = 1; i < maxKeyLen - 1; i++)
                {
                    for (int j = i + 1; j < maxKeyLen; j++)
                    {
                        ((Span<uint>)precomputed).Clear();

                        for (int index = 0; index < i; index++)
                        {
                            ulong carry = 0;
                            ulong val = (ulong)values[index];
                            int powIndex = (maxKeyLen - 1 - index) * uLen;
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
                            int powIndex = (maxKeyLen - 1 - index) * uLen;
                            for (int m = uLen - 1; m >= 0; m--, powIndex++)
                            {
                                ulong result = (pow[powIndex] * val) + pre[m] + carry;
                                pre[m] = (uint)result;
                                carry = (uint)(result >> 32);
                            }
                        }

                        for (int index = j + 1; index < maxKeyLen; index++)
                        {
                            ulong carry = 0;
                            ulong val = (ulong)values[index - 2];
                            int powIndex = (maxKeyLen - 1 - index) * uLen;
                            for (int m = uLen - 1; m >= 0; m--, powIndex++)
                            {
                                ulong result = (pow[powIndex] * val) + pre[m] + carry;
                                pre[m] = (uint)result;
                                carry = (uint)(result >> 32);
                            }
                        }

                        Debug.Assert(pow[0] == 12);

                        ParallelOptions opts = report.BuildParallelOptions();
                        Parallel.For(0, 58, opts, (c1, state) =>
                        {
                            for (int c2 = 0; c2 < 58; c2++)
                            {
                                if (state.IsStopped)
                                {
                                    return;
                                }

                                Span<uint> temp = new uint[precomputed.Length];
                                precomputed.CopyTo(temp);

                                ulong carry = 0;
                                ulong val = (ulong)c1;
                                int powIndex = (maxKeyLen - 1 - i) * uLen;
                                for (int m = uLen - 1; m >= 0; m--, powIndex++)
                                {
                                    ulong result = (powers58[powIndex] * val) + temp[m] + carry;
                                    temp[m] = (uint)result;
                                    carry = (uint)(result >> 32);
                                }

                                carry = 0;
                                val = (ulong)c2;
                                powIndex = (maxKeyLen - 1 - j) * uLen;
                                for (int m = uLen - 1; m >= 0; m--, powIndex++)
                                {
                                    ulong result = (powers58[powIndex] * val) + temp[m] + carry;
                                    temp[m] = (uint)result;
                                    carry = (uint)(result >> 32);
                                }

                                bool checksum = comp ? ComputeSpecialCompHash(temp) : ComputeSpecialUncompHash(temp);
                                if (checksum)
                                {
                                    string foundRes = key.Insert(i, $"{ConstantsFO.Base58Chars[c1]}")
                                                         .Insert(j, $"{ConstantsFO.Base58Chars[c2]}");
                                    report.AddMessageSafe($"Found a key: {foundRes}");
                                    report.FoundAnyResult = true;
                                    state.Stop();
                                    return;
                                }
                            }
                        });
                    }
                    report.IncrementProgress();
                }
            }
            return false;
        }

        private unsafe bool SpecialLoopComp3(string key)
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
                report.SetProgressStep(ConstantsFO.PrivKeyCompWifLen);

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

                            CancellationTokenSource cancelToken = new();
                            ParallelOptions options = report.BuildParallelOptions();
                            options.CancellationToken = cancelToken.Token;

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

                                            if (ComputeSpecialCompHash(temp))
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

                report.IncrementProgress();
            }
            return false;
        }

        private static unsafe bool ComputeSpecialUncompHash(Span<uint> keyValueInts)
        {
            if (keyValueInts[0] != 0x00000080)
            {
                return false;
            }

            uint* pt = stackalloc uint[Sha256Fo.UBufferSize];
            fixed (uint* keyPt = &keyValueInts[0])
            {
                pt[8] = (keyPt[0] << 24) | (keyPt[1] >> 8);
                pt[9] = (keyPt[1] << 24) | (keyPt[2] >> 8);
                pt[10] = (keyPt[2] << 24) | (keyPt[3] >> 8);
                pt[11] = (keyPt[3] << 24) | (keyPt[4] >> 8);
                pt[12] = (keyPt[4] << 24) | (keyPt[5] >> 8);
                pt[13] = (keyPt[5] << 24) | (keyPt[6] >> 8);
                pt[14] = (keyPt[6] << 24) | (keyPt[7] >> 8);
                pt[15] = (keyPt[7] << 24) | (keyPt[8] >> 8);
                pt[16] = (keyPt[8] << 24) | 0b00000000_10000000_00000000_00000000U;
                // from 9 to 14 = 0
                pt[23] = 264; // 33 *8 = 264

                Sha256Fo.Init(pt);
                Sha256Fo.CompressDouble33(pt);

                return pt[0] == keyPt[9];
            }
        }

        private static unsafe bool ComputeSpecialCompHash(Span<uint> keyValueInts)
        {
            if (((keyValueInts[0] & 0xffffff00) | (keyValueInts[^2] & 0x000000ff)) != 0x00008001)
            {
                return false;
            }

            uint* pt = stackalloc uint[Sha256Fo.UBufferSize];
            fixed (uint* keyPt = &keyValueInts[0])
            {
                pt[8] = (keyPt[0] << 16) | (keyPt[1] >> 16);
                pt[9] = (keyPt[1] << 16) | (keyPt[2] >> 16);
                pt[10] = (keyPt[2] << 16) | (keyPt[3] >> 16);
                pt[11] = (keyPt[3] << 16) | (keyPt[4] >> 16);
                pt[12] = (keyPt[4] << 16) | (keyPt[5] >> 16);
                pt[13] = (keyPt[5] << 16) | (keyPt[6] >> 16);
                pt[14] = (keyPt[6] << 16) | (keyPt[7] >> 16);
                pt[15] = (keyPt[7] << 16) | (keyPt[8] >> 16);
                pt[16] = (keyPt[8] << 16) | 0b00000000_00000000_10000000_00000000U;
                // from 9 to 14 =0
                pt[23] = 272; // 34 *8 = 272

                Sha256Fo.Init(pt);
                Sha256Fo.CompressDouble34(pt);

                return pt[0] == keyPt[9];
            }
        }

        public async Task<bool> FindUnknownLocation1(string key, bool comp)
        {
            // [51! / 1! *((51-1)!)] * 58^1
            BigInteger total = 51 * 58;
            report.SetTotal(total);
            report.Timer.Start();
            bool success = await Task.Run(() => SpecialLoopComp1(key, comp));

            return success;
        }

        public async Task<bool> FindUnknownLocation2(string key, bool comp)
        {
            // [51! / 2! *((51-2)!)] * 58^2
            BigInteger total = ((51 * 50) / (2 * 1)) * BigInteger.Pow(58, 2);
            report.SetTotal(total);
            report.Timer.Start();
            bool success = await Task.Run(() => SpecialLoopComp2(key, comp));

            return success;
        }

        public async Task<bool> FindUnknownLocation3(string key)
        {
            // [51! / 3! *((51-3)!)] * 58^3
            BigInteger total = ((51 * 50 * 49) / (3 * 2 * 1)) * BigInteger.Pow(58, 3);
            report.SetTotal(total);
            report.Timer.Start();
            bool success = await Task.Run(() => SpecialLoopComp3(key));

            return success;
        }


        private async Task FindPrivateKey()
        {
            if (searchSpace.MissCount != 0) // Length must be correct then
            {
                if (InputService.CanBePrivateKey(searchSpace.Input, out string error))
                {
                    report.AddMessageSafe($"{(searchSpace.isComp ? "Compressed" : "Uncompressed")} private key " +
                                          $"missing {searchSpace.MissCount} characters was detected.");
                    report.SetTotal(searchSpace.GetTotal());
                    report.Timer.Start();

                    await Task.Run(() =>
                    {
                        if (searchSpace.isComp)
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
                }
                else
                {
                    report.AddMessageSafe(error);
                }
            }
            else // Doesn't have any missing chars so length must be <= max key len
            {
                report.AddMessageSafe("Recovering keys with missing characters at unknown position is disabled now.");
                report.AddMessageSafe("Use FinderOuter V0.14.0");
                //if (key[0] == ConstantsFO.PrivKeyCompChar1 || key[0] == ConstantsFO.PrivKeyCompChar2)
                //{
                //    if (key.Length == ConstantsFO.PrivKeyCompWifLen)
                //    {
                //        report.AddMessageSafe("No character is missing, checking validity of the key itself.");
                //        report.AddMessageSafe(inputService.CheckPrivateKey(key));
                //        report.FoundAnyResult = true;
                //    }
                //    else if (key.Length == ConstantsFO.PrivKeyCompWifLen - 1)
                //    {
                //        await FindUnknownLocation1(key, true);
                //    }
                //    else if (key.Length == ConstantsFO.PrivKeyCompWifLen - 2)
                //    {
                //        await FindUnknownLocation2(key, true);
                //    }
                //    else if (key.Length == ConstantsFO.PrivKeyCompWifLen - 3)
                //    {
                //        await FindUnknownLocation3(key);
                //    }
                //    else
                //    {
                //        report.AddMessageSafe("Only 3 missing characters at unkown locations is supported for now.");
                //    }
                //}
                //else if (key[0] == ConstantsFO.PrivKeyUncompChar)
                //{
                //    if (key.Length == ConstantsFO.PrivKeyUncompWifLen)
                //    {
                //        report.AddMessageSafe("No character is missing, checking validity of the key itself.");
                //        report.AddMessageSafe(inputService.CheckPrivateKey(key));
                //        report.FoundAnyResult = true;
                //    }
                //    else if (key.Length == ConstantsFO.PrivKeyUncompWifLen - 1)
                //    {
                //        await FindUnknownLocation1(key, false);
                //    }
                //    else if (key.Length == ConstantsFO.PrivKeyUncompWifLen - 2)
                //    {
                //        await FindUnknownLocation2(key, false);
                //    }
                //    else
                //    {
                //        report.AddMessageSafe("Recovering uncompressed private keys with missing characters at unknown locations " +
                //                              "is not supported yet.");
                //    }
                //}
                //else
                //{
                //    report.AddMessageSafe("The given key has an invalid first character.");
                //}
            }
        }

        private async Task FindAddress()
        {
            Debug.Assert(searchSpace.MissCount != 0);
            report.AddMessageSafe($"Base-58 address missing {searchSpace.MissCount} characters was detected.");
            report.SetTotal(searchSpace.GetTotal());
            report.AddMessageSafe("Checking each case. Please wait...");

            report.Timer.Start();
            await Task.Run(() => Loop21());
        }

        private async Task FindBip38()
        {
            Debug.Assert(searchSpace.MissCount != 0);
            report.SetTotal(searchSpace.GetTotal());
            report.AddMessageSafe("Going throgh each case. Please wait...");

            report.Timer.Start();
            await Task.Run(() => Loop58());
        }


        public async void Find(B58SearchSpace ss, string comp, CompareInputType compType)
        {
            report.Init();

            if (ss.MissCount == 0)
            {
                report.FoundAnyResult = ss.ProcessNoMissing(out string msg);
                report.AddMessage(msg);
            }
            else
            {
                searchSpace = ss;
                switch (searchSpace.inputType)
                {
                    case Base58Type.PrivateKey:
                        if (!InputService.TryGetCompareService(compType, comp, out comparer))
                        {
                            if (!string.IsNullOrEmpty(comp))
                                report.AddMessage($"Could not instantiate ICompareService (invalid {compType}).");
                            comparer = new DefaultComparer();
                        }

                        await FindPrivateKey();
                        break;
                    case Base58Type.Address:
                        await FindAddress();
                        break;
                    case Base58Type.Bip38:
                        await FindBip38();
                        break;
                    default:
                        report.Fail("Given input type is not defined.");
                        return;
                }
            }

            report.Finalize();
        }
    }
}
