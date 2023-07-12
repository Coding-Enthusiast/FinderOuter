// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.Cryptography.EllipticCurve;
using FinderOuter.Models;
using FinderOuter.Services.Comparers;
using FinderOuter.Services.SearchSpaces;
using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace FinderOuter.Services
{
    public class Base16Sevice
    {
        public Base16Sevice(IReport rep)
        {
            report = rep;
        }


        private readonly IReport report;
        private ICompareService comparer;
        private B16SearchSpace searchSpace;


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

        private unsafe void SetResultParallel(Permutation* items, int firstItem)
        {
            char[] origHex = searchSpace.Input.ToCharArray();
            origHex[searchSpace.MissingIndexes[0]] = GetHex(firstItem);
            for (int i = 0; i < searchSpace.MissCount - 1; i++)
            {
                int index = searchSpace.MissingIndexes[i + 1];
                origHex[index] = GetHex((int)items[i].GetValue());
            }

            report.AddMessageSafe($"Found the key: {new string(origHex)}");
            report.FoundAnyResult = true;
        }

        private unsafe void Loop(int firstItem, in PointJacobian smallPub, ParallelLoopState loopState)
        {
            Calc calc = new();
            Debug.Assert(searchSpace.MissCount - 1 > 0);
            Permutation[] permutations = new Permutation[searchSpace.MissCount - 1];
            ICompareService localComp = comparer.Clone();

            Span<byte> temp = stackalloc byte[32];

            fixed (int* mi = &searchSpace.MissingIndexes[0])
            fixed (byte* tmp = &temp[0])
            fixed (Permutation* itemsPt = &permutations[0])
            fixed (uint* valPt = &searchSpace.AllPermutationValues[0])
            {
                uint* tempPt = valPt;
                for (int i = 0; i < permutations.Length; i++)
                {
                    tempPt += searchSpace.PermutationCounts[i];
                    itemsPt[i] = new(searchSpace.PermutationCounts[i + 1], tempPt);
                }

                int misIndex = mi[0];
                int firstIndex = misIndex / 2;
                byte firstValue = (misIndex % 2 == 0) ? (byte)(valPt[firstItem] << 4) : (byte)valPt[firstItem];
                tmp[firstIndex] = firstValue;

                do
                {
                    if (loopState.IsStopped)
                    {
                        return;
                    }

                    int mis = 1;
                    foreach (Permutation item in permutations)
                    {
                        misIndex = mi[mis++];
                        if (misIndex % 2 == 0)
                        {
                            tmp[misIndex / 2] &= 0b0000_1111;
                            tmp[misIndex / 2] |= (byte)(item.GetValue() << 4);
                        }
                        else
                        {
                            tmp[misIndex / 2] &= 0b1111_0000;
                            tmp[misIndex / 2] |= (byte)item.GetValue();
                        }
                    }

                    Scalar8x32 tempVal = new(temp, out _);
                    PointJacobian tempPub = calc.MultiplyByG(in tempVal);
                    PointJacobian pub = tempPub.AddVar(smallPub, out _);

                    if (comparer.Compare(pub))
                    {
                        SetResultParallel(itemsPt, firstItem);
                        loopState.Stop();
                        return;
                    }

                } while (MoveNext(itemsPt, permutations.Length));
            }

            report.IncrementProgress();
        }

        private unsafe void Loop()
        {
            Scalar8x32 smallVal = new(searchSpace.preComputed, out _);
            PointJacobian smallPub = comparer.Calc.MultiplyByG(smallVal);

            if (searchSpace.MissCount == 1)
            {
                // Checking max 16 keys is so fast that there is no need to use the limited search space
                int misIndex = searchSpace.MissingIndexes[0];
                int index = misIndex / 2;
                bool condition = misIndex % 2 == 0;

                Span<byte> temp = stackalloc byte[32];
                fixed (int* mi = &searchSpace.MissingIndexes[0])
                fixed (byte* tmp = &temp[0])
                {
                    for (int i = 0; i < 16; i++)
                    {
                        if (condition)
                        {
                            tmp[index] &= 0b0000_1111;
                            tmp[index] |= (byte)(i << 4);
                        }
                        else
                        {
                            tmp[index] &= 0b1111_0000;
                            tmp[index] |= (byte)i;
                        }

                        Scalar8x32 tempVal = new(temp, out _);
                        PointJacobian tempPub = comparer.Calc.MultiplyByG(tempVal);
                        PointJacobian pub = tempPub.AddVar(smallPub, out _);
                        if (comparer.Compare(pub))
                        {
                            char[] origHex = searchSpace.Input.ToCharArray();
                            origHex[misIndex] = GetHex(i);

                            report.AddMessageSafe($"Found the key: {new string(origHex)}");
                            report.FoundAnyResult = true;
                            return;
                        }
                    }
                }
            }
            else
            {
                int max = searchSpace.PermutationCounts[0];
                report.SetProgressStep(max);

                ParallelOptions opts = report.BuildParallelOptions();
                Parallel.For(0, max, opts, (firstItem, state) => Loop(firstItem, smallPub, state));
            }
        }

        private static char GetHex(int val)
        {
            return val switch
            {
                0 => '0',
                1 => '1',
                2 => '2',
                3 => '3',
                4 => '4',
                5 => '5',
                6 => '6',
                7 => '7',
                8 => '8',
                9 => '9',
                10 => 'a',
                11 => 'b',
                12 => 'c',
                13 => 'd',
                14 => 'e',
                15 => 'f',
                _ => throw new ArgumentOutOfRangeException(nameof(val), "Value must be between 0 and 15.")
            };
        }


        public async void Find(B16SearchSpace ss, string comp, CompareInputType compType)
        {
            report.Init();

            if (!InputService.TryGetCompareService(compType, comp, out comparer))
            {
                report.Fail($"Could not instantiate ICompareService (invalid {compType}).");
            }
            else if (ss.MissCount == 0)
            {
                report.FoundAnyResult = ss.ProcessNoMissing(comparer, out string message);
                report.AddMessageSafe(message);
            }
            else
            {
                report.AddMessage($"The given key is missing {ss.MissCount} characters.");
                report.SetTotal(ss.GetTotal());
                report.Timer.Start();

                searchSpace = ss;
                await Task.Run(() => Loop());
            }

            report.Finalize();
        }
    }
}
