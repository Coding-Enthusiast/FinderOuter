// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.Cryptography.Asymmetric.KeyPairs;
using Autarkysoft.Bitcoin.Encoders;
using FinderOuter.Backend;
using FinderOuter.Backend.ECC;
using FinderOuter.Models;
using FinderOuter.Services.Comparers;
using System;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace FinderOuter.Services
{
    public class Base16Sevice
    {
        public Base16Sevice(IReport rep)
        {
            inputService = new InputService();
            report = rep;
        }


        private readonly IReport report;
        private readonly InputService inputService;
        private ICompareService comparer;

        private int[] missingIndexes;
        private int missCount;
        private string key;


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe bool MoveNext(int* items, int len)
        {
            for (int i = len - 1; i >= 0; --i)
            {
                items[i] += 1;

                if (items[i] == 16)
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

        private unsafe void SetResultParallel(int* items, int firstItem)
        {
            char[] origHex = key.ToCharArray();
            origHex[missingIndexes[0]] = GetHex(firstItem);
            for (int i = 0; i < missCount - 1; i++)
            {
                int index = missingIndexes[i + 1];
                origHex[index] = GetHex(items[i]);
            }

            report.AddMessageSafe($"Found the key: {new string(origHex)}");
            report.FoundAnyResult = true;
        }

        private unsafe void Loop(int firstItem, in PointJacobian smallPub, ParallelLoopState loopState)
        {
            var calc = new Calc();
            var missingItems = new int[missCount - 1];
            var localComp = comparer.Clone();

            Span<byte> temp = stackalloc byte[32];

            fixed (int* itemsPt = &missingItems[0])
            fixed (int* mi = &missingIndexes[0])
            fixed (byte* tmp = &temp[0])
            {
                int misIndex = mi[0];
                int firstIndex = misIndex / 2;
                byte firstValue = (misIndex % 2 == 0) ? (byte)(firstItem << 4) : (byte)firstItem;
                tmp[firstIndex] = firstValue;

                do
                {
                    if (loopState.IsStopped)
                    {
                        return;
                    }

                    int mis = 1;
                    foreach (var item in missingItems)
                    {
                        misIndex = mi[mis++];
                        if (misIndex % 2 == 0)
                        {
                            tmp[misIndex / 2] &= 0b0000_1111;
                            tmp[misIndex / 2] |= (byte)(item << 4);
                        }
                        else
                        {
                            tmp[misIndex / 2] &= 0b1111_0000;
                            tmp[misIndex / 2] |= (byte)item;
                        }
                    }

                    var tempVal = new Scalar(temp, out _);
                    PointJacobian tempPub = calc.MultiplyByG(in tempVal);
                    PointJacobian pub = tempPub.AddVariable(smallPub);

                    if (comparer.Compare(pub))
                    {
                        SetResultParallel(itemsPt, firstItem);
                        loopState.Stop();
                        return;
                    }

                } while (MoveNext(itemsPt, missingItems.Length));
            }

            report.IncrementProgress();
        }
        private unsafe void Loop(byte[] preComputed)
        {
            var calc = new Calc();
            var smallVal = new Scalar(preComputed, out _);
            PointJacobian smallPub = calc.MultiplyByG(smallVal);

            if (missCount == 1)
            {
                int misIndex = missingIndexes[0];
                int index = misIndex / 2;
                bool condition = misIndex % 2 == 0;

                Span<byte> temp = stackalloc byte[32];
                fixed (int* mi = &missingIndexes[0])
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

                        var tempVal = new Scalar(temp, out _);
                        PointJacobian tempPub = calc.MultiplyByG(tempVal);
                        PointJacobian pub = tempPub.AddVariable(smallPub);
                        if (comparer.Compare(pub))
                        {
                            char[] origHex = key.ToCharArray();
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
                report.AddMessageSafe("Running in parallel.");
                report.SetProgressStep(16);
                Parallel.For(0, 16, (firstItem, state) => Loop(firstItem, smallPub, state));
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

        public static bool IsInputValid(string key, char missingChar)
        {
            return !string.IsNullOrEmpty(key) &&
                    key.All(c => c == missingChar || ConstantsFO.Base16Chars.Contains(char.ToLower(c)));
        }

        public async void Find(string key, char missingChar, string AdditionalInput, InputType extraType)
        {
            report.Init();

            if (!inputService.IsMissingCharValid(missingChar))
                report.Fail("Missing character is not valid.");
            else if (!IsInputValid(key, missingChar))
                report.Fail("Input contains invalid base-16 character(s).");
            else if (key.Length != 64)
                report.Fail("Key length must be 64.");
            else if (!inputService.IsPrivateKeyInRange(Base16.Decode(key.Replace(missingChar, 'f'))))
                report.Fail("This is a problematic key to brute force, please open a new issue on GitHub for this case.");
            else if (!inputService.TryGetCompareService(extraType, AdditionalInput, out comparer))
                report.Fail($"Could not instantiate ICompareService (invalid {extraType}).");
            else
            {
                missCount = key.Count(c => c == missingChar);
                if (missCount == 0)
                {
                    try
                    {
                        using PrivateKey prv = new(Base16.Decode(key));
                        bool check = new AddressService().Compare(AdditionalInput, extraType, prv, out string msg);
                        if (check)
                        {
                            report.Pass(msg);
                        }
                        else
                        {
                            report.Fail(msg);
                        }
                        return;
                    }
                    catch (Exception ex)
                    {
                        report.Fail($"Key is out of range {ex.Message}");
                    }

                    report.Pass("The given key is valid.");
                    return;
                }

                this.key = key;

                var total = BigInteger.Pow(16, missCount);
                report.AddMessage($"The given key is missing {missCount} characters and there are {total:n0} keys to check.");
                Stopwatch watch = Stopwatch.StartNew();

                missingIndexes = new int[missCount];
                byte[] ba = new byte[32];
                for (int i = 0, j = 0; i < ba.Length; i++)
                {
                    int hi, lo;
                    if (key[i * 2] == missingChar)
                    {
                        hi = 0;
                        missingIndexes[j++] = i * 2;
                    }
                    else
                    {
                        hi = key[i * 2] - 65;
                        hi = hi + 10 + ((hi >> 31) & 7);
                    }
                    if (key[i * 2 + 1] == missingChar)
                    {
                        lo = 0;
                        missingIndexes[j++] = i * 2 + 1;
                    }
                    else
                    {
                        lo = key[i * 2 + 1] - 65;
                        lo = lo + 10 + ((lo >> 31) & 7) & 0x0f;
                    }

                    ba[i] = (byte)(lo | hi << 4);
                }

                await Task.Run(() => Loop(ba));

                watch.Stop();
                report.AddMessageSafe($"Elapsed time: {watch.Elapsed}");
                report.SetKeyPerSec(total, watch.Elapsed.TotalSeconds);

                report.Finalize();
            }
        }
    }
}
