// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.Cryptography.Asymmetric.EllipticCurve;
using Autarkysoft.Bitcoin.Encoders;
using FinderOuter.Backend;
using FinderOuter.Backend.Cryptography.Asymmetric.EllipticCurve;
using FinderOuter.Models;
using FinderOuter.Services.Comparers;
using System;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
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


        private unsafe void LoopComp(string key, int missingCount, char missingChar)
        {
            int[] missingIndexes = new int[missingCount];
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

            var cartesian = CartesianProduct.Create(Enumerable.Repeat(Enumerable.Range(0, 16), missingCount));
            ECCalc calc = new ECCalc();


            BigInteger smallVal = new BigInteger(ba, true, true);
            EllipticCurvePoint smallPub = calc.MultiplyByG(smallVal);

            Parallel.ForEach(cartesian, (item, loopState) =>
            {
                Span<byte> temp = new byte[32];

                int mis = 0;
                foreach (int keyItem in item)
                {
                    int misIndex = missingIndexes[mis];
                    if (misIndex % 2 == 0)
                    {
                        temp[misIndex / 2] |= (byte)(keyItem << 4);
                    }
                    else
                    {
                        temp[misIndex / 2] |= (byte)keyItem;
                    }
                    mis++;
                }

                BigInteger tempVal = new BigInteger(temp, true, true);
                EllipticCurvePoint tempPub = calc.MultiplyByG(tempVal);
                EllipticCurvePoint pub = calc.AddChecked(tempPub, smallPub);
                if (comparer.Compare(pub))
                {
                    char[] origHex = key.ToCharArray();
                    int index = 0;
                    foreach (var keyItem in item)
                    {
                        origHex[missingIndexes[index++]] = GetHex(keyItem);
                    }
                    report.AddMessageSafe($"Found the key: {new string(origHex)}");
                    report.FoundAnyResult = true;
                    loopState.Stop();
                    return;
                }
            });
        }

        private char GetHex(int val)
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

        public bool IsInputValid(string key, char missingChar)
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
                report.Fail("Could not instantiate ICompareService.");
            else
            {
                int missingCount = key.Count(c => c == missingChar);
                if (missingCount == 0)
                {
                    report.Fail("The given key has no missing characters and it is inside the range defined by secp256k1 curve.");
                    return;
                }

                BigInteger total = BigInteger.Pow(16, missingCount);
                report.AddMessage($"There are {total:n0} keys to check.");
                Stopwatch watch = Stopwatch.StartNew();

                await Task.Run(() => LoopComp(key, missingCount, missingChar));

                watch.Stop();
                report.AddMessageSafe($"Elapsed time: {watch.Elapsed}");
                report.SetKeyPerSec(total, watch.Elapsed.TotalSeconds);

                report.Finalize();
            }
        }
    }
}
