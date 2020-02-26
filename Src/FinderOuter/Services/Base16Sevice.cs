// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend;
using FinderOuter.Backend.Encoders;
using FinderOuter.Models;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using System.Threading.Tasks;
using System;
using FinderOuter.Backend.Cryptography.Asymmetric.EllipticCurve;
using System.Collections.Generic;
using FinderOuter.Backend.Cryptography.Hashing;

namespace FinderOuter.Services
{
    public class Base16Sevice : ServiceBase
    {
        public Base16Sevice(Report rep) : base(rep)
        {
            inputService = new InputService();
        }



        private readonly InputService inputService;


        private unsafe bool LoopComp(string key, int missingCount, char missingChar, byte[] expectedHash)
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
                if (key[i * 2 + 1] == '*')
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
            EllipticCurveCalculator calc = new EllipticCurveCalculator();

            

            BigInteger smallVal = new BigInteger(ba, true, true);
            EllipticCurvePoint smallPub = calc.MultiplyByG(smallVal);
            Ripemd160Sha256 hash = new Ripemd160Sha256();

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
                byte[] toHash = new byte[33];
                toHash[0] = pub.Y.IsEven ? (byte)2 : (byte)3;
                byte[] xBytes = pub.X.ToByteArray(true, true);
                Buffer.BlockCopy(xBytes, 0, toHash, 33 - xBytes.Length, xBytes.Length);

                ReadOnlySpan<byte> actual = hash.ComputeHash(toHash);
                if (actual.SequenceEqual(expectedHash))
                {
                    char[] origHex = key.ToCharArray();
                    int index = 0;
                    foreach (var keyItem in item)
                    {
                        origHex[missingIndexes[index++]] = GetHex(keyItem);
                    }
                    AddQueue($"Found a key: {new string(origHex)}");
                    loopState.Break();
                }
            });


            AddQueue("Failed to find any key.");
            return false;
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

        public bool IsMissingCharValid(char c) => Constants.Symbols.Contains(c);
        public bool IsInputValid(string key, char missingChar)
        {
            return !string.IsNullOrEmpty(key) && key.All(c => c == missingChar || Constants.Base16Chars.Contains(char.ToLower(c)));
        }

        public async Task<bool> Find(string key, char missingChar, string AdditionalInput, bool isComp)
        {
            InitReport();

            if (!IsMissingCharValid(missingChar))
                return Fail("Missing character is not valid.");
            if (!IsInputValid(key, missingChar))
                return Fail("Input contains invalid base-16 character(s).");
            if (key.Length != 64)
                return Fail("Key length must be 64.");
            if (!inputService.IsPrivateKeyInRange(Base16.ToByteArray(key.Replace(missingChar, 'f'))))
                return Fail("This is a problematic key to brute force, please open a new issue on GitHub for this case.");
            if (!inputService.IsValidAddress(AdditionalInput, true, out byte[] hash))
                return Fail("Input is not a valid address.");
            int missingCount = key.Count(c => c == missingChar);
            if (missingCount == 0)
                return Pass("The given key has no missing characters and it is inside the range defined by secp256k1 curve.");

            BigInteger total = BigInteger.Pow(16, missingCount);
            AddMessage($"There are {total:n0} keys to check.");
            Stopwatch watch = Stopwatch.StartNew();

            bool success = await Task.Run(() =>
            {
                if (isComp)
                {
                    AddQueue("Running compressed loop.");
                    return LoopComp(key, missingCount, missingChar, hash);
                }
                else
                {
                    AddQueue("Not yet defined.");
                    return false;
                }
            }
            );

            watch.Stop();
            AddQueue($"Elapsed time: {watch.Elapsed}");
            AddQueue(GetKeyPerSec(total, watch.Elapsed.TotalSeconds));

            return CopyQueueToMessage(success);
        }
    }
}
