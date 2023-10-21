// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend;
using FinderOuter.Models;
using FinderOuter.Services.SearchSpaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;

namespace Tests.Services.SearchSpaces
{
    public class B58SearchSpaceTests
    {
        private const string NoMiss = "L28Peud5cQcijrtMthAdUS8FynpM8PKZtnoUZb1VAio9WxKoebHt";
        private const string OneMiss = "L28Peud5cQcijrtMthAdUS8FynpM8PKZtnoUZb1VAio9WxKoe*Ht";
        private const string TwoMiss = "L28Pe*d5cQcij*tMthAdUS8FynpM8PKZtnoUZb1VAio9WxKoebHt";
        private static readonly int[] OneMissIndex = new int[] { 49 };
        private static readonly int[] OneMissIndexMult = new int[] { 20 };
        private static readonly int[] TwoMissIndex = new int[] { 13, 5 };
        private static readonly int[] TwoMissIndexMult = new int[] { 380, 460 };


        public static IEnumerable<object[]> GetShiftedMultCases()
        {
            for (int i = 0; i <= 24; i++)
            {
                yield return new object[] { 35, 7, i }; // Address
                yield return new object[] { 51, 10, i }; // Uncompressed WIF
                yield return new object[] { 52, 10, i }; // Compressed WIF
                yield return new object[] { 58, 11, i }; // BIP38
            }
        }
        [Theory]
        [MemberData(nameof(GetShiftedMultCases))]
        public void GetShiftedMultPow58Test(int maxPow, int uLen, int shift)
        {
            ulong[] shiftedPowers = B58SearchSpace.GetShiftedMultPow58(maxPow, uLen, shift);

            ulong mask = (1U << shift) - 1;
            int index = 0;
            for (int i = 0; i < 58; i++)
            {
                for (int j = 0; j < maxPow; j++)
                {
                    byte[] ba = new byte[4 * uLen];
                    for (int k = 0; k < ba.Length; k += 4, index++)
                    {
                        // Make sure values are shifted correctly
                        Assert.Equal(0U, shiftedPowers[index] & mask);
                        ulong val = shiftedPowers[index] >> shift;
                        // Make sure each unshifted value fits in a UInt32
                        Assert.True(val <= uint.MaxValue);

                        ba[k] = (byte)val;
                        ba[k + 1] = (byte)(val >> 8);
                        ba[k + 2] = (byte)(val >> 16);
                        ba[k + 3] = (byte)(val >> 24);
                    }

                    BigInteger actual = new(ba, true, false);
                    BigInteger expected = BigInteger.Pow(58, j) * i;
                    Assert.Equal(expected, actual);
                }
            }

            Assert.Equal(index, shiftedPowers.Length);
        }


        public static IEnumerable<object[]> GetProcessCases()
        {
            ulong[] compWIfMultPow = B58SearchSpace.GetShiftedMultPow58(ConstantsFO.PrivKeyCompWifLen, 10, 16);
            ulong[] uncompWifMultPow = B58SearchSpace.GetShiftedMultPow58(ConstantsFO.PrivKeyUncompWifLen, 10, 24);
            ulong[] addrMultPow = B58SearchSpace.GetShiftedMultPow58(34, 7, 24);
            ulong[] bipMultPow = B58SearchSpace.GetShiftedMultPow58(ConstantsFO.Bip38Base58Len, 11, 8);


            // Invalid inputs
            yield return new object[]
            {
                "a", 'z', Base58Type.Address, false, "Missing character is not accepted.", 0,
                false, null, null, null
            };
            yield return new object[]
            {
                string.Empty, '*', Base58Type.Address, false, "Input can not be null or empty.", 0,
                false, null, null, null
            };
            yield return new object[]
            {
                null, '*', Base58Type.Address, false, "Input can not be null or empty.", 0,
                false, null, null, null
            };
            yield return new object[]
            {
                " ", '*', Base58Type.Address, false, "Invalid character \" \" found at index=0.", 0,
                false, null, null, null
            };
            yield return new object[]
            {
                "0", '*', Base58Type.Address, false, "Invalid character \"0\" found at index=0.", 0,
                false, null, null, null
            };
            yield return new object[]
            {
                "a*AOB", '*', Base58Type.Address, false, "Invalid character \"O\" found at index=3.", 0,
                false, null, null, null
            };
            yield return new object[]
            {
                "a*", '*', (Base58Type)1000, false, "Given input type is not defined.", 1, false, null, null, null
            };

            // Process private keys:
            yield return new object[]
            {
                "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
                '*', Base58Type.PrivateKey, true, null,
                0, false, null, null, null
            };
            yield return new object[]
            {
                // Wrong key with no missing character (validation is postponed)
                "7HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
                '*', Base58Type.PrivateKey, true, null,
                0, false, null, null, null
            };
            yield return new object[]
            {
                "5HueCGU8*MjxEXxiPuD5BDku4MkFqeZyd4dZ*jvhTVqvbTLvy*",
                '*', Base58Type.PrivateKey, false, "Given key has an invalid length.",
                3, false, null, null, null
            };
            yield return new object[]
            {
                "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTL-yTJ",
                '-', Base58Type.PrivateKey, true, null,
                1, false, new int[] { 47 }, new int[] { 30 }, uncompWifMultPow
            };
            yield return new object[]
            {
                "K*dMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1*xJw*vP9861*",
                '*', Base58Type.PrivateKey, true, null,
                4, true, new int[] { 51, 44, 40, 1 }, new int[] { 0, 70, 110, 500 }, compWIfMultPow
            };

            // Process addresses:
            yield return new object[]
            {
                "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
                '*', Base58Type.Address, true, null,
                0, false, null, null, null
            };
            yield return new object[]
            {
                // Wrong address with no missing character (validation is postponed)
                "2BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
                '*', Base58Type.Address, true, null,
                0, false, null, null, null
            };
            yield return new object[]
            {
                "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN-",
                '-', Base58Type.Address, true, null,
                1, false, new int[] { 33 }, new int[] { 0 }, addrMultPow
            };
            yield return new object[]
            {
                "1-vBMSE-stWetqTFn5A-4m4GFg7xJ-NVN-",
                '-', Base58Type.Address, true, null,
                5, false, new int[5] { 33, 29, 19, 7, 1  }, new int[5] { 0, 28, 98, 182, 224 }, addrMultPow
            };
            yield return new object[]
            {
                "3J98t1WpEZ73C*mQviecrnyiWrnqRh*NLy",
                '*', Base58Type.Address, true, null,
                2, false, new int[2] { 30, 13 }, new int[2] { 21, 140 }, addrMultPow
            };

            // Process BIP38:
            yield return new object[]
            {
                "6PRWdmoT1ZursVcr5NiD14p5bHrKVGPG7yeEoEeRb8FVaqYSHnZTLEbYsU",
                '*', Base58Type.Bip38, true, null,
                0, false, null, null, null
            };
            yield return new object[]
            {
                "6PRWdmoT1ZursVcr5NiD14p5bHrKVGPG7yeEoEeRb8FVaqYSHn",
                '*', Base58Type.Bip38, true, null,
                0, false, null, null, null
            };
            yield return new object[]
            {
                "7PRWdmoT1ZursVcr5NiD14p5bHrKVGPG7yeEoEeRb8FVaqYSHnZTLEbYsU",
                '*', Base58Type.Bip38, true, null,
                0, false, null, null, null
            };
            yield return new object[]
            {
                "7PRWdmoT1ZursVcr5NiD14p5bHrKVGPG7yeEoEeRb8FVaqYSHnZTLEbYs*",
                '*', Base58Type.Bip38, false, "Base-58 encoded BIP-38 should start with 6P.",
                1, false, null, null, null
            };
            yield return new object[]
            {
                "6PRWdmoT1ZursVcr5NiD14p5bHrKVGPG7yeEoEeRb8FVaqYSHnZTLEbYs**",
                '*', Base58Type.Bip38, false, "Base-58 encoded BIP-38 length must have 58 characters.",
                2, false, null, null, null
            };
            yield return new object[]
            {
                "6PRWdmoT1ZursVcr5NiD14p5bHrKVGPG7yeEoEeRb8FVaqYSHnZTLEbYs*",
                '*', Base58Type.Bip38, true, null,
                1, false, new int[1] { 57 }, new int[1] { 0 }, bipMultPow
            };
            yield return new object[]
            {
                "6P*WdmoT1ZursVcr5N*D14p5bHrKVGPG**eEoEeRb8FVaq*SHnZTLEbY*U",
                '*', Base58Type.Bip38, true, null,
                6, false, new int[6] { 56, 46, 33, 32, 18, 2 }, new int[6] { 11, 121, 264, 275, 429, 605 }, bipMultPow
            };
        }
        [Theory]
        [MemberData(nameof(GetProcessCases))]
        public void ProcessTest(string input, char missChar, Base58Type t, bool expB, string expErr, int expMisCount,
                                bool isComp, int[] misIndex, int[] multMisIndex, ulong[] multPow58)
        {
            B58SearchSpace ss = new();
            bool actualB = ss.Process(input, missChar, t, out string actualErr);

            Assert.Equal(expB, actualB);
            Assert.Equal(expErr, actualErr);
            Assert.Equal(expMisCount, ss.MissCount);
            Assert.Equal(input, ss.Input);
            Assert.Equal(t, ss.inputType);
            if (expB)
            {
                Assert.Equal(isComp, ss.isComp);
                Assert.Equal(misIndex, ss.MissingIndexes);
                Assert.Equal(multMisIndex, ss.multMissingIndexes);
                Assert.Equal(multPow58, ss.multPow58);
            }
        }


        private static B58SearchSpace BuildSS(string s, int expMissCount, Base58Type t, bool processResult)
        {
            B58SearchSpace ss = new();
            bool b = ss.Process(s, '*', t, out _);
            Assert.Equal(expMissCount, ss.MissCount);
            Assert.Equal(processResult, b);

            return ss;
        }

        public static IEnumerable<object[]> GetProcessNoMissingCases()
        {
            yield return new object[]
            {
                new B58SearchSpace() { inputType = (Base58Type)1000 }, false, "Undefined input type."
            };
            yield return new object[]
            {
                BuildSS("5Hu*CGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ", 1, Base58Type.PrivateKey, true),
                false, "This method should not be called with missing characters."
            };

            yield return new object[]
            {
                BuildSS("L53fCHmQhbNp1B4JipfBtfeHZH7cAibzG9oK19XfiFzxHgAkz6Jk", 0, Base58Type.PrivateKey, true),
                false, "The given key has an invalid checksum."
            };
            yield return new object[]
            {
                BuildSS("L53fCHmQhbNp1B4JipfBtfeHZH7cAibzG9oK19XfiFzxHgAkz6JK", 0, Base58Type.PrivateKey, true),
                true, "The given key is a valid compressed private key."
            };

            yield return new object[]
            {
                BuildSS(InputServiceTests.ValidP2pkhAddr + "1", 0, Base58Type.Address, true),
                false, "The given address has an invalid checksum."
            };
            yield return new object[]
            {
                BuildSS(InputServiceTests.ValidP2pkhAddr, 0, Base58Type.Address, true),
                true, "The given address is a valid base-58 encoded address used for P2PKH scripts."
            };

            yield return new object[]
            {
                BuildSS("6PRWdmoT1ZursVcr5NiD14p5bHrKVGPG7yeEoEeRb8FVaqYSHnZTLEbYs1", 0, Base58Type.Bip38, true),
                false, "The given BIP-38 string has an invalid checksum."
            };
            yield return new object[]
            {
                BuildSS("6PRWdmoT1ZursVcr5NiD14p5bHrKVGPG7yeEoEeRb8FVaqYSHnZTLEbYsU", 0, Base58Type.Bip38, true),
                true, "The given BIP-38 string is valid."
            };
        }
        [Theory]
        [MemberData(nameof(GetProcessNoMissingCases))]
        public void ProcessNoMissingTest(B58SearchSpace ss, bool expected, string expMsg)
        {
            bool actual = ss.ProcessNoMissing(out string message);
            Assert.Equal(expected, actual);
            Assert.Contains(expMsg, message);
        }

        public static IEnumerable<object[]> GetSetValuesCases()
        {
            yield return new object[]
            {
                BuildSS(OneMiss, 1, Base58Type.PrivateKey, true),
                null, null,
                false, "Permutations list can not be null",
                OneMissIndex, OneMissIndexMult,
                null, Array.Empty<int>()
            };
            yield return new object[]
            {
                BuildSS(OneMiss, 1, Base58Type.PrivateKey, true),
                Array.Empty<string[]>(), Array.Empty<string[]>(),
                false, "Permutations list doesn't have the same number of arrays as missing characters count.",
                OneMissIndex, OneMissIndexMult,
                null, Array.Empty<int>()
            };
            yield return new object[]
            {
                BuildSS(OneMiss, 1, Base58Type.PrivateKey, true),
                new string[2][] { new string[] { "" }, new string[] { "" } },
                new string[2][] { new string[] { "" }, new string[] { "" } },
                false,
                "Permutations list doesn't have the same number of arrays as missing characters count.",
                OneMissIndex, OneMissIndexMult, null, Array.Empty<int>()
            };
            yield return new object[]
            {
                BuildSS(TwoMiss, 2, Base58Type.PrivateKey, true),
                new string[2][] { null, new string[2] { "a", "b" } },
                new string[2][] { null, new string[2] { "a", "b" } },
                false,
                "Search space values are not correctly set. Add at least 2 possible values for the 1st missing position.",
                TwoMissIndex, TwoMissIndexMult, null, Array.Empty<int>()
            };
            yield return new object[]
            {
                BuildSS(TwoMiss, 2, Base58Type.PrivateKey, true),
                new string[2][] { new string[1] { "a" }, new string[2] { "a", "b" } },
                new string[2][] { new string[1] { "a" }, new string[2] { "a", "b" } },
                false,
                "Search space values are not correctly set. Add at least 2 possible values for the 1st missing position.",
                TwoMissIndex, TwoMissIndexMult, null, Array.Empty<int>()
            };
            yield return new object[]
            {
                BuildSS(TwoMiss, 2, Base58Type.PrivateKey, true),
                new string[2][] { new string[2] { "a", "b" }, null },
                new string[2][] { new string[2] { "a", "b" }, null },
                false,
                "Search space values are not correctly set. Add at least 2 possible values for the 2nd missing position.",
                TwoMissIndex, TwoMissIndexMult, null, Array.Empty<int>()
            };
            yield return new object[]
            {
                BuildSS(TwoMiss, 2, Base58Type.PrivateKey, true),
                new string[2][] { new string[2] { "a", "b" }, new string[1] { "a" } },
                new string[2][] { new string[2] { "a", "b" }, new string[1] { "a" } },
                false,
                "Search space values are not correctly set. Add at least 2 possible values for the 2nd missing position.",
                TwoMissIndex, TwoMissIndexMult, null, Array.Empty<int>()
            };
            yield return new object[]
            {
                BuildSS(TwoMiss, 2, Base58Type.PrivateKey, true),
                new string[2][] { new string[2] { null, "b" }, new string[2] { "a", "b" } },
                new string[2][] { new string[2] { null, "b" }, new string[2] { "a", "b" } },
                false,
                "Given value () is not a valid character.",
                TwoMissIndex, TwoMissIndexMult, new uint[4], new int[2] {2, 0}
            };
            yield return new object[]
            {
                BuildSS(TwoMiss, 2, Base58Type.PrivateKey, true),
                new string[2][] { new string[2] { "b", null }, new string[2] { "a", "b" } },
                new string[2][] { new string[2] { "b", null }, new string[2] { "a", "b" } },
                false,
                "Given value () is not a valid character.",
                TwoMissIndex, TwoMissIndexMult, new uint[4] {34,0, 0,0}, new int[2] {2,0}
            };
            yield return new object[]
            {
                BuildSS(TwoMiss, 2, Base58Type.PrivateKey, true),
                new string[2][] { new string[2] { "1", "2" }, new string[2] { null, "b" } },
                new string[2][] { new string[2] { "1", "2" }, new string[2] { null, "b" } },
                false,
                "Given value () is not a valid character.",
                TwoMissIndex, TwoMissIndexMult, new uint[4] {0,1, 0,0}, new int[2] {2,2}
            };
            yield return new object[]
            {
                BuildSS(TwoMiss, 2, Base58Type.PrivateKey, true),
                new string[2][] { new string[2] { "1", "2" }, new string[2] { "b", null } },
                new string[2][] { new string[2] { "1", "2" }, new string[2] { "b", null } },
                false,
                "Given value () is not a valid character.",
                TwoMissIndex, TwoMissIndexMult, new uint[4] {0,1, 34,0}, new int[2] {2,2}
            };
            yield return new object[]
            {
                BuildSS(TwoMiss, 2, Base58Type.PrivateKey, true),
                new string[2][] { new string[2] { "11", "2" }, new string[2] { "b", "1" } },
                new string[2][] { new string[2] { "11", "2" }, new string[2] { "b", "1" } },
                false,
                "Given value (11) is not a valid character.",
                TwoMissIndex, TwoMissIndexMult, new uint[4] {0,0, 0,0}, new int[2] {2,0}
            };
            yield return new object[]
            {
                BuildSS(TwoMiss, 2, Base58Type.PrivateKey, true),
                new string[2][] { new string[2] { "1", "2" }, new string[2] { "abc", "1" } },
                new string[2][] { new string[2] { "1", "2" }, new string[2] { "abc", "1" } },
                false,
                "Given value (abc) is not a valid character.",
                TwoMissIndex, TwoMissIndexMult, new uint[4] {0,1, 0,0}, new int[2] {2,2}
            };
            yield return new object[]
            {
                BuildSS(TwoMiss, 2, Base58Type.PrivateKey, true),
                new string[2][] { new string[2] { "a", "O" }, new string[2] { "abc", "1" } },
                new string[2][] { new string[2] { "a", "O" }, new string[2] { "abc", "1" } },
                false,
                "Given character (O) is not found in the valid characters list.",
                TwoMissIndex, TwoMissIndexMult, new uint[4] {33,0, 0,0}, new int[2] {2,0}
            };

            // Valid lists:
            yield return new object[]
            {
                BuildSS(TwoMiss, 2, Base58Type.PrivateKey, true),
                new string[2][] { new string[2] { "5", "G" }, new string[2] { "h", "f" } },
                new string[2][] { new string[2] { "5", "G" }, new string[2] { "h", "f" } },
                true, string.Empty,
                TwoMissIndex, TwoMissIndexMult, new uint[4] {4,15, 40,38}, new int[2] {2,2}
            };
            // The first array is bigger => no swap
            yield return new object[]
            {
                BuildSS(TwoMiss, 2, Base58Type.PrivateKey, true),
                new string[2][] { new string[3] { "5", "N", "a" }, new string[2] { "h", "f" } },
                new string[2][] { new string[3] { "5", "N", "a" }, new string[2] { "h", "f" } },
                true, string.Empty,
                TwoMissIndex, TwoMissIndexMult, new uint[5] {4,21,33, 40,38}, new int[2] {3,2}
            };
            // The second array is bigger => swapped
            yield return new object[]
            {
                BuildSS(TwoMiss, 2, Base58Type.PrivateKey, true),
                new string[2][] { new string[2] { "5", "N" }, new string[4] { "9", "f", "r", "a" } },
                new string[2][] { new string[4] { "9", "f", "r", "a" }, new string[2] { "5", "N" } },
                true, string.Empty,
                TwoMissIndex.Reverse().ToArray(), TwoMissIndexMult.Reverse().ToArray(),
                new uint[6] {8,38,49,33, 4,21}, new int[2] {4,2}
            };
            yield return new object[]
            {
                BuildSS("5HueCGU8*MjxEXx*PuD5BDku4MkFqeZ*d4dZ1jvhTV*vbTLvyTJ", 4, Base58Type.PrivateKey, true),
                new string[4][]
                {
                    new string[3] { "K", "u", "1" },
                    new string[2] { "Y", "z" },
                    new string[4] { "V", "p", "5", "a" },
                    new string[3] { "M", "b", "4" }
                },
                new string[4][]
                {
                    new string[4] { "V", "p", "5", "a" },
                    new string[2] { "Y", "z" },
                    new string[3] { "K", "u", "1" },
                    new string[3] { "M", "b", "4" }
                },
                true, string.Empty,
                new int[4] {15,31,42,8},new int[4] {350,190,80,420},
                new uint[12] {28,47,4,33, 31,57, 18,52,0, 20,34,3}, new int[4] {4,2,3,3}
            };
        }
        [Theory]
        [MemberData(nameof(GetSetValuesCases))]
        public void SetValuesTest(B58SearchSpace ss, string[][] array, string[][] expArray, bool expected, string expMsg,
                                  int[] expMissIndex, int[] expMissIndexMult, uint[] expPermVals, int[] expPermCounts)
        {
            bool actual = ss.SetValues(array, out string error);

            Assert.Equal(expected, actual);
            Assert.Contains(expMsg, error);
            Assert.Equal(expArray, array);
            Assert.Equal(expMissIndex, ss.MissingIndexes);
            Assert.Equal(expMissIndexMult, ss.multMissingIndexes);
            Assert.Equal(expPermVals, ss.AllPermutationValues);
            Assert.Equal(expPermCounts, ss.PermutationCounts);
        }
    }
}
