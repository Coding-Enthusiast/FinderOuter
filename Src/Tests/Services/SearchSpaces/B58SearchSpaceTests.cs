// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend;
using FinderOuter.Models;
using FinderOuter.Services.SearchSpaces;
using System.Collections.Generic;
using System.Numerics;
using Xunit;

namespace Tests.Services.SearchSpaces
{
    public class B58SearchSpaceTests
    {
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
                false, null, null, null, null
            };
            yield return new object[]
            {
                string.Empty, '*', Base58Type.Address, false, "Input can not be null or empty.", 0,
                false, null, null, null, null
            };
            yield return new object[]
            {
                null, '*', Base58Type.Address, false, "Input can not be null or empty.", 0,
                false, null, null, null, null
            };
            yield return new object[]
            {
                " ", '*', Base58Type.Address, false, "Invalid character \" \" found at index=0.", 0,
                false, null, null, null, null
            };
            yield return new object[]
            {
                "0", '*', Base58Type.Address, false, "Invalid character \"0\" found at index=0.", 0,
                false, null, null, null, null
            };
            yield return new object[]
            {
                "a*AOB", '*', Base58Type.Address, false, "Invalid character \"O\" found at index=3.", 0,
                false, null, null, null, null
            };
            yield return new object[]
            {
                "a*", '*', (Base58Type)1000, false, "Given input type is not defined.", 1, false, null, null, null, null
            };

            // Process private keys:
            yield return new object[]
            {
                "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
                '*', Base58Type.PrivateKey, true, null,
                0, false, null, null, null, null
            };
            yield return new object[]
            {
                // Wrong key with no missing character (validation is postponed)
                "7HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
                '*', Base58Type.PrivateKey, true, null,
                0, false, null, null, null, null
            };
            yield return new object[]
            {
                "5HueCGU8*MjxEXxiPuD5BDku4MkFqeZyd4dZ*jvhTVqvbTLvy*",
                '*', Base58Type.PrivateKey, false, "Given key has an invalid length.",
                3, false, null, null, null, null
            };
            //yield return new object[]
            //{
            //    "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTL-yTJ",
            //    '-', Base58Type.PrivateKey, true, null,
            //    1, false, new int[] { 47 }, new int[] { 30 }, uncompWifMultPow, null
            //};
            //yield return new object[]
            //{
            //    "K*dMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1*xJw*vP9861*",
            //    '*', Base58Type.PrivateKey, true, null,
            //    4, true, new int[] { 51, 44, 40, 1 }, new int[] { 0, 70, 110, 500 }, compWIfMultPow, null
            //};



            //// Process addresses:
            //yield return new object[]
            //{
            //    "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
            //    '*', Base58Type.Address, true, null,
            //    0, false, null, null, null, null
            //};
            //yield return new object[]
            //{
            //    "2BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
            //    '*', Base58Type.Address, false, "The given address has an invalid first character.",
            //    0, false, null, null, null, null
            //};
            //yield return new object[]
            //{
            //    "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN-",
            //    '-', Base58Type.Address, true, null,
            //    1, false, new int[] { 33 }, new int[] { 0 }, addrMultPow, null
            //};
            //yield return new object[]
            //{
            //    "1-vBMSE-stWetqTFn5A-4m4GFg7xJ-NVN-",
            //    '-', Base58Type.Address, true, null,
            //    5, false, new int[5] { 33, 29, 19, 7, 1  }, new int[5] { 0, 28, 98, 182, 224 }, addrMultPow, null
            //};
            //yield return new object[]
            //{
            //    "3J98t1WpEZ73C*mQviecrnyiWrnqRh*NLy",
            //    '*', Base58Type.Address, true, null,
            //    2, false, new int[2] { 30, 13 }, new int[2] { 21, 140 }, addrMultPow, null
            //};

            //// Process BIP38:
            //yield return new object[]
            //{
            //    "6PRWdmoT1ZursVcr5NiD14p5bHrKVGPG7yeEoEeRb8FVaqYSHnZTLEbYsU",
            //    '*', Base58Type.Bip38, true, null,
            //    0, false, null, null, null, null
            //};
            //yield return new object[]
            //{
            //    "6PRWdmoT1ZursVcr5NiD14p5bHrKVGPG7yeEoEeRb8FVaqYSHn",
            //    '*', Base58Type.Bip38, true, null,
            //    0, false, null, null, null, null
            //};
            //yield return new object[]
            //{
            //    "7PRWdmoT1ZursVcr5NiD14p5bHrKVGPG7yeEoEeRb8FVaqYSHnZTLEbYsU",
            //    '*', Base58Type.Bip38, true, null,
            //    0, false, null, null, null, null
            //};
            //yield return new object[]
            //{
            //    "7PRWdmoT1ZursVcr5NiD14p5bHrKVGPG7yeEoEeRb8FVaqYSHnZTLEbYs*",
            //    '*', Base58Type.Bip38, false, "Base-58 encoded BIP-38 should start with 6P.",
            //    1, false, null, null, null, null
            //};
            //yield return new object[]
            //{
            //    "6PRWdmoT1ZursVcr5NiD14p5bHrKVGPG7yeEoEeRb8FVaqYSHnZTLEbYs**",
            //    '*', Base58Type.Bip38, false, "Base-58 encoded BIP-38 length must have 58 characters.",
            //    2, false, null, null, null, null
            //};
            //yield return new object[]
            //{
            //    "6PRWdmoT1ZursVcr5NiD14p5bHrKVGPG7yeEoEeRb8FVaqYSHnZTLEbYs*",
            //    '*', Base58Type.Bip38, true, null,
            //    1, false, new int[1] { 57 }, new int[1] { 0 }, bipMultPow, null
            //};
            //yield return new object[]
            //{
            //    "6P*WdmoT1ZursVcr5N*D14p5bHrKVGPG**eEoEeRb8FVaq*SHnZTLEbY*U",
            //    '*', Base58Type.Bip38, true, null,
            //    6, false, new int[6] { 56, 46, 33, 32, 18, 2 }, new int[6] { 11, 121, 264, 275, 429, 605 }, bipMultPow, null
            //};
        }
        [Theory]
        [MemberData(nameof(GetProcessCases))]
        public void ProcessTest(string input, char missChar, Base58Type t, bool expB, string expErr, int expMisCount,
                                bool isComp, int[] misIndex, int[] multMisIndex, ulong[] multPow58, ulong[] expPre)
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
                Assert.Equal(expPre, ss.preComputed);
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
                BuildSS("5Hu*CGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ", 1, Base58Type.PrivateKey, true),
                false, "This method should not be called with missing characters."
            };
            // L53fCHmQhbNp1B4JipfBtfeHZH7cAibzG9oK19XfiFzxHgAkz6JK
            // KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617
        }
        [Theory]
        [MemberData(nameof(GetProcessNoMissingCases))]
        public void ProcessNoMissingTest(B58SearchSpace ss, bool expected, string expMsg)
        {
            bool actual = ss.ProcessNoMissing(out string message);
            Assert.Equal(expected, actual);
            Assert.Contains(expMsg, message);
        }
    }
}
