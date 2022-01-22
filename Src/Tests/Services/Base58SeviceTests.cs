// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Services;
using System.Collections.Generic;
using System.Numerics;
using Xunit;

namespace Tests.Services
{
    public class Base58SeviceTests
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
            ulong[] shiftedPowers = Base58Service.GetShiftedMultPow58(maxPow, uLen, shift);

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
    }
}
