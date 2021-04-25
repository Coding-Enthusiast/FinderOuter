// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend.ECC;
using FinderOuter.Services.Comparers;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace Tests.Services.Comparers
{
    public class PrvToPrvComparerTests
    {
        public static IEnumerable<object[]> GetHashCases()
        {
            yield return new object[] { KeyHelper.Prv1.ToWif(true), true };
            yield return new object[] { KeyHelper.Prv1.ToWif(false), true };
            yield return new object[] { KeyHelper.Prv1.ToWif(false) + "1", false };
            yield return new object[] { "FOO", false };
        }

        [Theory]
        [MemberData(nameof(GetHashCases))]
        public void InitTest(string wif, bool expected)
        {
            var comp = new PrvToPrvComparer();
            bool actual = comp.Init(wif);
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void CloneTest()
        {
            var original = new PrvToPrvComparer();
            Assert.True(original.Init(KeyHelper.Prv1.ToWif(true))); // Make sure it is successfully initialized
            var cloned = original.Clone();
            // Change original field value to make sure it is cloned not a reference copy
            Assert.True(original.Init(KeyHelper.Prv2.ToWif(true)));

            byte[] key = KeyHelper.Prv1.ToBytes();

            // Since the original was changed it should fail when comparing
            Assert.False(original.Compare(key));
            Assert.True(cloned.Compare(key));
        }

        [Fact]
        public void CompareTest()
        {
            var comp = new PrvToPrvComparer();
            Assert.True(comp.Init(KeyHelper.Prv1.ToWif(true)));
            byte[] key = KeyHelper.Prv1.ToBytes();
            key[0]++;

            bool b = comp.Compare(key);
            Assert.False(b);

            key[0]--;
            b = comp.Compare(key);
            Assert.True(b);
        }


        public static IEnumerable<object[]> GetCases()
        {
            var comp = new PrvToPrvComparer();
            Assert.True(comp.Init(KeyHelper.Prv1Wif));

            yield return new object[] { comp, KeyHelper.Prv1.ToBytes(), true };
            yield return new object[] { comp, KeyHelper.Prv2.ToBytes(), false };
        }

        [Theory]
        [MemberData(nameof(GetCases))]
        public unsafe void Compare_Sha256Hpt_Test(PrvToPrvComparer comp, byte[] key, bool expected)
        {
            uint* hPt = stackalloc uint[8];
            Helper.WriteToHpt(key, hPt);
            bool actual = comp.Compare(hPt);
            Assert.Equal(expected, actual);
        }

        [Theory]
        [MemberData(nameof(GetCases))]
        public unsafe void Compare_Sha512Hpt_Test(PrvToPrvComparer comp, byte[] key, bool expected)
        {
            ulong* hPt = stackalloc ulong[8];
            Helper.WriteToHpt32(key, hPt);
            bool actual = comp.Compare(hPt);
            Assert.Equal(expected, actual);
        }
    }
}
