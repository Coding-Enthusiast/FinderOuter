// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.Cryptography.Asymmetric.EllipticCurve;
using FinderOuter.Services.Comparers;
using System;
using System.Collections.Generic;
using Xunit;

namespace Tests.Services.Comparers
{
    public class PrvToAddrBothComparerTests
    {
        public static IEnumerable<object[]> GetHashCases()
        {
            yield return new object[] { KeyHelper.Pub1CompAddr, true };
            yield return new object[] { KeyHelper.Pub1CompAddr + "1", false };
            yield return new object[] { KeyHelper.Pub1NestedSegwit, true };
            yield return new object[] { KeyHelper.Pub1NestedSegwit + "1", false };
            yield return new object[] { KeyHelper.Pub1BechAddr, true };
            yield return new object[] { KeyHelper.Pub1BechAddr + "a", false };

            yield return new object[] { "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", false };
        }

        [Theory]
        [MemberData(nameof(GetHashCases))]
        public void InitTest(string addr, bool expected)
        {
            var comp = new PrvToAddrBothComparer();
            bool actual = comp.Init(addr);
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void CompareTest()
        {
            var comp = new PrvToAddrBothComparer();
            Assert.True(comp.Init(KeyHelper.Pub1CompAddr));
            byte[] key = KeyHelper.Prv1.ToBytes();
            key[0]++;
            
            bool b = comp.Compare(key);
            Assert.False(b);

            key[0]--;
            b = comp.Compare(key);
            Assert.True(b);
        }

        [Fact]
        public void Compare_EdgeTest()
        {
            var comp = new PrvToAddrBothComparer();
            Assert.True(comp.Init(KeyHelper.Pub1CompAddr));
            byte[] key = new byte[32];
            bool b = comp.Compare(key);
            Assert.False(b);

            ((Span<byte>)key).Fill(255);
            b = comp.Compare(key);
            Assert.False(b);

            key = new SecP256k1().N.ToByteArray(true, true);
            b = comp.Compare(key);
            Assert.False(b);
        }
    }
}
