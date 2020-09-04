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
    public class PrvToAddrNestedComparerTests
    {
        [Fact]
        public void CloneTest()
        {
            var original = new PrvToAddrNestedComparer();
            Assert.True(original.Init(KeyHelper.Pub1NestedSegwit)); // Make sure it is successfully initialized
            var cloned = original.Clone();
            // Change original field value to make sure it is cloned not a reference copy
            Assert.True(original.Init(KeyHelper.Pub2NestedSegwit));

            byte[] key = KeyHelper.Prv1.ToBytes();

            // Since the original was changed it should fail when comparing
            Assert.False(original.Compare(key));
            Assert.True(cloned.Compare(key));
        }

        public static IEnumerable<object[]> GetCompareCases()
        {
            yield return new object[] { KeyHelper.Pub1NestedSegwit, KeyHelper.Prv1.ToBytes() };
            yield return new object[] { KeyHelper.Pub2NestedSegwit, KeyHelper.Prv2.ToBytes() };
            yield return new object[] { KeyHelper.Pub3NestedSegwit, KeyHelper.Prv3.ToBytes() };
        }

        [Theory]
        [MemberData(nameof(GetCompareCases))]
        public void Compare_CompressedTest(string addr, byte[] key)
        {
            var comp = new PrvToAddrNestedComparer();
            Assert.True(comp.Init(addr));
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
            var comp = new PrvToAddrNestedComparer();
            Assert.True(comp.Init(KeyHelper.Pub1NestedSegwit));
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
