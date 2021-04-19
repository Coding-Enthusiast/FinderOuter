// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using FinderOuter.Backend.Cryptography.Hashing;
using FinderOuter.Backend.ECC;
using FinderOuter.Services.Comparers;
using System.Collections.Generic;
using Xunit;

namespace Tests.Services.Comparers
{
    public class PrvToPubComparerTests
    {
        public static IEnumerable<object[]> GetHashCases()
        {
            yield return new object[] { KeyHelper.Pub1CompHex, true };
            yield return new object[] { KeyHelper.Pub1UnCompHex, true };
            yield return new object[] { "040b3ad1cea48c61bdcff356675d92010290cdc2e04e1c9e68b6a01d3cec746c17", false };
            yield return new object[] { "0b3ad1cea48c61bdcff356675d92010290cdc2e04e1c9e68b6a01d3cec746c17", false };
            yield return new object[] { "FOO", false };
        }

        [Theory]
        [MemberData(nameof(GetHashCases))]
        public void InitTest(string pubHex, bool expected)
        {
            var comp = new PrvToPubComparer();
            bool actual = comp.Init(pubHex);
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void CloneTest()
        {
            var original = new PrvToPubComparer();
            Assert.True(original.Init(KeyHelper.Pub1CompHex)); // Make sure it is successfully initialized
            var cloned = original.Clone();
            // Change original field value to make sure it is cloned not a reference copy
            Assert.True(original.Init(KeyHelper.Pub2CompHex));

            byte[] key = KeyHelper.Prv1.ToBytes();

            // Since the original was changed it should fail when comparing
            Assert.False(original.Compare(key));
            Assert.True(cloned.Compare(key));
        }

        [Fact]
        public void CompareTest()
        {
            var comp1 = new PrvToPubComparer();
            var comp2 = new PrvToPubComparer();
            Assert.True(comp1.Init(KeyHelper.Pub1CompHex));
            Assert.True(comp2.Init(KeyHelper.Pub1UnCompHex));

            byte[] key = KeyHelper.Prv1.ToBytes();
            key[0]++;

            bool b1 = comp1.Compare(key);
            bool b2 = comp2.Compare(key);
            Assert.False(b1);
            Assert.False(b2);

            key[0]--;
            b1 = comp1.Compare(key);
            b2 = comp2.Compare(key);
            Assert.True(b1);
            Assert.True(b2);
        }

        [Fact]
        public unsafe void Compare_Sha256HashStateTest()
        {
            var comp = new PrvToPubComparer();
            using Sha256Fo sha = new();
            sha.ComputeHash(new byte[1]);
            fixed (uint* hPt = sha.hashState)
            {
                var key = new Scalar(hPt, out int overflow);
                Assert.Equal(0, overflow);
                var calc = new Calc();
                string pubHex = calc.GetPubkey(key, true).ToArray().ToBase16();
                bool b = comp.Init(pubHex);
                Assert.True(b);

                bool actual = comp.Compare(hPt);
                Assert.True(actual);
            }
        }

        [Fact]
        public unsafe void Compare_Sha512HashStateTest()
        {
            var comp = new PrvToPubComparer();
            using Sha512Fo sha = new();
            sha.ComputeHash(new byte[1]);
            fixed (ulong* hPt = sha.hashState)
            {
                var key = new Scalar(hPt, out int overflow);
                Assert.Equal(0, overflow);
                var calc = new Calc();
                string pubHex = calc.GetPubkey(key, true).ToArray().ToBase16();
                bool b = comp.Init(pubHex);
                Assert.True(b);

                bool actual = comp.Compare(hPt);
                Assert.True(actual);
            }
        }
    }
}
