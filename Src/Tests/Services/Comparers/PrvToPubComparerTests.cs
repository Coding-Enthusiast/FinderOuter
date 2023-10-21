// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using Autarkysoft.Bitcoin.Cryptography.EllipticCurve;
using FinderOuter.Backend.Hashing;
using FinderOuter.Services.Comparers;
using System.Collections.Generic;

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
            PrvToPubComparer comp = new();
            bool actual = comp.Init(pubHex);
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void CloneTest()
        {
            PrvToPubComparer original = new();
            Assert.True(original.Init(KeyHelper.Pub1CompHex)); // Make sure it is successfully initialized
            ICompareService cloned = original.Clone();
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
            PrvToPubComparer comp1 = new();
            PrvToPubComparer comp2 = new();
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
            PrvToPubComparer comp = new();
            uint* pt = stackalloc uint[Sha256Fo.UBufferSize];
            byte[] data = new byte[1];
            fixed (byte* dPt = &data[0])
            {
                Sha256Fo.CompressData(dPt, data.Length, data.Length, pt);

                Scalar8x32 key = new(pt, out bool overflow);
                Assert.False(overflow);
                Calc calc = new();
                string pubHex = calc.GetPubkey(key, true).ToArray().ToBase16();

                bool b = comp.Init(pubHex);
                Assert.True(b);

                bool actual = comp.Compare(pt);
                Assert.True(actual);
            }
        }

        [Fact]
        public unsafe void Compare_Sha512HashStateTest()
        {
            PrvToPubComparer comp = new();
            byte[] data = new byte[] { 1, 2, 3 };
            ulong* hPt = stackalloc ulong[Sha512Fo.UBufferSize];
            ulong* wPt = hPt + Sha512Fo.HashStateSize;
            fixed (byte* dPt = data)
            {
                // Get hashstate ready first
                Sha512Fo.CompressData(dPt, data.Length, data.Length, hPt, wPt);

                Scalar8x32 key = new(hPt, out bool overflow);
                Assert.False(overflow);
                Calc calc = new();
                string pubHex = calc.GetPubkey(key, true).ToArray().ToBase16();
                bool b = comp.Init(pubHex);
                Assert.True(b);

                bool actual = comp.Compare(hPt);
                Assert.True(actual);
            }
        }


        public static IEnumerable<object[]> GetCases()
        {
            PrvToPubComparer comp = new();
            Assert.True(comp.Init(KeyHelper.Pub1CompHex));

            yield return new object[] { comp, KeyHelper.Prv1.ToBytes(), true };
            yield return new object[] { comp, KeyHelper.Prv2.ToBytes(), false };
        }

        [Theory]
        [MemberData(nameof(GetCases))]
        public unsafe void Compare_Sha256Hpt_Test(PrvToPubComparer comp, byte[] key, bool expected)
        {
            uint* hPt = stackalloc uint[8];
            Helper.WriteToHpt(key, hPt);
            bool actual = comp.Compare(hPt);
            Assert.Equal(expected, actual);
        }

        [Theory]
        [MemberData(nameof(GetCases))]
        public unsafe void Compare_Sha512Hpt_Test(PrvToPubComparer comp, byte[] key, bool expected)
        {
            ulong* hPt = stackalloc ulong[8];
            Helper.WriteToHpt32(key, hPt);
            bool actual = comp.Compare(hPt);
            Assert.Equal(expected, actual);
        }
    }
}
