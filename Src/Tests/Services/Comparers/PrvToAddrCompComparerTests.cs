// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.Cryptography.EllipticCurve;
using FinderOuter.Services.Comparers;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Tests.Services.Comparers
{
    public class PrvToAddrCompComparerTests
    {
        [Fact]
        public void CloneTest()
        {
            PrvToAddrCompComparer original = new();
            Assert.True(original.Init(KeyHelper.Pub1CompAddr)); // Make sure it is successfully initialized
            ICompareService cloned = original.Clone();
            // Change original field value to make sure it is cloned not a reference copy
            Assert.True(original.Init(KeyHelper.Pub2CompAddr));

            byte[] key = KeyHelper.Prv1.ToBytes();

            // Since the original was changed it should fail when comparing
            Assert.False(original.Compare(key));
            Assert.True(cloned.Compare(key));
        }

        [Fact]
        public void Compare_CompressedTest()
        {
            PrvToAddrCompComparer comp = new();
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
        public void Compare_UncompressedTest()
        {
            PrvToAddrCompComparer comp = new();
            Assert.True(comp.Init(KeyHelper.Pub1UnCompAddr));
            byte[] key = KeyHelper.Prv1.ToBytes();
            key[0]++;

            bool b = comp.Compare(key);
            Assert.False(b);

            key[0]--;
            b = comp.Compare(key);
            Assert.False(b); // False since Init() was from uncomp. address
        }

        [Fact]
        public void Compare_EdgeTest()
        {
            PrvToAddrCompComparer comp = new();
            Assert.True(comp.Init(KeyHelper.Pub1CompAddr));
            byte[] key = new byte[32];
            bool b = comp.Compare(key);
            Assert.False(b);

            ((Span<byte>)key).Fill(255);
            b = comp.Compare(key);
            Assert.False(b);

            key = KeyHelper.CurveOrder;
            b = comp.Compare(key);
            Assert.False(b);
        }


        public static IEnumerable<object[]> GetCases()
        {
            PrvToAddrCompComparer comp = new();
            Assert.True(comp.Init(KeyHelper.Pub1CompAddr));

            yield return new object[] { comp, new byte[32], false };
            yield return new object[] { comp, Enumerable.Repeat((byte)255, 32).ToArray(), false };
            yield return new object[] { comp, KeyHelper.Prv1.ToBytes(), true };
            yield return new object[] { comp, KeyHelper.Prv2.ToBytes(), false };
        }

        [Theory]
        [MemberData(nameof(GetCases))]
        public unsafe void Compare_Sha256Hpt_Test(PrvToAddrCompComparer comp, byte[] key, bool expected)
        {
            uint* hPt = stackalloc uint[8];
            Helper.WriteToHpt(key, hPt);
            bool actual = comp.Compare(hPt);
            Assert.Equal(expected, actual);
        }

        [Theory]
        [MemberData(nameof(GetCases))]
        public unsafe void Compare_Sha512Hpt_Test(PrvToAddrCompComparer comp, byte[] key, bool expected)
        {
            ulong* hPt = stackalloc ulong[8];
            Helper.WriteToHpt32(key, hPt);
            bool actual = comp.Compare(hPt);
            Assert.Equal(expected, actual);
        }

        [Theory]
        [MemberData(nameof(GetCases))]
        public unsafe void Compare_PointJ_Test(PrvToAddrCompComparer comp, byte[] key, bool expected)
        {
            Scalar8x32 sc = new(key, out bool overflow);
            if (!overflow && !sc.IsZero)
            {
                PointJacobian point = Helper.Calc.MultiplyByG(sc);
                bool actual = comp.Compare(point);
                Assert.Equal(expected, actual);
            }
        }
    }
}
