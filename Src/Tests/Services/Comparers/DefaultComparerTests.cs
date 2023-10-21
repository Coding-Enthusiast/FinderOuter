// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.Cryptography.EllipticCurve;
using FinderOuter.Services.Comparers;

namespace Tests.Services.Comparers
{
    public class DefaultComparerTests
    {
        [Fact]
        public void InitTest()
        {
            DefaultComparer comp = new();
            Assert.True(comp.Init(""));
        }

        [Fact]
        public void CloneTest()
        {
            DefaultComparer original = new();
            ICompareService cloned = original.Clone();
            Assert.Same(cloned, original);
        }

        [Fact]
        public void CalcTest()
        {
            DefaultComparer comp = new();
            Assert.NotNull(comp.Calc);
        }

        [Fact]
        public void CompareTest()
        {
            DefaultComparer comp = new();
            Assert.True(comp.Compare(new byte[1]));
            Assert.True(comp.Compare(new PointJacobian()));
            Assert.True(comp.Compare(new Scalar8x32()));
            unsafe
            {
                uint[] arr32 = new uint[1];
                ulong[] arr64 = new ulong[1];
                fixed (uint* h32 = &arr32[0])
                fixed (ulong* h64 = &arr64[0])
                {
                    Assert.True(comp.Compare(h32));
                    Assert.True(comp.Compare(h64));
                }
            }
        }
    }
}
