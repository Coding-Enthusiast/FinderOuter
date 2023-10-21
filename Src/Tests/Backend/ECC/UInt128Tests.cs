// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend.ECC;

namespace Tests.Backend.ECC
{
    public class UInt128Tests
    {
        private const ulong U0 = 0x3973e022e93220f9U;
        private const ulong U1 = 0x212c18d0d0c543aeU;


        [Theory]
        [InlineData(0, 0)]
        [InlineData(U0, U1)]
        public void Constructor_FromUlongTest(ulong u0, ulong u1)
        {
            UInt128 val = new(u0, u1);

            Assert.Equal(u0, val.b0);
            Assert.Equal(u1, val.b1);
        }

        [Theory]
        [InlineData(0, 0, 0, 0, 0, 0)]
        [InlineData(0xe93220f9, 0x3973e022, 0xd0c543ae, 0x212c18d0, U0, U1)]
        public void Constructor_FromUintTest(uint u0, uint u1, uint u2, uint u3, ulong exp0, ulong exp1)
        {
            UInt128 val = new(u0, u1, u2, u3);

            Assert.Equal(exp0, val.b0);
            Assert.Equal(exp1, val.b1);
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(int.MaxValue)]
        public void Constructor_FromIntTest(int i)
        {
            UInt128 val = new(i);

            Assert.Equal((ulong)i, val.b0);
            Assert.Equal(0U, val.b1);
        }

        [Theory]
        [InlineData(0, 0, true)]
        [InlineData(0, 1, true)]
        [InlineData(1, 0, false)]
        [InlineData(1, 1, false)]
        [InlineData(0x3973e022e93220f9U, 0x212c18d0d0c543aeU, false)]
        [InlineData(0x3973e022e93220feU, 0x212c18d0d0c543aeU, true)]
        public void IsEvenTest(ulong u0, ulong u1, bool expected)
        {
            UInt128 val = new(u0, u1);
            Assert.Equal(expected, val.IsEven);
        }

        [Theory]
        [InlineData(1, 0, true)]
        [InlineData(0, 0, false)]
        [InlineData(0, 1, false)]
        [InlineData(1, 1, false)]
        [InlineData(U0, U1, false)]
        public void IsOneTest(ulong u0, ulong u1, bool expected)
        {
            UInt128 val = new(u0, u1);
            Assert.Equal(expected, val.IsOne);
        }

        [Theory]
        [InlineData(0, 0, true)]
        [InlineData(0, 1, false)]
        [InlineData(1, 0, false)]
        [InlineData(1, 1, false)]
        [InlineData(U0, U1, false)]
        public void IsZeroTest(ulong u0, ulong u1, bool expected)
        {
            UInt128 val = new(u0, u1);
            Assert.Equal(expected, val.IsZero);
        }

        [Theory]
        [InlineData(0, 0, 0, 0)]
        [InlineData(ulong.MaxValue, 0, 0, 0)]
        [InlineData(ulong.MaxValue, 1, ulong.MaxValue, 0)]
        [InlineData(ulong.MaxValue, ulong.MaxValue, 0x0000000000000001, 0xfffffffffffffffe)]
        [InlineData(0x4e6ca1245be885b5, 0x9ee5d871da3da389, 0x920708233ab2ccdd, 0x30ad74ef1f04eb52)]
        public void MultiplyTest(ulong x, ulong y, ulong exp0, ulong exp1)
        {
            UInt128 actual1 = UInt128.Multiply(x, y);
            UInt128 actual2 = (UInt128)x * y;

            Assert.Equal(exp0, actual1.b0);
            Assert.Equal(exp1, actual1.b1);
            Assert.Equal(exp0, actual2.b0);
            Assert.Equal(exp1, actual2.b1);
        }

        [Theory]
        [InlineData(0, 0, 0, 0, 0, 0)]
        [InlineData(0xffffffffffffffff, 0xffffffffffffffff, 0, 0, 0xffffffffffffffff, 0xffffffffffffffff)]
        [InlineData(0xffffffffffffffff, 0xffffffffffffffff, 0, 1, 0xffffffffffffffff, 0)]
        [InlineData(0xffffffffffffffff, 0xffffffffffffffff, 1, 0, 0, 0)]
        [InlineData(0xffffffffffffffff, 0xffffffffffffffff, 1, 1, 0, 1)]
        [InlineData(0xa710a29d7acba2b4, 0x899ae0c37587cec6, 0x2209c4f3765f1521, 0xea2ab9569ddcaf4d, 0xc91a6790f12ab7d5, 0x73c59a1a13647e13)]
        public void AddOperatorTest(ulong u0, ulong u1, ulong u2, ulong u3, ulong exp0, ulong exp1)
        {
            UInt128 a = new(u0, u1);
            UInt128 b = new(u2, u3);

            UInt128 actual1 = a + b;
            UInt128 actual2 = b + a;

            Assert.Equal(exp0, actual1.b0);
            Assert.Equal(exp1, actual1.b1);
            Assert.Equal(exp0, actual2.b0);
            Assert.Equal(exp1, actual2.b1);
        }

        [Theory]
        [InlineData(0, 0, 0, 0, 0)]
        [InlineData(0xffffffffffffffff, 0xffffffffffffffff, 0, 0xffffffffffffffff, 0xffffffffffffffff)]
        [InlineData(0xffffffffffffffff, 0xffffffffffffffff, 1, 0, 0)]
        [InlineData(0xd1261e5aab453c99, 0x455ddcd5d00be15d, 0x9eab5f34988702de, 0x6fd17d8f43cc3f77, 0x455ddcd5d00be15e)]
        public void AddOperator_WithUlongTest(ulong u0, ulong u1, ulong u2, ulong exp0, ulong exp1)
        {
            UInt128 a = new(u0, u1);
            UInt128 actual1 = a + u2;
            UInt128 actual2 = u2 + a;

            Assert.Equal(exp0, actual1.b0);
            Assert.Equal(exp1, actual1.b1);
            Assert.Equal(exp0, actual2.b0);
            Assert.Equal(exp1, actual2.b1);
        }

        [Theory]
        [InlineData(0, 0, 0, 0, 0, 0)]
        [InlineData(0xffffffffffffffff, 0xffffffffffffffff, 0, 0, 0, 0)]
        [InlineData(0xffffffffffffffff, 0xffffffffffffffff, 1, 0, 0xffffffffffffffff, 0xffffffffffffffff)]
        [InlineData(0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 1, 0)]
        [InlineData(0x4423f49f115b79a6, 0xc5fdadb6442971e2, 0x45079f64b6460f7d, 0xe694388ec1816dd8, 0x048d2a071d2f200e, 0x2edecd6643dadc7c)]
        public void MultiplyOperatorTest(ulong u0, ulong u1, ulong u2, ulong u3, ulong exp0, ulong exp1)
        {
            UInt128 a = new(u0, u1);
            UInt128 b = new(u2, u3);

            UInt128 actual1 = a * b;
            UInt128 actual2 = b * a;

            Assert.Equal(exp0, actual1.b0);
            Assert.Equal(exp1, actual1.b1);
            Assert.Equal(exp0, actual2.b0);
            Assert.Equal(exp1, actual2.b1);
        }

        [Theory]
        [InlineData(0, 0, 0, 0, 0)]
        [InlineData(0xffffffffffffffff, 0xffffffffffffffff, 0, 0, 0)]
        [InlineData(0xffffffffffffffff, 0xffffffffffffffff, 1, 0xffffffffffffffff, 0xffffffffffffffff)]
        [InlineData(0x74564d5e8ed78e15, 0x09149c6071fed110, 0xeec64b6f4c1b8459, 0xad9b788c066a394d, 0xfc6e73256eae2f6f)]
        public void MultiplyOperator_WithUlongTest(ulong u0, ulong u1, ulong u2, ulong exp0, ulong exp1)
        {
            UInt128 a = new(u0, u1);
            UInt128 actual1 = a * u2;
            UInt128 actual2 = u2 * a;

            Assert.Equal(exp0, actual1.b0);
            Assert.Equal(exp1, actual1.b1);
            Assert.Equal(exp0, actual2.b0);
            Assert.Equal(exp1, actual2.b1);
        }

        [Theory]
        [InlineData(0, 0, 0, 0, 0)]
        [InlineData(0, 0, 1, 0, 0)]
        [InlineData(0, 0, 63, 0, 0)]
        [InlineData(0, 0, 64, 0, 0)]
        [InlineData(0, 0, 65, 0, 0)]
        [InlineData(0, 0, 128, 0, 0)]
        [InlineData(0x4423f49f115b79a6, 0xc5fdadb6442971e2, 1, 0x2211fa4f88adbcd3, 0x62fed6db2214b8f1)]
        [InlineData(0x4423f49f115b79a6, 0xc5fdadb6442971e2, 16, 0x71e24423f49f115b, 0x0000c5fdadb64429)]
        [InlineData(0x4423f49f115b79a6, 0xc5fdadb6442971e2, 63, 0x8bfb5b6c8852e3c4, 0x0000000000000001)]
        [InlineData(0x4423f49f115b79a6, 0xc5fdadb6442971e2, 64, 0xc5fdadb6442971e2, 0x0000000000000000)]
        [InlineData(0x4423f49f115b79a6, 0xc5fdadb6442971e2, 65, 0x62fed6db2214b8f1, 0x0000000000000000)]
        [InlineData(0x4423f49f115b79a6, 0xc5fdadb6442971e2, 80, 0x0000c5fdadb64429, 0x0000000000000000)]
        [InlineData(0x4423f49f115b79a6, 0xc5fdadb6442971e2, 127, 0x0000000000000001, 0x0000000000000000)]
        public void ShiftRightTest(ulong u0, ulong u1, int shift, ulong exp0, ulong exp1)
        {
            UInt128 a = new(u0, u1);
            UInt128 actual = a >> shift;

            Assert.Equal(exp0, actual.b0);
            Assert.Equal(exp1, actual.b1);
        }

        [Theory]
        [InlineData(0, 0, 0, 0)]
        [InlineData(0xffffffffffffffff, 0xffffffffffffffff, 0, 0)]
        [InlineData(0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff)]
        [InlineData(0x4423f49f115b79a6, 0xc5fdadb6442971e2, 0x45079f64b6460f7d, 0xe694388ec1816dd8)]
        public void AndTest(ulong u0, ulong u1, ulong u2, ulong u3)
        {
            UInt128 a = new(u0, u1);
            UInt128 b = new(u2, u3);

            UInt128 actual1 = a & b;
            UInt128 actual2 = b & a;
            ulong exp0 = u0 & u2;
            ulong exp1 = u1 & u3;

            Assert.Equal(exp0, actual1.b0);
            Assert.Equal(exp1, actual1.b1);
            Assert.Equal(exp0, actual2.b0);
            Assert.Equal(exp1, actual2.b1);
        }

        [Theory]
        [InlineData(0, 0, 0)]
        [InlineData(0xffffffffffffffff, 0xffffffffffffffff, 0)]
        [InlineData(0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff)]
        [InlineData(0x4423f49f115b79a6, 0xc5fdadb6442971e2, 0x45079f64b6460f7d)]
        public void And_WithUlongTest(ulong u0, ulong u1, ulong u2)
        {
            UInt128 a = new(u0, u1);

            UInt128 actual1 = a & u2;
            UInt128 actual2 = u2 & a;
            ulong exp0 = u0 & u2;
            ulong exp1 = u1 & 0;

            Assert.Equal(exp0, actual1.b0);
            Assert.Equal(exp1, actual1.b1);
            Assert.Equal(exp0, actual2.b0);
            Assert.Equal(exp1, actual2.b1);
        }

        [Theory]
        [InlineData(0, 0, 0, 0)]
        [InlineData(0xffffffffffffffff, 0xffffffffffffffff, 0, 0)]
        [InlineData(0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff)]
        [InlineData(0x4423f49f115b79a6, 0xc5fdadb6442971e2, 0x45079f64b6460f7d, 0xe694388ec1816dd8)]
        public void OrTest(ulong u0, ulong u1, ulong u2, ulong u3)
        {
            UInt128 a = new(u0, u1);
            UInt128 b = new(u2, u3);

            UInt128 actual1 = a | b;
            UInt128 actual2 = b | a;
            ulong exp0 = u0 | u2;
            ulong exp1 = u1 | u3;

            Assert.Equal(exp0, actual1.b0);
            Assert.Equal(exp1, actual1.b1);
            Assert.Equal(exp0, actual2.b0);
            Assert.Equal(exp1, actual2.b1);
        }

        [Theory]
        [InlineData(0, 0, 0, 0)]
        [InlineData(0xffffffffffffffff, 0xffffffffffffffff, 0, 0)]
        [InlineData(0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff)]
        [InlineData(0x4423f49f115b79a6, 0xc5fdadb6442971e2, 0x45079f64b6460f7d, 0xe694388ec1816dd8)]
        public void XorTest(ulong u0, ulong u1, ulong u2, ulong u3)
        {
            UInt128 a = new(u0, u1);
            UInt128 b = new(u2, u3);

            UInt128 actual1 = a ^ b;
            UInt128 actual2 = b ^ a;
            ulong exp0 = u0 ^ u2;
            ulong exp1 = u1 ^ u3;

            Assert.Equal(exp0, actual1.b0);
            Assert.Equal(exp1, actual1.b1);
            Assert.Equal(exp0, actual2.b0);
            Assert.Equal(exp1, actual2.b1);
        }
    }
}
