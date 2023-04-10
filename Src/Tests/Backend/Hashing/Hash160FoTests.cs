// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using FinderOuter.Backend.Hashing;
using System;
using Xunit;

namespace Tests.Backend.Hashing
{
    public class Hash160FoTests
    {
        [Fact]
        public void ComputeHashTest()
        {
            byte[] data1 = Helper.HexToBytes("03306eeb63417d2e50c49bd5cb6256296116d6474c14853d64e008d281e392109a");
            byte[] actual1 = Hash160Fo.ComputeHash_static(data1);
            byte[] expected1 = Helper.HexToBytes("3edd2f8b85027645ddb5aec9ad59b3b60c396c7e");

            byte[] data2 = Helper.HexToBytes("04306EEB63417D2E50C49BD5CB6256296116D6474C14853D64E008D281E392109AF3C0F0E015C966BE3DBB4BD09E4BE95EC109CCDFBEC4C4FD910E77091DC00A67");
            byte[] actual2 = Hash160Fo.ComputeHash_static(data2);
            byte[] expected2 = Helper.HexToBytes("543e87f1cde0a028ad4c33afc8052ed78846c216");

            Assert.Equal(expected1, actual1);
            Assert.Equal(expected2, actual2);
        }

        private static byte[] GetRandomBytes(int len)
        {
            byte[] res = new byte[len];
            new Random().NextBytes(res);
            return res;
        }

        private static byte[] ComputeHash160(byte[] data)
        {
            using System.Security.Cryptography.SHA256 sha = System.Security.Cryptography.SHA256.Create();
            return Ripemd160Fo.ComputeHash_Static(sha.ComputeHash(data));
        }

        [Fact]
        public unsafe void Compress22Test()
        {
            byte[] data = GetRandomBytes(22);

            byte[] actual = Hash160Fo.Compress22(data);
            byte[] expected = ComputeHash160(data);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void Compress33_P2shTest()
        {
            byte[] data = GetRandomBytes(33);

            byte[] actual = Hash160Fo.Compress33_P2sh(data);
            // Hash160(0x0014-Hash160(pub))
            byte[] expected = ComputeHash160(new byte[] { 0, 20 }.ConcatFast(ComputeHash160(data)));

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void Compress33Test()
        {
            byte[] data = GetRandomBytes(33);

            byte[] actual = Hash160Fo.Compress33(data);
            byte[] expected = ComputeHash160(data);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void Compress65Test()
        {
            byte[] data = GetRandomBytes(65);

            byte[] actual = Hash160Fo.Compress65(data);
            byte[] expected = ComputeHash160(data);

            Assert.Equal(expected, actual);
        }
    }
}
