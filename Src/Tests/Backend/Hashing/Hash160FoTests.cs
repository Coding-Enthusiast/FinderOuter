// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using FinderOuter.Backend.Hashing;
using System;

namespace Tests.Backend.Hashing
{
    public class Hash160FoTests
    {
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
