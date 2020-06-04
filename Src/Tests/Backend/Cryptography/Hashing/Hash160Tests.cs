// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend.Cryptography.Hashing;
using Xunit;

namespace Tests.Backend.Cryptography.Hashing
{
    public class Hash160Tests
    {
        private const string CompPub = "03306EEB63417D2E50C49BD5CB6256296116D6474C14853D64E008D281E392109A";
        private const string CompPubHex = "3edd2f8b85027645ddb5aec9ad59b3b60c396c7e";
        private const string UncompPub = "04306EEB63417D2E50C49BD5CB6256296116D6474C14853D64E008D281E392109AF3C0F0E015C966BE3DBB4BD09E4BE95EC109CCDFBEC4C4FD910E77091DC00A67";
        private const string UncompPubHex = "543e87f1cde0a028ad4c33afc8052ed78846c216";

        [Fact]
        public void ComputeHashTest()
        {
            using Hash160 hash = new Hash160();
            byte[] data1 = Helper.HexToBytes(CompPub);
            byte[] actual1 = hash.ComputeHash(data1);
            byte[] expected1 = Helper.HexToBytes(CompPubHex);

            byte[] data2 = Helper.HexToBytes(UncompPub);
            byte[] actual2 = hash.ComputeHash(data2);
            byte[] expected2 = Helper.HexToBytes(UncompPubHex);

            Assert.Equal(expected1, actual1);
            Assert.Equal(expected2, actual2);
        }

        [Fact]
        public unsafe void Compress33Test()
        {
            using Hash160 hash = new Hash160();
            byte[] data = Helper.HexToBytes(CompPub);
            byte[] actual = hash.Compress33(data);
            byte[] expected = Helper.HexToBytes(CompPubHex);

            Assert.Equal(33, data.Length);
            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void Compress65Test()
        {
            using Hash160 hash = new Hash160();
            byte[] data = Helper.HexToBytes(UncompPub);
            byte[] actual = hash.Compress65(data);
            byte[] expected = Helper.HexToBytes(UncompPubHex);

            Assert.Equal(65, data.Length);
            Assert.Equal(expected, actual);
        }
    }
}
