// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend.Hashing;
using Newtonsoft.Json.Linq;
using System.Text;

namespace Tests.Backend.Hashing
{
    public class Ripemd160FoTests
    {
        [Theory]
        [MemberData(nameof(HashTestCaseHelper.GetRegularHashCases), parameters: "RIPEMD160", MemberType = typeof(HashTestCaseHelper))]
        public void ComputeHashTest(byte[] message, byte[] expectedHash)
        {
            byte[] actualHash = Ripemd160Fo.ComputeHash_Static(message);
            Assert.Equal(expectedHash, actualHash);
        }

        private static byte[] GetBytes(int len)
        {
            byte[] result = new byte[len];
            for (int i = 0; i < len; i++)
            {
                result[i] = (byte)(i + 1);
            }

            return result;
        }
        public static TheoryData GetProgressiveCase()
        {
            TheoryData<byte[], byte[]> result = new();
            int len = 1;
            // Hash values were computed using .Net framework 4.7.2 System.Security.Cryptography.RIPEMD160Managed
            foreach (JToken item in Helper.ReadResources<JArray>("Ripemd160ProgressiveTestData"))
            {
                byte[] msgBytes = GetBytes(len++);
                byte[] hashBytes = Helper.HexToBytes(item.ToString());

                result.Add(msgBytes, hashBytes);
            }
            return result;
        }
        [Theory]
        [MemberData(nameof(GetProgressiveCase))]
        public void ComputeHash_ProgressiveTest(byte[] message, byte[] expectedHash)
        {
            byte[] actualHash = Ripemd160Fo.ComputeHash_Static(message);
            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void ComputeHash_AMillionATest()
        {
            byte[] actualHash = Ripemd160Fo.ComputeHash_Static(HashTestCaseHelper.GetAMillionA());
            byte[] expectedHash = Helper.HexToBytes("52783243c1697bdbe16d37f97f68f08325dc1528");

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void ComputeHash_ReuseTest()
        {
            // From https://en.wikipedia.org/wiki/RIPEMD#RIPEMD-160_hashes
            byte[] msg1 = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
            byte[] msg2 = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy cog");
            byte[] exp1 = Helper.HexToBytes("37f332f68db77bd9d7edd4969571ad671cf9dd3b");
            byte[] exp2 = Helper.HexToBytes("132072df690933835eb8b6ad0b77e7b6f14acad7");

            byte[] act1 = Ripemd160Fo.ComputeHash_Static(msg1);
            byte[] act2 = Ripemd160Fo.ComputeHash_Static(msg2);

            Assert.Equal(exp1, act1);
            Assert.Equal(exp2, act2);
        }
    }
}
