// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Services.SearchSpaces;
using System.Collections.Generic;

namespace Tests.Services.SearchSpaces
{
    public class CorePassSearchSpaceTests
    {
        public static IEnumerable<object[]> GetProcessCases()
        {
            // Taken from: https://bitcointalk.org/index.php?topic=5511431.msg64607294#msg64607294
            yield return new object[]
            {
                "43000130ac71182a748152bb788fb9deb11f2f5a55f5e848d66586747cc000826d4c0c350032153d50cbf924a2ac1dc5f6279436089ca0271b64c0e66f00000000c6fe040000",
                2,
                true, string.Empty,
                Helper.HexToBytes("9ca0271b64c0e66f"),
                Helper.HexToBytes("0032153d50cbf924a2ac1dc5f6279436"),
                Helper.HexToBytes("55f5e848d66586747cc000826d4c0c35"),
                327366
            };
            yield return new object[]
            {
                "43000130ac71182a748152bb788fb9deb11f2f5a55f5e848d66586747cc000826d4c0c350032153d50cbf924a2ac1dc5f6279436089ca0271b64c0e66f00000000c6fe040000",
                0,
                false, "Password length must be at least 1.",
                null, null, null, 0
            };
            yield return new object[]
            {
                "43000130ac71182a748152bb788fb9deb11f2f5a55f5e848d66586747cc000826d4c0c350032153d50cbf924a2ac1dc5f6279436089ca0271b64c0e66f00000000c6fe040000",
                -1,
                false, "Password length must be at least 1.",
                null, null, null, 0
            };
            yield return new object[]
            {
                null,
                2,
                false, "Input hex can not be null or empty.",
                null, null, null, 0
            };
            yield return new object[]
            {
                "abcx",
                2,
                false, "Invalid character \"x\" found at index=3.",
                null, null, null, 0
            };
            yield return new object[]
            {
                "abc",
                2,
                false, "Invalid hex string.",
                null, null, null, 0
            };
            yield return new object[]
            {
                "abcd",
                2,
                false, "Input hex is expected to be at least 70 bytes but it is 2 bytes.",
                null, null, null, 0
            };
            yield return new object[]
            {
                Helper.GetBytesHex(70),
                2,
                false, "Could not find 0x43000130 in the given hex.",
                null, null, null, 0
            };
        }

        [Theory]
        [MemberData(nameof(GetProcessCases))]
        public void ProcessTest(string hex, int passLength, bool expected, string expError,
                                byte[] expSalt, byte[] expEncrypted, byte[] expXor, int expIter)
        {
            CorePassSearchSpace searchSpace = new();
            bool actual = searchSpace.Process(hex, passLength, out string error);

            Assert.Equal(expected, actual);
            Assert.Equal(expError, error);

            if (expected)
            {
                Assert.Equal(searchSpace.PasswordLength, passLength);
                Assert.Equal(searchSpace.Salt, expSalt);
                Assert.Equal(searchSpace.Encrypted, expEncrypted);
                Assert.Equal(searchSpace.XOR, expXor);
                Assert.Equal(searchSpace.Iteration, expIter);
            }
        }
    }
}
