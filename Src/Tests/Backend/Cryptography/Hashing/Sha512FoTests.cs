// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend.Cryptography.Hashing;
using Newtonsoft.Json.Linq;
using System;
using System.Text;
using Xunit;

namespace Tests.Backend.Cryptography.Hashing
{
    public class Sha512FoTests
    {
        [Theory]
        [MemberData(nameof(HashTestCaseHelper.GetRegularHashCases), parameters: "SHA512", MemberType = typeof(HashTestCaseHelper))]
        public void ComputeHashTest(byte[] message, byte[] expectedHash)
        {
            using Sha512Fo sha = new Sha512Fo();
            byte[] actualHash = sha.ComputeHash(message);
            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void ComputeHash_AMillionATest()
        {
            using Sha512Fo sha = new Sha512Fo();
            byte[] actualHash = sha.ComputeHash(HashTestCaseHelper.GetAMillionA());
            byte[] expectedHash = Helper.HexToBytes("e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b");

            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void ComputeHash_ReuseTest()
        {
            byte[] msg1 = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
            byte[] msg2 = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy cog");
            byte[] exp1 = Helper.HexToBytes("07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb642e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6");
            byte[] exp2 = Helper.HexToBytes("3eeee1d0e11733ef152a6c29503b3ae20c4f1f3cda4cb26f1bc1a41f91c7fe4ab3bd86494049e201c4bd5155f31ecb7a3c8606843c4cc8dfcab7da11c8ae5045");

            using Sha512Fo sha = new Sha512Fo();
            byte[] act1 = sha.ComputeHash(msg1);
            byte[] act2 = sha.ComputeHash(msg2);

            Assert.Equal(exp1, act1);
            Assert.Equal(exp2, act2);
        }

        [Theory]
        [MemberData(nameof(HashTestCaseHelper.GetNistShortCases), parameters: "Sha512", MemberType = typeof(HashTestCaseHelper))]
        public void ComputeHash_NistShortTest(byte[] message, byte[] expected)
        {
            using Sha512Fo sha = new Sha512Fo();
            byte[] actual = sha.ComputeHash(message);
            Assert.Equal(expected, actual);
        }

        [Theory]
        [MemberData(nameof(HashTestCaseHelper.GetNistLongCases), parameters: "Sha512", MemberType = typeof(HashTestCaseHelper))]
        public void ComputeHash_NistLongTest(byte[] message, byte[] expected)
        {
            using Sha512Fo sha = new Sha512Fo();
            byte[] actual = sha.ComputeHash(message);
            Assert.Equal(expected, actual);
        }


        [Fact]
        public void ComputeHash_NistMonteCarloTest()
        {
            byte[] seed = Helper.HexToBytes("5c337de5caf35d18ed90b5cddfce001ca1b8ee8602f367e7c24ccca6f893802fb1aca7a3dae32dcd60800a59959bc540d63237876b799229ae71a2526fbc52cd");
            JObject jObjs = Helper.ReadResources<JObject>("Sha512NistTestData");
            int size = 64;
            byte[] toHash = new byte[3 * size];

            byte[] M0 = seed;
            byte[] M1 = seed;
            byte[] M2 = seed;

            using Sha512Fo sha = new Sha512Fo();

            foreach (var item in jObjs["MonteCarlo"])
            {
                byte[] expected = Helper.HexToBytes(item.ToString());
                for (int i = 0; i < 1000; i++)
                {
                    Buffer.BlockCopy(M0, 0, toHash, 0, size);
                    Buffer.BlockCopy(M1, 0, toHash, size, size);
                    Buffer.BlockCopy(M2, 0, toHash, size * 2, size);

                    M0 = M1;
                    M1 = M2;
                    M2 = sha.ComputeHash(toHash);
                }
                M0 = M2;
                M1 = M2;

                Assert.Equal(expected, M2);
            }
        }


        [Fact]
        public unsafe void GetFirst32BytesTest()
        {
            byte[] data = GetRandomBytes(64);
            byte[] expected = ((Span<byte>)data).Slice(0, 32).ToArray();
            ulong[] hashState = new ulong[8];
            for (int i = 0, j = 0; i < 8; i++, j += 8)
            {
                hashState[i] =
                            ((ulong)data[j] << 56) |
                            ((ulong)data[j + 1] << 48) |
                            ((ulong)data[j + 2] << 40) |
                            ((ulong)data[j + 3] << 32) |
                            ((ulong)data[j + 4] << 24) |
                            ((ulong)data[j + 5] << 16) |
                            ((ulong)data[j + 6] << 8) |
                            data[j + 7];
            }

            using Sha512Fo sha = new Sha512Fo();
            fixed (ulong* hPt = &hashState[0])
            {
                byte[] actual = sha.GetFirst32Bytes(hPt);
                Assert.Equal(expected, actual);
            }
        }

        [Fact]
        public unsafe void GetSecond32BytesTest()
        {
            byte[] data = GetRandomBytes(64);
            byte[] expected = ((Span<byte>)data).Slice(32, 32).ToArray();
            ulong[] hashState = new ulong[8];
            for (int i = 0, j = 0; i < 8; i++, j += 8)
            {
                hashState[i] =
                            ((ulong)data[j] << 56) |
                            ((ulong)data[j + 1] << 48) |
                            ((ulong)data[j + 2] << 40) |
                            ((ulong)data[j + 3] << 32) |
                            ((ulong)data[j + 4] << 24) |
                            ((ulong)data[j + 5] << 16) |
                            ((ulong)data[j + 6] << 8) |
                            data[j + 7];
            }

            using Sha512Fo sha = new Sha512Fo();
            fixed (ulong* hPt = &hashState[0])
            {
                byte[] actual = sha.GetSecond32Bytes(hPt);
                Assert.Equal(expected, actual);
            }
        }



        private byte[] GetRandomBytes(int len)
        {
            byte[] res = new byte[len];
            new Random().NextBytes(res);
            return res;
        }
        private byte[] ComputeSingleSha(byte[] data)
        {
            using var sysSha = System.Security.Cryptography.SHA512.Create();
            return sysSha.ComputeHash(data);
        }

        [Fact]
        public unsafe void Init_InnerPad_Bitcoinseed_Test()
        {
            int extraLen = 5;
            byte[] extraEndBa = GetRandomBytes(extraLen);
            int dataLen = 128 + extraLen;
            byte[] data = new byte[dataLen];
            ((Span<byte>)data).Fill(0x36);
            Buffer.BlockCopy(extraEndBa, 0, data, 128, extraLen);
            // XOR "Bitcoin seed" with initial bytes
            byte[] xor = Encoding.UTF8.GetBytes("Bitcoin seed");
            for (int i = 0; i < xor.Length; i++)
            {
                data[i] ^= xor[i];
            }

            byte[] expected = ComputeSingleSha(data);

            using Sha512Fo sha = new Sha512Fo();
            fixed (byte* dPt = &data[0])
            fixed (ulong* hPt = &sha.hashState[0], wPt = &sha.w[0])
            {
                sha.Init_InnerPad_Bitcoinseed(hPt);
                sha.CompressData(dPt + 128, extraLen, dataLen, hPt, wPt);
                byte[] actual = sha.GetBytes(hPt);

                Assert.Equal(expected, actual);
            }
        }

        [Fact]
        public unsafe void Init_OuterPad_Bitcoinseed_Test()
        {
            int extraLen = 5;
            byte[] extraEndBa = GetRandomBytes(extraLen);
            int dataLen = 128 + extraLen;
            byte[] data = new byte[dataLen];
            ((Span<byte>)data).Fill(0x5c);
            Buffer.BlockCopy(extraEndBa, 0, data, 128, extraLen);
            // XOR "Bitcoin seed" with initial bytes
            byte[] xor = Encoding.UTF8.GetBytes("Bitcoin seed");
            for (int i = 0; i < xor.Length; i++)
            {
                data[i] ^= xor[i];
            }

            byte[] expected = ComputeSingleSha(data);

            using Sha512Fo sha = new Sha512Fo();
            fixed (byte* dPt = &data[0])
            fixed (ulong* hPt = &sha.hashState[0], wPt = &sha.w[0])
            {
                sha.Init_OuterPad_Bitcoinseed(hPt);
                sha.CompressData(dPt + 128, extraLen, dataLen, hPt, wPt);
                byte[] actual = sha.GetBytes(hPt);

                Assert.Equal(expected, actual);
            }
        }

        [Fact]
        public unsafe void Init_InnerPad_SeedVersion_Test()
        {
            int extraLen = 5;
            byte[] extraEndBa = GetRandomBytes(extraLen);
            int dataLen = 128 + extraLen;
            byte[] data = new byte[dataLen];
            ((Span<byte>)data).Fill(0x36);
            Buffer.BlockCopy(extraEndBa, 0, data, 128, extraLen);
            // XOR "Seed version" with initial bytes
            byte[] xor = Encoding.UTF8.GetBytes("Seed version");
            for (int i = 0; i < xor.Length; i++)
            {
                data[i] ^= xor[i];
            }

            byte[] expected = ComputeSingleSha(data);

            using Sha512Fo sha = new Sha512Fo();
            fixed (byte* dPt = &data[0])
            fixed (ulong* hPt = &sha.hashState[0], wPt = &sha.w[0])
            {
                sha.Init_InnerPad_SeedVersion(hPt);
                sha.CompressData(dPt + 128, extraLen, dataLen, hPt, wPt);
                byte[] actual = sha.GetBytes(hPt);

                Assert.Equal(expected, actual);
            }
        }

        [Fact]
        public unsafe void Init_OuterPad_SeedVersion_Test()
        {
            int extraLen = 5;
            byte[] extraEndBa = GetRandomBytes(extraLen);
            int dataLen = 128 + extraLen;
            byte[] data = new byte[dataLen];
            ((Span<byte>)data).Fill(0x5c);
            Buffer.BlockCopy(extraEndBa, 0, data, 128, extraLen);
            // XOR "Seed version" with initial bytes
            byte[] xor = Encoding.UTF8.GetBytes("Seed version");
            for (int i = 0; i < xor.Length; i++)
            {
                data[i] ^= xor[i];
            }

            byte[] expected = ComputeSingleSha(data);

            using Sha512Fo sha = new Sha512Fo();
            fixed (byte* dPt = &data[0])
            fixed (ulong* hPt = &sha.hashState[0], wPt = &sha.w[0])
            {
                sha.Init_OuterPad_SeedVersion(hPt);
                sha.CompressData(dPt + 128, extraLen, dataLen, hPt, wPt);
                byte[] actual = sha.GetBytes(hPt);

                Assert.Equal(expected, actual);
            }
        }

        [Fact]
        public unsafe void Compress165SecondBlockTest()
        {
            int dataLen = 165;
            byte[] data = GetRandomBytes(dataLen);
            byte[] expected = ComputeSingleSha(data);

            using Sha512Fo sha = new Sha512Fo();
            fixed (ulong* hPt = &sha.hashState[0], wPt = &sha.w[0])
            {
                sha.Init(hPt);

                int dIndex = 0;
                for (int i = 0; i < 16; i++, dIndex += 8)
                {
                    wPt[i] =
                            ((ulong)data[dIndex] << 56) |
                            ((ulong)data[dIndex + 1] << 48) |
                            ((ulong)data[dIndex + 2] << 40) |
                            ((ulong)data[dIndex + 3] << 32) |
                            ((ulong)data[dIndex + 4] << 24) |
                            ((ulong)data[dIndex + 5] << 16) |
                            ((ulong)data[dIndex + 6] << 8) |
                            data[dIndex + 7];
                }

                sha.CompressBlock(hPt, wPt);

                for (int i = 0; i < 4; i++, dIndex += 8)
                {
                    wPt[i] =
                            ((ulong)data[dIndex] << 56) |
                            ((ulong)data[dIndex + 1] << 48) |
                            ((ulong)data[dIndex + 2] << 40) |
                            ((ulong)data[dIndex + 3] << 32) |
                            ((ulong)data[dIndex + 4] << 24) |
                            ((ulong)data[dIndex + 5] << 16) |
                            ((ulong)data[dIndex + 6] << 8) |
                            data[dIndex + 7];
                }
                wPt[4] = ((ulong)data[dIndex] << 56) |
                         ((ulong)data[dIndex + 1] << 48) |
                         ((ulong)data[dIndex + 2] << 40) |
                         ((ulong)data[dIndex + 3] << 32) |
                         ((ulong)data[dIndex + 4] << 24) |
                         0b00000000_00000000_00000000_00000000_00000000_10000000_00000000_00000000UL;
                wPt[5] = 0;
                wPt[6] = 0;
                wPt[7] = 0;
                wPt[8] = 0;
                wPt[9] = 0;
                wPt[10] = 0;
                wPt[11] = 0;
                wPt[12] = 0;
                wPt[13] = 0;
                wPt[14] = 0;
                wPt[15] = (ulong)dataLen * 8;

                sha.Compress165SecondBlock(hPt, wPt);
                byte[] actual = sha.GetBytes(hPt);

                Assert.Equal(expected, actual);
            }
        }

        [Fact]
        public unsafe void Compress192SecondBlockTest()
        {
            int dataLen = 192;
            byte[] data = GetRandomBytes(dataLen);
            byte[] expected = ComputeSingleSha(data);

            using Sha512Fo sha = new Sha512Fo();
            fixed (ulong* hPt = &sha.hashState[0], wPt = &sha.w[0])
            {
                sha.Init(hPt);

                int dIndex = 0;
                for (int i = 0; i < 16; i++, dIndex += 8)
                {
                    wPt[i] =
                            ((ulong)data[dIndex] << 56) |
                            ((ulong)data[dIndex + 1] << 48) |
                            ((ulong)data[dIndex + 2] << 40) |
                            ((ulong)data[dIndex + 3] << 32) |
                            ((ulong)data[dIndex + 4] << 24) |
                            ((ulong)data[dIndex + 5] << 16) |
                            ((ulong)data[dIndex + 6] << 8) |
                            data[dIndex + 7];
                }

                sha.CompressBlock(hPt, wPt);

                for (int i = 0; i < 8; i++, dIndex += 8)
                {
                    wPt[i] =
                            ((ulong)data[dIndex] << 56) |
                            ((ulong)data[dIndex + 1] << 48) |
                            ((ulong)data[dIndex + 2] << 40) |
                            ((ulong)data[dIndex + 3] << 32) |
                            ((ulong)data[dIndex + 4] << 24) |
                            ((ulong)data[dIndex + 5] << 16) |
                            ((ulong)data[dIndex + 6] << 8) |
                            data[dIndex + 7];
                }
                wPt[8] = 0b10000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000UL;
                wPt[9] = 0;
                wPt[10] = 0;
                wPt[11] = 0;
                wPt[12] = 0;
                wPt[13] = 0;
                wPt[14] = 0;
                wPt[15] = (ulong)dataLen * 8;

                sha.Compress192SecondBlock(hPt, wPt);
                byte[] actual = sha.GetBytes(hPt);

                Assert.Equal(expected, actual);
            }
        }

        [Fact]
        public unsafe void CompressHmacBlock_0x36_Bitcoinseed_Test()
        {
            int extraLen = 5;
            byte[] extraEndBa = GetRandomBytes(extraLen);
            int dataLen = 128 + extraLen;
            byte[] data = new byte[dataLen];
            ((Span<byte>)data).Fill(0x36);
            Buffer.BlockCopy(extraEndBa, 0, data, 128, extraLen);
            // XOR "Bitcoin seed" with initial bytes
            byte[] xor = Encoding.UTF8.GetBytes("Bitcoin seed");
            for (int i = 0; i < xor.Length; i++)
            {
                data[i] ^= xor[i];
            }

            byte[] expected = ComputeSingleSha(data);

            using Sha512Fo sha = new Sha512Fo();
            fixed (byte* dPt = &data[0])
            fixed (ulong* hPt = &sha.hashState[0], wPt = &sha.w[0])
            {
                sha.Init(hPt);
                sha.CompressHmacBlock_0x36_Bitcoinseed(hPt, wPt);

                sha.CompressData(dPt + 128, extraLen, dataLen, hPt, wPt);
                byte[] actual = sha.GetBytes(hPt);

                Assert.Equal(expected, actual);
            }
        }

        [Fact]
        public unsafe void CompressHmacBlock_0x5c_Bitcoinseed_Test()
        {
            int extraLen = 5;
            byte[] extraEndBa = GetRandomBytes(extraLen);
            int dataLen = 128 + extraLen;
            byte[] data = new byte[dataLen];
            ((Span<byte>)data).Fill(0x5c);
            Buffer.BlockCopy(extraEndBa, 0, data, 128, extraLen);
            // XOR "Bitcoin seed" with initial bytes
            byte[] xor = Encoding.UTF8.GetBytes("Bitcoin seed");
            for (int i = 0; i < xor.Length; i++)
            {
                data[i] ^= xor[i];
            }

            byte[] expected = ComputeSingleSha(data);

            using Sha512Fo sha = new Sha512Fo();
            fixed (byte* dPt = &data[0])
            fixed (ulong* hPt = &sha.hashState[0], wPt = &sha.w[0])
            {
                sha.Init(hPt);
                sha.CompressHmacBlock_0x5c_Bitcoinseed(hPt, wPt);

                sha.CompressData(dPt + 128, extraLen, dataLen, hPt, wPt);
                byte[] actual = sha.GetBytes(hPt);

                Assert.Equal(expected, actual);
            }
        }
    }
}
