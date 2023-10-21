// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend.Hashing;
using Newtonsoft.Json.Linq;
using System;
using System.Runtime.CompilerServices;
using System.Text;

namespace Tests.Backend.Hashing
{
    public class Sha256FoTests
    {
        [Theory]
        [MemberData(nameof(HashTestCaseHelper.GetRegularHashCases), parameters: "SHA256", MemberType = typeof(HashTestCaseHelper))]
        public void ComputeHashTest(byte[] message, byte[] expectedHash)
        {
            byte[] actualHash = Sha256Fo.ComputeHash(message);
            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void ComputeHash_AMillionATest()
        {
            byte[] actualHash = Sha256Fo.ComputeHash(HashTestCaseHelper.GetAMillionA());
            byte[] expectedHash = Helper.HexToBytes("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
            Assert.Equal(expectedHash, actualHash);
        }

        [Fact]
        public void ComputeHash_ReuseTest()
        {
            byte[] msg1 = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy dog");
            byte[] msg2 = Encoding.UTF8.GetBytes("The quick brown fox jumps over the lazy cog");
            byte[] exp1 = Helper.HexToBytes("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
            byte[] exp2 = Helper.HexToBytes("e4c4d8f3bf76b692de791a173e05321150f7a345b46484fe427f6acc7ecc81be");

            byte[] act1 = Sha256Fo.ComputeHash(msg1);
            byte[] act2 = Sha256Fo.ComputeHash(msg2);

            Assert.Equal(exp1, act1);
            Assert.Equal(exp2, act2);
        }


        [Fact]
        public void ComputeHash_DoubleTest()
        {
            byte[] data = Helper.HexToBytes("fb8049137747e712628240cf6d7056ea2870170cb7d9bc713d91e901b514c6ae7d7dda3cd03ea1b99cf85046a505f3590541123d3f8f2c22c4d7d6e65de65c4ebb9251f09619");
            byte[] actualHash = Sha256Fo.ComputeHashTwice(data);
            byte[] expectedHash = Helper.HexToBytes("d2cee8d3cfaf1819c55cce1214d01cdef1d97446719ccfaad4d76d912a8126f9");

            Assert.Equal(expectedHash, actualHash);
        }

        [Theory]
        [MemberData(nameof(HashTestCaseHelper.GetNistShortCases), parameters: "Sha256", MemberType = typeof(HashTestCaseHelper))]
        public void ComputeHash_NistShortTest(byte[] message, byte[] expected)
        {
            byte[] actual = Sha256Fo.ComputeHash(message);
            Assert.Equal(expected, actual);
        }

        [Theory]
        [MemberData(nameof(HashTestCaseHelper.GetNistShortCases), parameters: "Sha256", MemberType = typeof(HashTestCaseHelper))]
        public void ComputeHash_NistLongTest(byte[] message, byte[] expected)
        {
            byte[] actual = Sha256Fo.ComputeHash(message);
            Assert.Equal(expected, actual);
        }


        [Fact]
        public void ComputeHash_NistMonteCarloTest()
        {
            byte[] seed = Helper.HexToBytes("6d1e72ad03ddeb5de891e572e2396f8da015d899ef0e79503152d6010a3fe691");
            JObject jObjs = Helper.ReadResources<JObject>("Sha256NistTestData");
            int size = 32;
            byte[] toHash = new byte[3 * size];

            byte[] M0 = seed;
            byte[] M1 = seed;
            byte[] M2 = seed;

            foreach (JToken item in jObjs["MonteCarlo"])
            {
                byte[] expected = Helper.HexToBytes(item.ToString());
                for (int i = 0; i < 1000; i++)
                {
                    Buffer.BlockCopy(M0, 0, toHash, 0, size);
                    Buffer.BlockCopy(M1, 0, toHash, size, size);
                    Buffer.BlockCopy(M2, 0, toHash, size * 2, size);

                    M0 = M1;
                    M1 = M2;
                    M2 = Sha256Fo.ComputeHash(toHash);
                }
                M0 = M2;
                M1 = M2;

                Assert.Equal(expected, M2);
            }
        }



        // The original MAJ() and CH() functions are defined differently in RFC documentation.
        // The following tests makes sure the changed function is giving the same result
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        private static uint CH_Original(uint x, uint y, uint z) => (x & y) ^ ((~x) & z);
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        private static uint CH_Changed(uint x, uint y, uint z) => z ^ (x & (y ^ z));

        [Fact]
        public void CH_Test()
        {
            for (uint x = 0b00; x <= 0b11; x++)
            {
                for (uint y = 0b00; y <= 0b11; y++)
                {
                    for (uint z = 0b00; z <= 0b11; z++)
                    {
                        Assert.Equal(CH_Original(x, y, z), CH_Changed(x, y, z));
                    }
                }
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        private static uint MAJ_Original(uint x, uint y, uint z) => (x & y) ^ (x & z) ^ (y & z);
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        private static uint MAJ_Changed(uint x, uint y, uint z) => (x & y) | (z & (x | y));

        [Fact]
        public void MAJ_Test()
        {
            for (uint x = 0b00; x <= 0b11; x++)
            {
                for (uint y = 0b00; y <= 0b11; y++)
                {
                    for (uint z = 0b00; z <= 0b11; z++)
                    {
                        Assert.Equal(MAJ_Original(x, y, z), MAJ_Changed(x, y, z));
                    }
                }
            }
        }

        [Fact]
        public void MessageLengthTest()
        {
            int len = 0x493657ad;
            long msgLen = (long)len << 3; // *8

            byte[] first = new byte[8];
            byte[] second = new byte[8];

            // Message length is an Int32 multiplied by 8 to convert to bit length so the maximum value is:
            // int.MaxValue * 8 = 17179869176 or int.MaxValue << 3
            // 00000000_00000000_00000000_00000011_11111111_11111111_11111111_11111000
            // This means the first 3 bytes must always be zero

            first[7] = (byte)msgLen;
            first[6] = (byte)(msgLen >> 8);
            first[5] = (byte)(msgLen >> 16);
            first[4] = (byte)(msgLen >> 24);
            first[3] = (byte)(msgLen >> 32);
            first[2] = (byte)(msgLen >> 40); // must be zero
            first[1] = (byte)(msgLen >> 48); // must be zero
            first[0] = (byte)(msgLen >> 56); // must be zero

            /****** The alternative way: ******/
            // msgLen = len << 3
            // [7] = (byte)msgLen           = (byte)(len << 3)
            // [6] = (byte)(msgLen >> 8)    = (byte)((len << 3) >> 8) = (byte)(len >> 5)
            // ...
            // [3] = (byte)(msgLen >> 32)   = (byte)((len << 3) >> 32) = (byte)(len >> 29)

            // [2] = (byte)(msgLen >> 40)   = (byte)((len << 3) >> 40) = (byte)(len >> 37)
            // Assuming len were Int64, 37 bit shift is getting rid of the first 32+3 bits so it must be zero
            second[7] = (byte)(len << 3);
            second[6] = (byte)(len >> 5);
            second[5] = (byte)(len >> 13);
            second[4] = (byte)(len >> 21);
            second[3] = (byte)(len >> 29);
            //second[2] = (byte)(len >> 37); shifts are bigger than 32, won't work as long as len is Int32
            //second[1] = (byte)(len >> 45); 
            //second[0] = (byte)(len >> 53); 

            Assert.Equal(first, second);
            Assert.Equal(0, first[0]);
            Assert.Equal(0, first[1]);
            Assert.Equal(0, first[2]);
        }

        private static byte[] GetRandomBytes(int len)
        {
            byte[] res = new byte[len];
            new Random().NextBytes(res);
            return res;
        }
        private static byte[] ComputeSingleSha(byte[] data)
        {
            using System.Security.Cryptography.SHA256 sysSha = System.Security.Cryptography.SHA256.Create();
            return sysSha.ComputeHash(data);
        }
        private static byte[] ComputeDoubleSha(byte[] data)
        {
            using System.Security.Cryptography.SHA256 sysSha = System.Security.Cryptography.SHA256.Create();
            return sysSha.ComputeHash(sysSha.ComputeHash(data));
        }


        [Fact]
        public unsafe void Compress62SecondBlockTest()
        {
            int dataLen = 62;
            byte[] data = GetRandomBytes(dataLen);
            byte[] expected = ComputeSingleSha(data);

            uint* hPt = stackalloc uint[Sha256Fo.HashStateSize + Sha256Fo.WorkingVectorSize];
            uint* wPt = hPt + Sha256Fo.HashStateSize;

            int dIndex = 0;
            for (int i = 0; i < 15; i++, dIndex += 4)
            {
                wPt[i] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            }
            wPt[15] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16)) | 0b00000000_00000000_10000000_00000000U;

            Sha256Fo.Init(hPt);
            Sha256Fo.SetW(wPt);
            Sha256Fo.CompressBlockWithWSet(hPt);

            // Next block:
            for (int i = 0; i < 15; i++)
            {
                wPt[i] = 0;
            }
            wPt[15] = (uint)dataLen * 8;
            Sha256Fo.Compress62SecondBlock(hPt);
            byte[] actual = Sha256Fo.GetBytes(hPt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void Compress64SecondBlockTest()
        {
            int dataLen = 64;
            byte[] data = GetRandomBytes(dataLen);
            byte[] expected = ComputeSingleSha(data);

            uint* hPt = stackalloc uint[Sha256Fo.UBufferSize];
            uint* wPt = hPt + Sha256Fo.HashStateSize;

            int dIndex = 0;
            for (int i = 0; i < 16; i++, dIndex += 4)
            {
                wPt[i] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            }

            Sha256Fo.Init(hPt);
            Sha256Fo.SetW(wPt);
            Sha256Fo.CompressBlockWithWSet(hPt);
            // Next block:
            wPt[0] = 0b10000000_00000000_00000000_00000000U;
            for (int i = 1; i < 15; i++)
            {
                wPt[i] = 0;
            }
            wPt[15] = (uint)dataLen * 8;
            Sha256Fo.Compress64SecondBlock(hPt);
            byte[] actual = Sha256Fo.GetBytes(hPt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void Compress72SecondBlockTest()
        {
            int dataLen = 72;
            byte[] data = GetRandomBytes(dataLen);
            byte[] expected = ComputeSingleSha(data);

            uint* hPt = stackalloc uint[Sha256Fo.UBufferSize];
            uint* wPt = hPt + Sha256Fo.HashStateSize;

            int dIndex = 0;
            for (int i = 0; i < 16; i++, dIndex += 4)
            {
                wPt[i] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            }

            Sha256Fo.Init(hPt);
            Sha256Fo.SetW(wPt);
            Sha256Fo.CompressBlockWithWSet(hPt);
            // Next block:
            wPt[0] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            dIndex += 4;
            wPt[1] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            wPt[2] = 0b10000000_00000000_00000000_00000000U;
            for (int i = 3; i < 15; i++)
            {
                wPt[i] = 0;
            }
            wPt[15] = (uint)dataLen * 8;
            Sha256Fo.Compress72SecondBlock(hPt);
            byte[] actual = Sha256Fo.GetBytes(hPt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void Compress76SecondBlockTest()
        {
            int dataLen = 76;
            byte[] data = GetRandomBytes(dataLen);
            byte[] expected = ComputeSingleSha(data);

            uint* hPt = stackalloc uint[Sha256Fo.UBufferSize];
            uint* wPt = hPt + Sha256Fo.HashStateSize;

            int dIndex = 0;
            for (int i = 0; i < 16; i++, dIndex += 4)
            {
                wPt[i] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            }

            Sha256Fo.Init(hPt);
            Sha256Fo.SetW(wPt);
            Sha256Fo.CompressBlockWithWSet(hPt);
            // Next block:
            wPt[0] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            dIndex += 4;
            wPt[1] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            dIndex += 4;
            wPt[2] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            wPt[3] = 0b10000000_00000000_00000000_00000000U;
            for (int i = 4; i < 15; i++)
            {
                wPt[i] = 0;
            }
            wPt[15] = (uint)dataLen * 8;
            Sha256Fo.Compress76SecondBlock(hPt);
            byte[] actual = Sha256Fo.GetBytes(hPt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void Compress80SecondBlockTest()
        {
            int dataLen = 80;
            byte[] data = GetRandomBytes(dataLen);
            byte[] expected = ComputeSingleSha(data);

            uint* hPt = stackalloc uint[Sha256Fo.UBufferSize];
            uint* wPt = hPt + Sha256Fo.HashStateSize;

            int dIndex = 0;
            for (int i = 0; i < 16; i++, dIndex += 4)
            {
                wPt[i] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            }

            Sha256Fo.Init(hPt);
            Sha256Fo.SetW(wPt);
            Sha256Fo.CompressBlockWithWSet(hPt);
            // Next block:
            wPt[0] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            dIndex += 4;
            wPt[1] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            dIndex += 4;
            wPt[2] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            dIndex += 4;
            wPt[3] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            wPt[4] = 0b10000000_00000000_00000000_00000000U;
            for (int i = 5; i < 15; i++)
            {
                wPt[i] = 0;
            }
            wPt[15] = (uint)dataLen * 8;
            Sha256Fo.Compress80SecondBlock(hPt);
            byte[] actual = Sha256Fo.GetBytes(hPt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void Compress96SecondBlockTest()
        {
            int dataLen = 96;
            byte[] data = GetRandomBytes(dataLen);
            byte[] expected = ComputeSingleSha(data);

            uint* hPt = stackalloc uint[Sha256Fo.UBufferSize];
            uint* wPt = hPt + Sha256Fo.HashStateSize;

            int dIndex = 0;
            for (int i = 0; i < 16; i++, dIndex += 4)
            {
                wPt[i] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            }

            Sha256Fo.Init(hPt);
            Sha256Fo.SetW(wPt);
            Sha256Fo.CompressBlockWithWSet(hPt);
            // Next block:
            for (int i = 0; i < 8; i++, dIndex += 4)
            {
                wPt[i] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            }
            wPt[8] = 0b10000000_00000000_00000000_00000000U;
            for (int i = 9; i < 15; i++)
            {
                wPt[i] = 0;
            }
            wPt[15] = (uint)dataLen * 8;
            Sha256Fo.Compress96SecondBlock(hPt);
            byte[] actual = Sha256Fo.GetBytes(hPt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void Compress196FinalBlock_1Test()
        {
            int dataLen = 196;
            byte[] data = GetRandomBytes(dataLen);
            data[^1] = 1;
            data[^2] = 0;
            data[^3] = 0;
            data[^4] = 0;
            byte[] expected = ComputeSingleSha(data);

            uint* hPt = stackalloc uint[Sha256Fo.UBufferSize];
            uint* wPt = hPt + Sha256Fo.HashStateSize;

            Sha256Fo.Init(hPt);
            int dIndex = 0;
            for (int j = 0; j < dataLen / Sha256Fo.BlockByteSize; j++)
            {
                for (int i = 0; i < 16; i++, dIndex += 4)
                {
                    wPt[i] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
                }

                Sha256Fo.SetW(wPt);
                Sha256Fo.CompressBlockWithWSet(hPt);
            }
            // Final block:
            wPt[0] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            wPt[1] = 0b10000000_00000000_00000000_00000000U;
            for (int i = 2; i < 15; i++)
            {
                wPt[i] = 0;
            }
            wPt[15] = (uint)dataLen * 8;
            Sha256Fo.Compress196FinalBlock(hPt, 1);
            byte[] actual = Sha256Fo.GetBytes(hPt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void Compress196FinalBlock_2Test()
        {
            int dataLen = 196;
            byte[] data = GetRandomBytes(dataLen);
            data[^1] = 2;
            data[^2] = 0;
            data[^3] = 0;
            data[^4] = 0;
            byte[] expected = ComputeSingleSha(data);

            uint* hPt = stackalloc uint[Sha256Fo.UBufferSize];
            uint* wPt = hPt + Sha256Fo.HashStateSize;

            Sha256Fo.Init(hPt);
            int dIndex = 0;
            for (int j = 0; j < dataLen / Sha256Fo.BlockByteSize; j++)
            {
                for (int i = 0; i < 16; i++, dIndex += 4)
                {
                    wPt[i] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
                }

                Sha256Fo.SetW(wPt);
                Sha256Fo.CompressBlockWithWSet(hPt);
            }
            // Final block:
            wPt[0] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            wPt[1] = 0b10000000_00000000_00000000_00000000U;
            for (int i = 2; i < 15; i++)
            {
                wPt[i] = 0;
            }
            wPt[15] = (uint)dataLen * 8;
            Sha256Fo.Compress196FinalBlock(hPt, 2);
            byte[] actual = Sha256Fo.GetBytes(hPt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void Compress8260FinalBlock_1Test()
        {
            int dataLen = 8260;
            byte[] data = GetRandomBytes(dataLen);
            data[^1] = 1;
            data[^2] = 0;
            data[^3] = 0;
            data[^4] = 0;
            byte[] expected = ComputeSingleSha(data);

            uint* hPt = stackalloc uint[Sha256Fo.UBufferSize];
            uint* wPt = hPt + Sha256Fo.HashStateSize;

            Sha256Fo.Init(hPt);
            int dIndex = 0;
            for (int j = 0; j < dataLen / Sha256Fo.BlockByteSize; j++)
            {
                for (int i = 0; i < 16; i++, dIndex += 4)
                {
                    wPt[i] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
                }

                Sha256Fo.SetW(wPt);
                Sha256Fo.CompressBlockWithWSet(hPt);
            }
            // Final block:
            wPt[0] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            wPt[1] = 0b10000000_00000000_00000000_00000000U;
            for (int i = 2; i < 15; i++)
            {
                wPt[i] = 0;
            }
            wPt[15] = (uint)dataLen * 8;
            Sha256Fo.Compress8260FinalBlock(hPt, 1);
            byte[] actual = Sha256Fo.GetBytes(hPt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void Compress8260FinalBlock_2Test()
        {
            int dataLen = 8260;
            byte[] data = GetRandomBytes(dataLen);
            data[^1] = 2;
            data[^2] = 0;
            data[^3] = 0;
            data[^4] = 0;
            byte[] expected = ComputeSingleSha(data);

            uint* hPt = stackalloc uint[Sha256Fo.UBufferSize];
            uint* wPt = hPt + Sha256Fo.HashStateSize;

            Sha256Fo.Init(hPt);
            int dIndex = 0;
            for (int j = 0; j < dataLen / Sha256Fo.BlockByteSize; j++)
            {
                for (int i = 0; i < 16; i++, dIndex += 4)
                {
                    wPt[i] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
                }

                Sha256Fo.SetW(wPt);
                Sha256Fo.CompressBlockWithWSet(hPt);
            }
            // Final block:
            wPt[0] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            wPt[1] = 0b10000000_00000000_00000000_00000000U;
            for (int i = 2; i < 15; i++)
            {
                wPt[i] = 0;
            }
            wPt[15] = (uint)dataLen * 8;
            Sha256Fo.Compress8260FinalBlock(hPt, 2);
            byte[] actual = Sha256Fo.GetBytes(hPt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void Compress16Test()
        {
            int dataLen = 16;
            byte[] data = GetRandomBytes(dataLen);
            byte[] expected = ComputeSingleSha(data);

            uint* hPt = stackalloc uint[Sha256Fo.UBufferSize];
            uint* wPt = hPt + Sha256Fo.HashStateSize;

            int dIndex = 0;
            for (int i = 0; i < 4; i++, dIndex += 4)
            {
                wPt[i] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            }
            wPt[4] = 0b10000000_00000000_00000000_00000000U;

            wPt[15] = (uint)dataLen * 8;
            Sha256Fo.Init(hPt);
            Sha256Fo.Compress16(hPt);
            byte[] actual = Sha256Fo.GetBytes(hPt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void Compress20Test()
        {
            int dataLen = 20;
            byte[] data = GetRandomBytes(dataLen);
            byte[] expected = ComputeSingleSha(data);

            uint* hPt = stackalloc uint[Sha256Fo.UBufferSize];
            uint* wPt = hPt + Sha256Fo.HashStateSize;

            int dIndex = 0;
            for (int i = 0; i < 5; i++, dIndex += 4)
            {
                wPt[i] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            }
            wPt[5] = 0b10000000_00000000_00000000_00000000U;

            wPt[15] = (uint)dataLen * 8;
            Sha256Fo.Init(hPt);
            Sha256Fo.Compress20(hPt);
            byte[] actual = Sha256Fo.GetBytes(hPt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void Compress22Test()
        {
            int dataLen = 22;
            byte[] data = GetRandomBytes(dataLen);
            byte[] expected = ComputeSingleSha(data);

            uint* hPt = stackalloc uint[Sha256Fo.UBufferSize];
            uint* wPt = hPt + Sha256Fo.HashStateSize;

            int dIndex = 0;
            for (int i = 0; i < 5; i++, dIndex += 4)
            {
                wPt[i] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            }
            wPt[5] = (uint)((data[20] << 24) | (data[21] << 16) | 0b00000000_00000000_10000000_00000000U);

            wPt[15] = (uint)dataLen * 8;
            Sha256Fo.Init(hPt);
            Sha256Fo.Compress22(hPt);
            byte[] actual = Sha256Fo.GetBytes(hPt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void Compress23Test()
        {
            int dataLen = 23;
            byte[] data = GetRandomBytes(dataLen);
            byte[] expected = ComputeSingleSha(data);

            uint* hPt = stackalloc uint[Sha256Fo.UBufferSize];
            uint* wPt = hPt + Sha256Fo.HashStateSize;

            int dIndex = 0;
            for (int i = 0; i < 5; i++, dIndex += 4)
            {
                wPt[i] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            }
            wPt[5] = (uint)((data[20] << 24) | (data[21] << 16) | (data[22] << 8) | 0b00000000_00000000_00000000_10000000U);

            wPt[15] = (uint)dataLen * 8;
            Sha256Fo.Init(hPt);
            Sha256Fo.Compress23(hPt);
            byte[] actual = Sha256Fo.GetBytes(hPt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void Compress24Test()
        {
            int dataLen = 24;
            byte[] data = GetRandomBytes(dataLen);
            byte[] expected = ComputeSingleSha(data);

            uint* hPt = stackalloc uint[Sha256Fo.UBufferSize];
            uint* wPt = hPt + Sha256Fo.HashStateSize;

            int dIndex = 0;
            for (int i = 0; i < 6; i++, dIndex += 4)
            {
                wPt[i] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            }
            wPt[6] = 0b10000000_00000000_00000000_00000000U;

            wPt[15] = (uint)dataLen * 8;
            Sha256Fo.Init(hPt);
            Sha256Fo.Compress24(hPt);
            byte[] actual = Sha256Fo.GetBytes(hPt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void Compress26Test()
        {
            int dataLen = 26;
            byte[] data = GetRandomBytes(dataLen);
            byte[] expected = ComputeSingleSha(data);

            uint* hPt = stackalloc uint[Sha256Fo.UBufferSize];
            uint* wPt = hPt + Sha256Fo.HashStateSize;

            int dIndex = 0;
            for (int i = 0; i < 6; i++, dIndex += 4)
            {
                wPt[i] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            }
            wPt[6] = (uint)data[24] << 24 | (uint)data[25] << 16 | 0b00000000_00000000_10000000_00000000U;

            wPt[15] = (uint)dataLen * 8;
            Sha256Fo.Init(hPt);
            Sha256Fo.Compress26(hPt);
            byte[] actual = Sha256Fo.GetBytes(hPt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void Compress27Test()
        {
            int dataLen = 27;
            byte[] data = GetRandomBytes(dataLen);
            byte[] expected = ComputeSingleSha(data);

            uint* hPt = stackalloc uint[Sha256Fo.UBufferSize];
            uint* wPt = hPt + Sha256Fo.HashStateSize;

            int dIndex = 0;
            for (int i = 0; i < 6; i++, dIndex += 4)
            {
                wPt[i] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            }
            wPt[6] = (uint)data[24] << 24 | (uint)data[25] << 16 | (uint)data[26] << 8 | 0b00000000_00000000_00000000_10000000U;

            wPt[15] = (uint)dataLen * 8;
            Sha256Fo.Init(hPt);
            Sha256Fo.Compress27(hPt);
            byte[] actual = Sha256Fo.GetBytes(hPt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void Compress28Test()
        {
            int dataLen = 28;
            byte[] data = GetRandomBytes(dataLen);
            byte[] expected = ComputeSingleSha(data);

            uint* hPt = stackalloc uint[Sha256Fo.UBufferSize];
            uint* wPt = hPt + Sha256Fo.HashStateSize;

            int dIndex = 0;
            for (int i = 0; i < 7; i++, dIndex += 4)
            {
                wPt[i] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            }
            wPt[7] = 0b10000000_00000000_00000000_00000000U;

            wPt[15] = (uint)dataLen * 8;
            Sha256Fo.Init(hPt);
            Sha256Fo.Compress28(hPt);
            byte[] actual = Sha256Fo.GetBytes(hPt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void Compress30Test()
        {
            int dataLen = 30;
            byte[] data = GetRandomBytes(dataLen);
            byte[] expected = ComputeSingleSha(data);

            uint* hPt = stackalloc uint[Sha256Fo.UBufferSize];
            uint* wPt = hPt + Sha256Fo.HashStateSize;

            int dIndex = 0;
            for (int i = 0; i < 7; i++, dIndex += 4)
            {
                wPt[i] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            }
            wPt[7] = (uint)((data[28] << 24) | (data[29] << 16) | 0b00000000_00000000_10000000_00000000U);

            wPt[15] = (uint)dataLen * 8;
            Sha256Fo.Init(hPt);
            Sha256Fo.Compress30(hPt);
            byte[] actual = Sha256Fo.GetBytes(hPt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void Compress31Test()
        {
            int dataLen = 31;
            byte[] data = GetRandomBytes(dataLen);
            byte[] expected = ComputeSingleSha(data);

            uint* hPt = stackalloc uint[Sha256Fo.UBufferSize];
            uint* wPt = hPt + Sha256Fo.HashStateSize;

            int dIndex = 0;
            for (int i = 0; i < 7; i++, dIndex += 4)
            {
                wPt[i] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            }
            wPt[7] = (uint)((data[28] << 24) | (data[29] << 16) | (data[30] << 8) | 0b00000000_00000000_00000000_10000000U);

            wPt[15] = (uint)dataLen * 8;
            Sha256Fo.Init(hPt);
            Sha256Fo.Compress31(hPt);
            byte[] actual = Sha256Fo.GetBytes(hPt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void Compress32Test()
        {
            int dataLen = 32;
            byte[] data = GetRandomBytes(dataLen);
            byte[] expected = ComputeSingleSha(data);

            uint* hPt = stackalloc uint[Sha256Fo.UBufferSize];
            uint* wPt = hPt + Sha256Fo.HashStateSize;

            int dIndex = 0;
            for (int i = 0; i < 8; i++, dIndex += 4)
            {
                wPt[i] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            }
            wPt[8] = 0b10000000_00000000_00000000_00000000U;

            wPt[15] = (uint)dataLen * 8;
            Sha256Fo.Init(hPt);
            Sha256Fo.Compress32(hPt);
            byte[] actual = Sha256Fo.GetBytes(hPt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void Compress33Test()
        {
            int dataLen = 33;
            byte[] data = GetRandomBytes(dataLen);
            byte[] expected = ComputeSingleSha(data);

            uint* hPt = stackalloc uint[Sha256Fo.UBufferSize];
            uint* wPt = hPt + Sha256Fo.HashStateSize;

            int dIndex = 0;
            for (int i = 0; i < 8; i++, dIndex += 4)
            {
                wPt[i] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            }
            wPt[8] = (uint)data[32] << 24 | 0b00000000_10000000_00000000_00000000U;

            wPt[15] = (uint)dataLen * 8;
            Sha256Fo.Init(hPt);
            Sha256Fo.Compress33(hPt);
            byte[] actual = Sha256Fo.GetBytes(hPt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void Compress65Test()
        {
            int dataLen = 65;
            byte[] data = GetRandomBytes(dataLen);
            byte[] expected = ComputeSingleSha(data);

            uint* hPt = stackalloc uint[Sha256Fo.UBufferSize];
            fixed (byte* dPt = &data[0])
            {
                Sha256Fo.Init(hPt);
                Sha256Fo.Compress65(hPt, dPt);
                byte[] actual = Sha256Fo.GetBytes(hPt);

                Assert.Equal(expected, actual);
            }
        }


        [Fact]
        public unsafe void CompressDouble16Test()
        {
            int dataLen = 16;
            byte[] data = GetRandomBytes(dataLen);
            byte[] expected = ComputeDoubleSha(data);

            uint* hPt = stackalloc uint[Sha256Fo.UBufferSize];
            uint* wPt = hPt + Sha256Fo.HashStateSize;

            int dIndex = 0;
            for (int i = 0; i < 4; i++, dIndex += 4)
            {
                wPt[i] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            }
            wPt[4] = 0b10000000_00000000_00000000_00000000U;
            wPt[15] = (uint)dataLen * 8;
            Sha256Fo.Init(hPt);
            Sha256Fo.CompressDouble16(hPt);
            byte[] actual = Sha256Fo.GetBytes(hPt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void CompressDouble21Test()
        {
            int dataLen = 21;
            byte[] data = GetRandomBytes(dataLen);
            byte[] expected = ComputeDoubleSha(data);

            uint* hPt = stackalloc uint[Sha256Fo.UBufferSize];
            uint* wPt = hPt + Sha256Fo.HashStateSize;

            int dIndex = 0;
            for (int i = 0; i < 5; i++, dIndex += 4)
            {
                wPt[i] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            }
            wPt[5] = (uint)((data[20] << 24) | 0b00000000_10000000_00000000_00000000U);
            wPt[15] = (uint)dataLen * 8;

            Sha256Fo.Init(hPt);
            Sha256Fo.CompressDouble21(hPt);
            byte[] actual = Sha256Fo.GetBytes(hPt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void CompressDouble22Test()
        {
            int dataLen = 22;
            byte[] data = GetRandomBytes(dataLen);
            byte[] expected = ComputeDoubleSha(data);

            uint* hPt = stackalloc uint[Sha256Fo.UBufferSize];
            uint* wPt = hPt + Sha256Fo.HashStateSize;

            int dIndex = 0;
            for (int i = 0; i < 5; i++, dIndex += 4)
            {
                wPt[i] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            }
            wPt[5] = (uint)((data[20] << 24) | (data[21] << 16) | 0b00000000_00000000_10000000_00000000U);
            wPt[15] = (uint)dataLen * 8;

            Sha256Fo.Init(hPt);
            Sha256Fo.CompressDouble22(hPt);
            byte[] actual = Sha256Fo.GetBytes(hPt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void CompressDouble23Test()
        {
            int dataLen = 23;
            byte[] data = GetRandomBytes(dataLen);
            byte[] expected = ComputeDoubleSha(data);

            uint* hPt = stackalloc uint[Sha256Fo.UBufferSize];
            uint* wPt = hPt + Sha256Fo.HashStateSize;

            int dIndex = 0;
            for (int i = 0; i < 5; i++, dIndex += 4)
            {
                wPt[i] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            }
            wPt[5] = (uint)((data[20] << 24) | (data[21] << 16) | (data[22] << 8) | 0b00000000_00000000_00000000_10000000U);
            wPt[15] = (uint)dataLen * 8;

            Sha256Fo.Init(hPt);
            Sha256Fo.CompressDouble23(hPt);
            byte[] actual = Sha256Fo.GetBytes(hPt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void CompressDouble24Test()
        {
            int dataLen = 24;
            byte[] data = GetRandomBytes(dataLen);
            byte[] expected = ComputeDoubleSha(data);

            uint* hPt = stackalloc uint[Sha256Fo.UBufferSize];
            uint* wPt = hPt + Sha256Fo.HashStateSize;

            int dIndex = 0;
            for (int i = 0; i < 6; i++, dIndex += 4)
            {
                wPt[i] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            }
            wPt[6] = 0b10000000_00000000_00000000_00000000U;
            wPt[15] = (uint)dataLen * 8;

            Sha256Fo.Init(hPt);
            Sha256Fo.CompressDouble24(hPt);
            byte[] actual = Sha256Fo.GetBytes(hPt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void CompressDouble32Test()
        {
            int dataLen = 32;
            byte[] data = GetRandomBytes(dataLen);
            byte[] expected = ComputeDoubleSha(data);

            uint* hPt = stackalloc uint[Sha256Fo.UBufferSize];
            uint* wPt = hPt + Sha256Fo.HashStateSize;

            int dIndex = 0;
            for (int i = 0; i < 8; i++, dIndex += 4)
            {
                wPt[i] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            }
            wPt[8] = 0b10000000_00000000_00000000_00000000U;
            wPt[15] = (uint)dataLen * 8;
            Sha256Fo.Init(hPt);
            Sha256Fo.CompressDouble32(hPt);
            byte[] actual = Sha256Fo.GetBytes(hPt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void CompressDouble33Test()
        {
            int dataLen = 33;
            byte[] data = GetRandomBytes(dataLen);
            byte[] expected = ComputeDoubleSha(data);

            uint* hPt = stackalloc uint[Sha256Fo.UBufferSize];
            uint* wPt = hPt + Sha256Fo.HashStateSize;

            int dIndex = 0;
            for (int i = 0; i < 8; i++, dIndex += 4)
            {
                wPt[i] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            }
            wPt[8] = (uint)((data[32] << 24) | 0b00000000_10000000_00000000_00000000U);
            wPt[15] = (uint)dataLen * 8;
            Sha256Fo.Init(hPt);
            Sha256Fo.CompressDouble33(hPt);
            byte[] actual = Sha256Fo.GetBytes(hPt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void CompressDouble34Test()
        {
            int dataLen = 34;
            byte[] data = GetRandomBytes(dataLen);
            byte[] expected = ComputeDoubleSha(data);

            uint* hPt = stackalloc uint[Sha256Fo.UBufferSize];
            uint* wPt = hPt + Sha256Fo.HashStateSize;

            int dIndex = 0;
            for (int i = 0; i < 8; i++, dIndex += 4)
            {
                wPt[i] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            }
            wPt[8] = (uint)((data[32] << 24) | (data[33] << 16) | 0b00000000_00000000_10000000_00000000U);
            wPt[15] = (uint)dataLen * 8;
            Sha256Fo.Init(hPt);
            Sha256Fo.CompressDouble34(hPt);
            byte[] actual = Sha256Fo.GetBytes(hPt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void CompressDouble39Test()
        {
            int dataLen = 39;
            byte[] data = GetRandomBytes(dataLen);
            byte[] expected = ComputeDoubleSha(data);

            uint* hPt = stackalloc uint[Sha256Fo.UBufferSize];
            uint* wPt = hPt + Sha256Fo.HashStateSize;

            int dIndex = 0;
            for (int i = 0; i < 9; i++, dIndex += 4)
            {
                wPt[i] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            }
            wPt[9] = (uint)((data[36] << 24) | (data[37] << 16) | (data[38] << 8) | 0b00000000_00000000_00000000_10000000U);
            wPt[15] = (uint)dataLen * 8;

            Sha256Fo.Init(hPt);
            Sha256Fo.CompressDouble39(hPt);
            byte[] actual = Sha256Fo.GetBytes(hPt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public unsafe void CompressDouble40Test()
        {
            int dataLen = 40;
            byte[] data = GetRandomBytes(dataLen);
            byte[] expected = ComputeDoubleSha(data);

            uint* hPt = stackalloc uint[Sha256Fo.UBufferSize];
            uint* wPt = hPt + Sha256Fo.HashStateSize;

            int dIndex = 0;
            for (int i = 0; i < 10; i++, dIndex += 4)
            {
                wPt[i] = (uint)((data[dIndex] << 24) | (data[dIndex + 1] << 16) | (data[dIndex + 2] << 8) | data[dIndex + 3]);
            }
            wPt[10] = 0b10000000_00000000_00000000_00000000U;
            wPt[15] = (uint)dataLen * 8;

            Sha256Fo.Init(hPt);
            Sha256Fo.CompressDouble40(hPt);
            byte[] actual = Sha256Fo.GetBytes(hPt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public void CompressDouble65Test()
        {
            int dataLen = 65;
            byte[] data = GetRandomBytes(dataLen);
            byte[] expected = ComputeDoubleSha(data);

            byte[] actual = Sha256Fo.CompressDouble65(data);

            Assert.Equal(expected, actual);
        }
    }
}
