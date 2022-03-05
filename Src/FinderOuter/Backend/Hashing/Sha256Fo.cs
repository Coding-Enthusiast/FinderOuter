// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace FinderOuter.Backend.Hashing
{
    /// <summary>
    /// Implementation of 256-bit Secure Hash Algorithm (SHA) base on RFC-6234
    /// <para/> https://tools.ietf.org/html/rfc6234
    /// </summary>
    public static class Sha256Fo
    {
        /// <summary>
        /// Size of the hash result in bytes (=32 bytes).
        /// </summary>
        public const int HashByteSize = 32;
        /// <summary>
        /// Size of the blocks used in each round (=64 bytes).
        /// </summary>
        public const int BlockByteSize = 64;

        public const int HashStateSize = 8;
        public const int WorkingVectorSize = 64;
        /// <summary>
        /// Size of UInt32[] buffer = 72
        /// </summary>
        public const int UBufferSize = HashStateSize + WorkingVectorSize;


        private static readonly uint[] Ks =
        {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };


        public static unsafe byte[] ComputeHash(Span<byte> data)
        {
            uint* pt = stackalloc uint[HashStateSize + WorkingVectorSize];
            Init(pt);
            fixed (byte* dPt = data)
            {
                CompressData(dPt, data.Length, data.Length, pt);
            }
            return GetBytes(pt);
        }

        public static unsafe byte[] ComputeHashTwice(Span<byte> data)
        {
            uint* pt = stackalloc uint[HashStateSize + WorkingVectorSize];
            Init(pt);
            fixed (byte* dPt = data)
            {
                CompressData(dPt, data.Length, data.Length, pt);
                DoSecondHash(pt);
            }
            return GetBytes(pt);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static unsafe void Init(uint* hPt)
        {
            hPt[0] = 0x6a09e667;
            hPt[1] = 0xbb67ae85;
            hPt[2] = 0x3c6ef372;
            hPt[3] = 0xa54ff53a;
            hPt[4] = 0x510e527f;
            hPt[5] = 0x9b05688c;
            hPt[6] = 0x1f83d9ab;
            hPt[7] = 0x5be0cd19;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static unsafe byte[] GetBytes(uint* hPt)
        {
            return new byte[32]
            {
                (byte)(hPt[0] >> 24), (byte)(hPt[0] >> 16), (byte)(hPt[0] >> 8), (byte)hPt[0],
                (byte)(hPt[1] >> 24), (byte)(hPt[1] >> 16), (byte)(hPt[1] >> 8), (byte)hPt[1],
                (byte)(hPt[2] >> 24), (byte)(hPt[2] >> 16), (byte)(hPt[2] >> 8), (byte)hPt[2],
                (byte)(hPt[3] >> 24), (byte)(hPt[3] >> 16), (byte)(hPt[3] >> 8), (byte)hPt[3],
                (byte)(hPt[4] >> 24), (byte)(hPt[4] >> 16), (byte)(hPt[4] >> 8), (byte)hPt[4],
                (byte)(hPt[5] >> 24), (byte)(hPt[5] >> 16), (byte)(hPt[5] >> 8), (byte)hPt[5],
                (byte)(hPt[6] >> 24), (byte)(hPt[6] >> 16), (byte)(hPt[6] >> 8), (byte)hPt[6],
                (byte)(hPt[7] >> 24), (byte)(hPt[7] >> 16), (byte)(hPt[7] >> 8), (byte)hPt[7]
            };
        }


        public static unsafe void CompressData(byte* dPt, int dataLen, int totalLen, uint* pt)
        {
            Span<byte> finalBlock = new byte[64];

            fixed (byte* fPt = &finalBlock[0])
            {
                uint* wPt = pt + HashStateSize;
                int dIndex = 0;
                while (dataLen >= BlockByteSize)
                {
                    for (int i = 0; i < 16; i++, dIndex += 4)
                    {
                        wPt[i] = (uint)((dPt[dIndex] << 24) | (dPt[dIndex + 1] << 16) | (dPt[dIndex + 2] << 8) | dPt[dIndex + 3]);
                    }
                    SetW(wPt);
                    CompressBlockWithWSet(pt);

                    dataLen -= BlockByteSize;
                }

                // Copy the reamaining bytes into a blockSize length buffer so that we can loop through it easily:
                Buffer.MemoryCopy(dPt + dIndex, fPt, finalBlock.Length, dataLen);

                // Append 1 bit followed by zeros. Since we only work with bytes, this is 1 whole byte
                fPt[dataLen] = 0b1000_0000;

                if (dataLen >= 56) // blockSize - pad2.Len = 64 - 8
                {
                    // This means we have an additional block to compress, which we do it here:

                    for (int i = 0, j = 0; i < 16; i++, j += 4)
                    {
                        wPt[i] = (uint)((fPt[j] << 24) | (fPt[j + 1] << 16) | (fPt[j + 2] << 8) | fPt[j + 3]);
                    }
                    SetW(wPt);
                    CompressBlockWithWSet(pt);

                    // Zero out all the items in FinalBlock so it can be reused
                    finalBlock.Clear();
                }

                // Add length in bits as the last 8 bytes of final block in big-endian order
                // See MessageLengthTest in Test project to understand what the following shifts are
                fPt[63] = (byte)(totalLen << 3);
                fPt[62] = (byte)(totalLen >> 5);
                fPt[61] = (byte)(totalLen >> 13);
                fPt[60] = (byte)(totalLen >> 21);
                fPt[59] = (byte)(totalLen >> 29);
                // The remainig 3 bytes are always zero
                // The remaining 56 bytes are already set

                for (int i = 0, j = 0; i < 16; i++, j += 4)
                {
                    wPt[i] = (uint)((fPt[j] << 24) | (fPt[j + 1] << 16) | (fPt[j + 2] << 8) | fPt[j + 3]);
                }
                SetW(wPt);
                CompressBlockWithWSet(pt);
            }
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for the second block of
        /// (data.Length == 62) and (wPt[0] to wPt[14] is set to zero and wPt[15] to 496)
        /// hPt is the result of compressing the previous block and shouldn't change
        /// </summary>
        public static unsafe void Compress62SecondBlock(uint* pt)
        {
            // w0 to w14 = 0
            // w15 = 496
            pt[24] = 0x00000000;
            pt[25] = 0x00c60000;
            pt[26] = 0x00000000;
            pt[27] = 0xc00031fb;
            pt[28] = 0x00000000;
            pt[29] = 0x1ef2980c;
            pt[30] = 0x000001f0;
            pt[31] = 0x1f003001;
            pt[32] = 0x018c0000;
            pt[33] = 0x1e076c6c;
            pt[34] = 0x400095f2;
            pt[35] = 0x5bbc0d18;
            pt[36] = 0x774a0031;
            pt[37] = 0x8739cb9a;
            pt[38] = 0x3f7f780a;
            pt[39] = 0xde2bdef9;
            pt[40] = 0xf12c402b;
            pt[41] = 0xd55af419;
            pt[42] = 0xe7e7d117;
            pt[43] = 0x5c04b8e7;
            pt[44] = 0x57ab7422;
            pt[45] = 0x0a6654ff;
            pt[46] = 0xc08aae86;
            pt[47] = 0xf1420679;
            pt[48] = 0xda7273ec;
            pt[49] = 0x13bb5720;
            pt[50] = 0x4c49a91a;
            pt[51] = 0x60e3f08d;
            pt[52] = 0xba7dbe21;
            pt[53] = 0x9ba73cdf;
            pt[54] = 0xb9834f89;
            pt[55] = 0x8c3e571b;
            pt[56] = 0x670ac0aa;
            pt[57] = 0xca6921b9;
            pt[58] = 0x6c26c8e4;
            pt[59] = 0x5eae6abf;
            pt[60] = 0x1b3027d5;
            pt[61] = 0x7a3b844f;
            pt[62] = 0xd034a12b;
            pt[63] = 0x68ff3fe4;
            pt[64] = 0x00f84d7d;
            pt[65] = 0x4f4ddc16;
            pt[66] = 0xc5081411;
            pt[67] = 0x0d6177c1;
            pt[68] = 0xa0e9299b;
            pt[69] = 0xd898de59;
            pt[70] = 0x87b282d2;
            pt[71] = 0xea0e6a56;

            CompressBlockWithWSet(pt);
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for the second block of
        /// (data.Length == 64) and (wPt[0] is the padding wPt[1] to wPt[14] is set to zero and wPt[15] to 512)
        /// hPt is the result of compressing the previous block and shouldn't change
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public static unsafe void Compress64SecondBlock(uint* pt)
        {
            // w0 = 0b10000000_00000000_00000000_00000000U
            // w1 to w14 = 0
            // w15 = 512
            pt[24] = 0x80000000;
            pt[25] = 0x01400000;
            pt[26] = 0x00205000;
            pt[27] = 0x00005088;
            pt[28] = 0x22000800;
            pt[29] = 0x22550014;
            pt[30] = 0x05089742;
            pt[31] = 0xa0000020;
            pt[32] = 0x5a880000;
            pt[33] = 0x005c9400;
            pt[34] = 0x0016d49d;
            pt[35] = 0xfa801f00;
            pt[36] = 0xd33225d0;
            pt[37] = 0x11675959;
            pt[38] = 0xf6e6bfda;
            pt[39] = 0xb30c1549;
            pt[40] = 0x08b2b050;
            pt[41] = 0x9d7c4c27;
            pt[42] = 0x0ce2a393;
            pt[43] = 0x88e6e1ea;
            pt[44] = 0xa52b4335;
            pt[45] = 0x67a16f49;
            pt[46] = 0xd732016f;
            pt[47] = 0x4eeb2e91;
            pt[48] = 0x5dbf55e5;
            pt[49] = 0x8eee2335;
            pt[50] = 0xe2bc5ec2;
            pt[51] = 0xa83f4394;
            pt[52] = 0x45ad78f7;
            pt[53] = 0x36f3d0cd;
            pt[54] = 0xd99c05e8;
            pt[55] = 0xb0511dc7;
            pt[56] = 0x69bc7ac4;
            pt[57] = 0xbd11375b;
            pt[58] = 0xe3ba71e5;
            pt[59] = 0x3b209ff2;
            pt[60] = 0x18feee17;
            pt[61] = 0xe25ad9e7;
            pt[62] = 0x13375046;
            pt[63] = 0x0515089d;
            pt[64] = 0x4f0d0f04;
            pt[65] = 0x2627484e;
            pt[66] = 0x310128d2;
            pt[67] = 0xc668b434;
            pt[68] = 0x420841cc;
            pt[69] = 0x62d311b8;
            pt[70] = 0xe59ba771;
            pt[71] = 0x85a7a484;

            CompressBlockWithWSet(pt);
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for the second block of
        /// (data.Length == 72) and (wPt[2] is the padding wPt[3] to wPt[14] is set to zero and wPt[15] to 576)
        /// hPt is the result of compressing the previous block and shouldn't change
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public static unsafe void Compress72SecondBlock(uint* pt)
        {
            // w2 = 0b10000000_00000000_00000000_00000000U
            // w3 to w14 = 0
            // w15 = 576
            pt[24] = SSIG0(pt[9]) + pt[8];
            pt[25] = 308813824 + pt[9];
            pt[26] = SSIG1(pt[24]) + 2147483648;
            pt[27] = SSIG1(pt[25]);
            pt[28] = SSIG1(pt[26]);
            pt[29] = SSIG1(pt[27]);
            pt[30] = SSIG1(pt[28]) + 576;
            pt[31] = SSIG1(pt[29]) + pt[24];
            pt[32] = SSIG1(pt[30]) + pt[25];
            pt[33] = SSIG1(pt[31]) + pt[26];
            pt[34] = SSIG1(pt[32]) + pt[27];
            pt[35] = SSIG1(pt[33]) + pt[28];
            pt[36] = SSIG1(pt[34]) + pt[29];
            pt[37] = SSIG1(pt[35]) + pt[30];
            pt[38] = SSIG1(pt[36]) + pt[31] + 2156920908;
            pt[39] = SSIG1(pt[37]) + pt[32] + SSIG0(pt[24]) + 576;
            pt[40] = SSIG1(pt[38]) + pt[33] + SSIG0(pt[25]) + pt[24];
            pt[41] = SSIG1(pt[39]) + pt[34] + SSIG0(pt[26]) + pt[25];
            pt[42] = SSIG1(pt[40]) + pt[35] + SSIG0(pt[27]) + pt[26];
            pt[43] = SSIG1(pt[41]) + pt[36] + SSIG0(pt[28]) + pt[27];
            pt[44] = SSIG1(pt[42]) + pt[37] + SSIG0(pt[29]) + pt[28];
            pt[45] = SSIG1(pt[43]) + pt[38] + SSIG0(pt[30]) + pt[29];
            pt[46] = SSIG1(pt[44]) + pt[39] + SSIG0(pt[31]) + pt[30];
            pt[47] = SSIG1(pt[45]) + pt[40] + SSIG0(pt[32]) + pt[31];
            pt[48] = SSIG1(pt[46]) + pt[41] + SSIG0(pt[33]) + pt[32];
            pt[49] = SSIG1(pt[47]) + pt[42] + SSIG0(pt[34]) + pt[33];
            pt[50] = SSIG1(pt[48]) + pt[43] + SSIG0(pt[35]) + pt[34];
            pt[51] = SSIG1(pt[49]) + pt[44] + SSIG0(pt[36]) + pt[35];
            pt[52] = SSIG1(pt[50]) + pt[45] + SSIG0(pt[37]) + pt[36];
            pt[53] = SSIG1(pt[51]) + pt[46] + SSIG0(pt[38]) + pt[37];
            pt[54] = SSIG1(pt[52]) + pt[47] + SSIG0(pt[39]) + pt[38];
            pt[55] = SSIG1(pt[53]) + pt[48] + SSIG0(pt[40]) + pt[39];
            pt[56] = SSIG1(pt[54]) + pt[49] + SSIG0(pt[41]) + pt[40];
            pt[57] = SSIG1(pt[55]) + pt[50] + SSIG0(pt[42]) + pt[41];
            pt[58] = SSIG1(pt[56]) + pt[51] + SSIG0(pt[43]) + pt[42];
            pt[59] = SSIG1(pt[57]) + pt[52] + SSIG0(pt[44]) + pt[43];
            pt[60] = SSIG1(pt[58]) + pt[53] + SSIG0(pt[45]) + pt[44];
            pt[61] = SSIG1(pt[59]) + pt[54] + SSIG0(pt[46]) + pt[45];
            pt[62] = SSIG1(pt[60]) + pt[55] + SSIG0(pt[47]) + pt[46];
            pt[63] = SSIG1(pt[61]) + pt[56] + SSIG0(pt[48]) + pt[47];
            pt[64] = SSIG1(pt[62]) + pt[57] + SSIG0(pt[49]) + pt[48];
            pt[65] = SSIG1(pt[63]) + pt[58] + SSIG0(pt[50]) + pt[49];
            pt[66] = SSIG1(pt[64]) + pt[59] + SSIG0(pt[51]) + pt[50];
            pt[67] = SSIG1(pt[65]) + pt[60] + SSIG0(pt[52]) + pt[51];
            pt[68] = SSIG1(pt[66]) + pt[61] + SSIG0(pt[53]) + pt[52];
            pt[69] = SSIG1(pt[67]) + pt[62] + SSIG0(pt[54]) + pt[53];
            pt[70] = SSIG1(pt[68]) + pt[63] + SSIG0(pt[55]) + pt[54];
            pt[71] = SSIG1(pt[69]) + pt[64] + SSIG0(pt[56]) + pt[55];

            CompressBlockWithWSet(pt);
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for the second block of
        /// (data.Length == 76) and (wPt[3] is the padding wPt[4] to wPt[14] is set to zero and wPt[15] to 608)
        /// hPt is the result of compressing the previous block and shouldn't change
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public static unsafe void Compress76SecondBlock(uint* pt)
        {
            // w3 = 0b10000000_00000000_00000000_00000000U
            // w4 to w14 = 0
            // w15 = 608
            pt[24] = SSIG0(pt[9]) + pt[8];
            pt[25] = 24903680 + SSIG0(pt[10]) + pt[9];
            pt[26] = SSIG1(pt[24]) + 285220864 + pt[10];
            pt[27] = SSIG1(pt[25]) + 2147483648;
            pt[28] = SSIG1(pt[26]);
            pt[29] = SSIG1(pt[27]);
            pt[30] = SSIG1(pt[28]) + 608;
            pt[31] = SSIG1(pt[29]) + pt[24];
            pt[32] = SSIG1(pt[30]) + pt[25];
            pt[33] = SSIG1(pt[31]) + pt[26];
            pt[34] = SSIG1(pt[32]) + pt[27];
            pt[35] = SSIG1(pt[33]) + pt[28];
            pt[36] = SSIG1(pt[34]) + pt[29];
            pt[37] = SSIG1(pt[35]) + pt[30];
            pt[38] = SSIG1(pt[36]) + pt[31] + 3231187016;
            pt[39] = SSIG1(pt[37]) + pt[32] + SSIG0(pt[24]) + 608;
            pt[40] = SSIG1(pt[38]) + pt[33] + SSIG0(pt[25]) + pt[24];
            pt[41] = SSIG1(pt[39]) + pt[34] + SSIG0(pt[26]) + pt[25];
            pt[42] = SSIG1(pt[40]) + pt[35] + SSIG0(pt[27]) + pt[26];
            pt[43] = SSIG1(pt[41]) + pt[36] + SSIG0(pt[28]) + pt[27];
            pt[44] = SSIG1(pt[42]) + pt[37] + SSIG0(pt[29]) + pt[28];
            pt[45] = SSIG1(pt[43]) + pt[38] + SSIG0(pt[30]) + pt[29];
            pt[46] = SSIG1(pt[44]) + pt[39] + SSIG0(pt[31]) + pt[30];
            pt[47] = SSIG1(pt[45]) + pt[40] + SSIG0(pt[32]) + pt[31];
            pt[48] = SSIG1(pt[46]) + pt[41] + SSIG0(pt[33]) + pt[32];
            pt[49] = SSIG1(pt[47]) + pt[42] + SSIG0(pt[34]) + pt[33];
            pt[50] = SSIG1(pt[48]) + pt[43] + SSIG0(pt[35]) + pt[34];
            pt[51] = SSIG1(pt[49]) + pt[44] + SSIG0(pt[36]) + pt[35];
            pt[52] = SSIG1(pt[50]) + pt[45] + SSIG0(pt[37]) + pt[36];
            pt[53] = SSIG1(pt[51]) + pt[46] + SSIG0(pt[38]) + pt[37];
            pt[54] = SSIG1(pt[52]) + pt[47] + SSIG0(pt[39]) + pt[38];
            pt[55] = SSIG1(pt[53]) + pt[48] + SSIG0(pt[40]) + pt[39];
            pt[56] = SSIG1(pt[54]) + pt[49] + SSIG0(pt[41]) + pt[40];
            pt[57] = SSIG1(pt[55]) + pt[50] + SSIG0(pt[42]) + pt[41];
            pt[58] = SSIG1(pt[56]) + pt[51] + SSIG0(pt[43]) + pt[42];
            pt[59] = SSIG1(pt[57]) + pt[52] + SSIG0(pt[44]) + pt[43];
            pt[60] = SSIG1(pt[58]) + pt[53] + SSIG0(pt[45]) + pt[44];
            pt[61] = SSIG1(pt[59]) + pt[54] + SSIG0(pt[46]) + pt[45];
            pt[62] = SSIG1(pt[60]) + pt[55] + SSIG0(pt[47]) + pt[46];
            pt[63] = SSIG1(pt[61]) + pt[56] + SSIG0(pt[48]) + pt[47];
            pt[64] = SSIG1(pt[62]) + pt[57] + SSIG0(pt[49]) + pt[48];
            pt[65] = SSIG1(pt[63]) + pt[58] + SSIG0(pt[50]) + pt[49];
            pt[66] = SSIG1(pt[64]) + pt[59] + SSIG0(pt[51]) + pt[50];
            pt[67] = SSIG1(pt[65]) + pt[60] + SSIG0(pt[52]) + pt[51];
            pt[68] = SSIG1(pt[66]) + pt[61] + SSIG0(pt[53]) + pt[52];
            pt[69] = SSIG1(pt[67]) + pt[62] + SSIG0(pt[54]) + pt[53];
            pt[70] = SSIG1(pt[68]) + pt[63] + SSIG0(pt[55]) + pt[54];
            pt[71] = SSIG1(pt[69]) + pt[64] + SSIG0(pt[56]) + pt[55];

            CompressBlockWithWSet(pt);
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for the second block of
        /// (data.Length == 80) and (wPt[4] is the padding wPt[5] to wPt[14] is set to zero and wPt[15] to 640)
        /// hPt is the result of compressing the previous block and shouldn't change
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public static unsafe void Compress80SecondBlock(uint* pt)
        {
            // w4 = 0b10000000_00000000_00000000_00000000U
            // w5 to w14 = 0
            // w15 = 640
            pt[24] = SSIG0(pt[9]) + pt[8];
            pt[25] = 17825792 + SSIG0(pt[10]) + pt[9];
            pt[26] = SSIG1(pt[24]) + SSIG0(pt[11]) + pt[10];
            pt[27] = SSIG1(pt[25]) + 285220864 + pt[11];
            pt[28] = SSIG1(pt[26]) + 2147483648;
            pt[29] = SSIG1(pt[27]);
            pt[30] = SSIG1(pt[28]) + 640;
            pt[31] = SSIG1(pt[29]) + pt[24];
            pt[32] = SSIG1(pt[30]) + pt[25];
            pt[33] = SSIG1(pt[31]) + pt[26];
            pt[34] = SSIG1(pt[32]) + pt[27];
            pt[35] = SSIG1(pt[33]) + pt[28];
            pt[36] = SSIG1(pt[34]) + pt[29];
            pt[37] = SSIG1(pt[35]) + pt[30];
            pt[38] = SSIG1(pt[36]) + pt[31] + 10485845;
            pt[39] = SSIG1(pt[37]) + pt[32] + SSIG0(pt[24]) + 640;
            pt[40] = SSIG1(pt[38]) + pt[33] + SSIG0(pt[25]) + pt[24];
            pt[41] = SSIG1(pt[39]) + pt[34] + SSIG0(pt[26]) + pt[25];
            pt[42] = SSIG1(pt[40]) + pt[35] + SSIG0(pt[27]) + pt[26];
            pt[43] = SSIG1(pt[41]) + pt[36] + SSIG0(pt[28]) + pt[27];
            pt[44] = SSIG1(pt[42]) + pt[37] + SSIG0(pt[29]) + pt[28];
            pt[45] = SSIG1(pt[43]) + pt[38] + SSIG0(pt[30]) + pt[29];
            pt[46] = SSIG1(pt[44]) + pt[39] + SSIG0(pt[31]) + pt[30];
            pt[47] = SSIG1(pt[45]) + pt[40] + SSIG0(pt[32]) + pt[31];
            pt[48] = SSIG1(pt[46]) + pt[41] + SSIG0(pt[33]) + pt[32];
            pt[49] = SSIG1(pt[47]) + pt[42] + SSIG0(pt[34]) + pt[33];
            pt[50] = SSIG1(pt[48]) + pt[43] + SSIG0(pt[35]) + pt[34];
            pt[51] = SSIG1(pt[49]) + pt[44] + SSIG0(pt[36]) + pt[35];
            pt[52] = SSIG1(pt[50]) + pt[45] + SSIG0(pt[37]) + pt[36];
            pt[53] = SSIG1(pt[51]) + pt[46] + SSIG0(pt[38]) + pt[37];
            pt[54] = SSIG1(pt[52]) + pt[47] + SSIG0(pt[39]) + pt[38];
            pt[55] = SSIG1(pt[53]) + pt[48] + SSIG0(pt[40]) + pt[39];
            pt[56] = SSIG1(pt[54]) + pt[49] + SSIG0(pt[41]) + pt[40];
            pt[57] = SSIG1(pt[55]) + pt[50] + SSIG0(pt[42]) + pt[41];
            pt[58] = SSIG1(pt[56]) + pt[51] + SSIG0(pt[43]) + pt[42];
            pt[59] = SSIG1(pt[57]) + pt[52] + SSIG0(pt[44]) + pt[43];
            pt[60] = SSIG1(pt[58]) + pt[53] + SSIG0(pt[45]) + pt[44];
            pt[61] = SSIG1(pt[59]) + pt[54] + SSIG0(pt[46]) + pt[45];
            pt[62] = SSIG1(pt[60]) + pt[55] + SSIG0(pt[47]) + pt[46];
            pt[63] = SSIG1(pt[61]) + pt[56] + SSIG0(pt[48]) + pt[47];
            pt[64] = SSIG1(pt[62]) + pt[57] + SSIG0(pt[49]) + pt[48];
            pt[65] = SSIG1(pt[63]) + pt[58] + SSIG0(pt[50]) + pt[49];
            pt[66] = SSIG1(pt[64]) + pt[59] + SSIG0(pt[51]) + pt[50];
            pt[67] = SSIG1(pt[65]) + pt[60] + SSIG0(pt[52]) + pt[51];
            pt[68] = SSIG1(pt[66]) + pt[61] + SSIG0(pt[53]) + pt[52];
            pt[69] = SSIG1(pt[67]) + pt[62] + SSIG0(pt[54]) + pt[53];
            pt[70] = SSIG1(pt[68]) + pt[63] + SSIG0(pt[55]) + pt[54];
            pt[71] = SSIG1(pt[69]) + pt[64] + SSIG0(pt[56]) + pt[55];

            CompressBlockWithWSet(pt);
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for the second block of
        /// (data.Length == 96) and (wPt[8] is the padding wPt[9] to wPt[14] is set to zero and wPt[15] to 768)
        /// hPt is the result of compressing the previous block and shouldn't change
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public static unsafe void Compress96SecondBlock(uint* pt)
        {
            // w8 = 0b10000000_00000000_00000000_00000000U
            // w9 to w14 = 0
            // w15 = 768
            pt[24] = SSIG0(pt[9]) + pt[8];
            pt[25] = 31457280 + SSIG0(pt[10]) + pt[9];
            pt[26] = SSIG1(pt[24]) + SSIG0(pt[11]) + pt[10];
            pt[27] = SSIG1(pt[25]) + SSIG0(pt[12]) + pt[11];
            pt[28] = SSIG1(pt[26]) + SSIG0(pt[13]) + pt[12];
            pt[29] = SSIG1(pt[27]) + SSIG0(pt[14]) + pt[13];
            pt[30] = SSIG1(pt[28]) + 768 + SSIG0(pt[15]) + pt[14];
            pt[31] = SSIG1(pt[29]) + pt[24] + 285220864 + pt[15];
            pt[32] = SSIG1(pt[30]) + pt[25] + 2147483648;
            pt[33] = SSIG1(pt[31]) + pt[26];
            pt[34] = SSIG1(pt[32]) + pt[27];
            pt[35] = SSIG1(pt[33]) + pt[28];
            pt[36] = SSIG1(pt[34]) + pt[29];
            pt[37] = SSIG1(pt[35]) + pt[30];
            pt[38] = SSIG1(pt[36]) + pt[31] + 12583014;
            pt[39] = SSIG1(pt[37]) + pt[32] + SSIG0(pt[24]) + 768;
            pt[40] = SSIG1(pt[38]) + pt[33] + SSIG0(pt[25]) + pt[24];
            pt[41] = SSIG1(pt[39]) + pt[34] + SSIG0(pt[26]) + pt[25];
            pt[42] = SSIG1(pt[40]) + pt[35] + SSIG0(pt[27]) + pt[26];
            pt[43] = SSIG1(pt[41]) + pt[36] + SSIG0(pt[28]) + pt[27];
            pt[44] = SSIG1(pt[42]) + pt[37] + SSIG0(pt[29]) + pt[28];
            pt[45] = SSIG1(pt[43]) + pt[38] + SSIG0(pt[30]) + pt[29];
            pt[46] = SSIG1(pt[44]) + pt[39] + SSIG0(pt[31]) + pt[30];
            pt[47] = SSIG1(pt[45]) + pt[40] + SSIG0(pt[32]) + pt[31];
            pt[48] = SSIG1(pt[46]) + pt[41] + SSIG0(pt[33]) + pt[32];
            pt[49] = SSIG1(pt[47]) + pt[42] + SSIG0(pt[34]) + pt[33];
            pt[50] = SSIG1(pt[48]) + pt[43] + SSIG0(pt[35]) + pt[34];
            pt[51] = SSIG1(pt[49]) + pt[44] + SSIG0(pt[36]) + pt[35];
            pt[52] = SSIG1(pt[50]) + pt[45] + SSIG0(pt[37]) + pt[36];
            pt[53] = SSIG1(pt[51]) + pt[46] + SSIG0(pt[38]) + pt[37];
            pt[54] = SSIG1(pt[52]) + pt[47] + SSIG0(pt[39]) + pt[38];
            pt[55] = SSIG1(pt[53]) + pt[48] + SSIG0(pt[40]) + pt[39];
            pt[56] = SSIG1(pt[54]) + pt[49] + SSIG0(pt[41]) + pt[40];
            pt[57] = SSIG1(pt[55]) + pt[50] + SSIG0(pt[42]) + pt[41];
            pt[58] = SSIG1(pt[56]) + pt[51] + SSIG0(pt[43]) + pt[42];
            pt[59] = SSIG1(pt[57]) + pt[52] + SSIG0(pt[44]) + pt[43];
            pt[60] = SSIG1(pt[58]) + pt[53] + SSIG0(pt[45]) + pt[44];
            pt[61] = SSIG1(pt[59]) + pt[54] + SSIG0(pt[46]) + pt[45];
            pt[62] = SSIG1(pt[60]) + pt[55] + SSIG0(pt[47]) + pt[46];
            pt[63] = SSIG1(pt[61]) + pt[56] + SSIG0(pt[48]) + pt[47];
            pt[64] = SSIG1(pt[62]) + pt[57] + SSIG0(pt[49]) + pt[48];
            pt[65] = SSIG1(pt[63]) + pt[58] + SSIG0(pt[50]) + pt[49];
            pt[66] = SSIG1(pt[64]) + pt[59] + SSIG0(pt[51]) + pt[50];
            pt[67] = SSIG1(pt[65]) + pt[60] + SSIG0(pt[52]) + pt[51];
            pt[68] = SSIG1(pt[66]) + pt[61] + SSIG0(pt[53]) + pt[52];
            pt[69] = SSIG1(pt[67]) + pt[62] + SSIG0(pt[54]) + pt[53];
            pt[70] = SSIG1(pt[68]) + pt[63] + SSIG0(pt[55]) + pt[54];
            pt[71] = SSIG1(pt[69]) + pt[64] + SSIG0(pt[56]) + pt[55];

            CompressBlockWithWSet(pt);
        }



        public static unsafe void Compress196FinalBlock(uint* pt, uint i)
        {
            Debug.Assert(i == 1 || i == 2);

            if (i == 1)
            {
                Compress196FinalBlock_1(pt);
            }
            else
            {
                Compress196FinalBlock_2(pt);
            }
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for the final block of
        /// (data.Length == 8260) and (wPt[0] is 1, wPt[1] is the padding wPt[2] to wPt[14] is set to zero and wPt[15] to 66080)
        /// hPt is the result of compressing the previous block and shouldn't change
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public static unsafe void Compress196FinalBlock_1(uint* pt)
        {
            // w0 = 1
            // w1 = 0b10000000_00000000_00000000_00000000U
            // w2 to w14 = 0
            // w15 = 1568
            pt[24] = 0x11002001;
            pt[25] = 0x83d40001;
            pt[26] = 0x1404eaa8;
            pt[27] = 0x80200490;
            pt[28] = 0xe80409b8;
            pt[29] = 0x02fa5815;
            pt[30] = 0x85d16e20;
            pt[31] = 0x7808bfb5;
            pt[32] = 0x1ec9260a;
            pt[33] = 0x5c36fbd2;
            pt[34] = 0x37e40384;
            pt[35] = 0x8a8871db;
            pt[36] = 0x84b9bc23;
            pt[37] = 0xbcc58429;
            pt[38] = 0xa3455d21;
            pt[39] = 0x998a44c5;
            pt[40] = 0x85d09965;
            pt[41] = 0x8e96b26b;
            pt[42] = 0x2e6cc38a;
            pt[43] = 0x02f3870d;
            pt[44] = 0x5ae956b8;
            pt[45] = 0x63e10168;
            pt[46] = 0xeb15a7ec;
            pt[47] = 0xfcc15025;
            pt[48] = 0x265b2b76;
            pt[49] = 0x1b3f7696;
            pt[50] = 0xe5e6c837;
            pt[51] = 0x73a76f8a;
            pt[52] = 0xcbaa8a44;
            pt[53] = 0x026a1460;
            pt[54] = 0xbd91fdbb;
            pt[55] = 0x068adfa2;
            pt[56] = 0xccaaf58c;
            pt[57] = 0xca162632;
            pt[58] = 0xc1f1dfe4;
            pt[59] = 0xd4d2b9d1;
            pt[60] = 0xce73eaa0;
            pt[61] = 0xdaaa88f7;
            pt[62] = 0x7a41412f;
            pt[63] = 0x011a5d01;
            pt[64] = 0x6c122ad0;
            pt[65] = 0x03cd2aa2;
            pt[66] = 0xcc5400d0;
            pt[67] = 0xa49443b5;
            pt[68] = 0x6be81419;
            pt[69] = 0x45d88c7f;
            pt[70] = 0xba768d31;
            pt[71] = 0x87ad7f56;

            CompressBlockWithWSet(pt);
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for the final block of
        /// (data.Length == 8260) and (wPt[0] is 2, wPt[1] is the padding wPt[2] to wPt[14] is set to zero and wPt[15] to 66080)
        /// hPt is the result of compressing the previous block and shouldn't change
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public static unsafe void Compress196FinalBlock_2(uint* pt)
        {
            // w0 = 2
            // w1 = 0b10000000_00000000_00000000_00000000U
            // w2 to w14 = 0
            // w15 = 66080
            pt[24] = 0x11002002;
            pt[25] = 0x83d40001;
            pt[26] = 0x14050aa8;
            pt[27] = 0x80200490;
            pt[28] = 0x240409c0;
            pt[29] = 0x02fa5815;
            pt[30] = 0x85d11da0;
            pt[31] = 0x7808bfb6;
            pt[32] = 0x31192616;
            pt[33] = 0x5c38fbd2;
            pt[34] = 0x37e59d76;
            pt[35] = 0x86887565;
            pt[36] = 0x80127c7e;
            pt[37] = 0xba10ef28;
            pt[38] = 0x2b215512;
            pt[39] = 0xa97b7aa7;
            pt[40] = 0x00d7fd6a;
            pt[41] = 0x9de9cb04;
            pt[42] = 0xcbc6562e;
            pt[43] = 0x63b0a873;
            pt[44] = 0x7c554502;
            pt[45] = 0x86247fa6;
            pt[46] = 0x85a795c3;
            pt[47] = 0x8cab72b1;
            pt[48] = 0x9947c61f;
            pt[49] = 0x8cfc2489;
            pt[50] = 0x7e063447;
            pt[51] = 0x0bf24ec2;
            pt[52] = 0x60e7e031;
            pt[53] = 0x22eb1fbf;
            pt[54] = 0x48a7e159;
            pt[55] = 0x5a25e117;
            pt[56] = 0x02b1943e;
            pt[57] = 0x3a14c311;
            pt[58] = 0x90febf0d;
            pt[59] = 0x18af655b;
            pt[60] = 0x69a51112;
            pt[61] = 0x9f9c8294;
            pt[62] = 0xb89ee315;
            pt[63] = 0x3e39d32a;
            pt[64] = 0x8cc6f5fb;
            pt[65] = 0xfe27cfa6;
            pt[66] = 0x51f04fa1;
            pt[67] = 0x2a80f4f7;
            pt[68] = 0xecacdf0c;
            pt[69] = 0x844db4c1;
            pt[70] = 0xd8f396e0;
            pt[71] = 0x6d2389d7;

            CompressBlockWithWSet(pt);
        }


        public static unsafe void Compress8260FinalBlock(uint* pt, uint i)
        {
            Debug.Assert(i == 1 || i == 2);

            if (i == 1)
            {
                Compress8260FinalBlock_1(pt);
            }
            else
            {
                Compress8260FinalBlock_2(pt);
            }
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for the final block of
        /// (data.Length == 8260) and (wPt[0] is 1, wPt[1] is the padding wPt[2] to wPt[14] is set to zero and wPt[15] to 66080)
        /// hPt is the result of compressing the previous block and shouldn't change
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public static unsafe void Compress8260FinalBlock_1(uint* pt)
        {
            // w0 = 1
            // w1 = 0b10000000_00000000_00000000_00000000U
            // w2 to w14 = 0
            // w15 = 66080
            pt[24] = 0x11002001;
            pt[25] = 0x21540040;
            pt[26] = 0x1404eaa8;
            pt[27] = 0x80204180;
            pt[28] = 0xe80409b8;
            pt[29] = 0x28d05804;
            pt[30] = 0x85d26a20;
            pt[31] = 0x3808c565;
            pt[32] = 0x99c92709;
            pt[33] = 0x8e1523dc;
            pt[34] = 0x3763cf14;
            pt[35] = 0x1dba5d38;
            pt[36] = 0xc7359db2;
            pt[37] = 0xeb0ece1d;
            pt[38] = 0xb5efddc0;
            pt[39] = 0x60c3f47e;
            pt[40] = 0x39029bf7;
            pt[41] = 0x45632d59;
            pt[42] = 0x51aeeba2;
            pt[43] = 0xa92b652d;
            pt[44] = 0x970e82b1;
            pt[45] = 0x88132a11;
            pt[46] = 0x73e9e088;
            pt[47] = 0xab3d23fa;
            pt[48] = 0x8b9fd00c;
            pt[49] = 0xf2b492d3;
            pt[50] = 0xd7769ffc;
            pt[51] = 0xa9dc7351;
            pt[52] = 0x80adb351;
            pt[53] = 0x77874ee6;
            pt[54] = 0xded63e40;
            pt[55] = 0x8ac57173;
            pt[56] = 0x7607e2b1;
            pt[57] = 0x280ce783;
            pt[58] = 0x9fdac353;
            pt[59] = 0xea78b34c;
            pt[60] = 0x41103d4f;
            pt[61] = 0x1d97d1da;
            pt[62] = 0xc09cd397;
            pt[63] = 0x307e167e;
            pt[64] = 0x443cfeca;
            pt[65] = 0xa14b22f8;
            pt[66] = 0x4d5915e9;
            pt[67] = 0xbfb8540b;
            pt[68] = 0x5846d90d;
            pt[69] = 0x6ec6c4bc;
            pt[70] = 0x711731d8;
            pt[71] = 0x1e552959;

            CompressBlockWithWSet(pt);
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for the final block of
        /// (data.Length == 8260) and (wPt[0] is 2, wPt[1] is the padding wPt[2] to wPt[14] is set to zero and wPt[15] to 66080)
        /// hPt is the result of compressing the previous block and shouldn't change
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public static unsafe void Compress8260FinalBlock_2(uint* pt)
        {
            // w0 = 2
            // w1 = 0b10000000_00000000_00000000_00000000U
            // w2 to w14 = 0
            // w15 = 66080
            pt[24] = 0x11002002;
            pt[25] = 0x21540040;
            pt[26] = 0x14050aa8;
            pt[27] = 0x80204180;
            pt[28] = 0x240409c0;
            pt[29] = 0x28d05804;
            pt[30] = 0x85d219a0;
            pt[31] = 0x3808c566;
            pt[32] = 0x71192715;
            pt[33] = 0x8e16e3dc;
            pt[34] = 0x37949266;
            pt[35] = 0xd1ba5d31;
            pt[36] = 0x04429020;
            pt[37] = 0xeadcd61d;
            pt[38] = 0x52a5f9b3;
            pt[39] = 0x7114a835;
            pt[40] = 0x678a8eb3;
            pt[41] = 0x29eb9469;
            pt[42] = 0xfdba0e2b;
            pt[43] = 0xc3cf1cf7;
            pt[44] = 0x711b714a;
            pt[45] = 0xc1260283;
            pt[46] = 0xc79f796b;
            pt[47] = 0xcdb9703a;
            pt[48] = 0xfed80a99;
            pt[49] = 0x0ffe79cb;
            pt[50] = 0xee5c7184;
            pt[51] = 0x1b3dbe4d;
            pt[52] = 0x8f3b6a74;
            pt[53] = 0x2e03518a;
            pt[54] = 0x478462a0;
            pt[55] = 0xfc7f220c;
            pt[56] = 0x6713c287;
            pt[57] = 0x5987cf1c;
            pt[58] = 0xe2c5f567;
            pt[59] = 0xb81a11f8;
            pt[60] = 0x824cfb37;
            pt[61] = 0x64bdd2e5;
            pt[62] = 0xd71f2d51;
            pt[63] = 0xb685336e;
            pt[64] = 0xd529e091;
            pt[65] = 0x3b31a954;
            pt[66] = 0x69a8a83f;
            pt[67] = 0xa17d486c;
            pt[68] = 0xfafa5836;
            pt[69] = 0x630db00e;
            pt[70] = 0x3420d7dc;
            pt[71] = 0x3254c739;

            CompressBlockWithWSet(pt);
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for
        /// (data.Length == 16) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        public static unsafe void Compress16(uint* pt)
        {
            // w4 = 0b10000000_00000000_00000000_00000000U 
            // w5 to w14 = 0
            // w15 = 128
            pt[24] = SSIG0(pt[9]) + pt[8];
            pt[25] = 5242880 + SSIG0(pt[10]) + pt[9];
            pt[26] = SSIG1(pt[24]) + SSIG0(pt[11]) + pt[10];
            pt[27] = SSIG1(pt[25]) + 285220864 + pt[11];
            pt[28] = SSIG1(pt[26]) + 2147483648;
            pt[29] = SSIG1(pt[27]);
            pt[30] = SSIG1(pt[28]) + 128;
            pt[31] = SSIG1(pt[29]) + pt[24];
            pt[32] = SSIG1(pt[30]) + pt[25];
            pt[33] = SSIG1(pt[31]) + pt[26];
            pt[34] = SSIG1(pt[32]) + pt[27];
            pt[35] = SSIG1(pt[33]) + pt[28];
            pt[36] = SSIG1(pt[34]) + pt[29];
            pt[37] = SSIG1(pt[35]) + pt[30];
            pt[38] = SSIG1(pt[36]) + pt[31] + 2097169;
            pt[39] = SSIG1(pt[37]) + pt[32] + SSIG0(pt[24]) + 128;
            pt[40] = SSIG1(pt[38]) + pt[33] + SSIG0(pt[25]) + pt[24];
            pt[41] = SSIG1(pt[39]) + pt[34] + SSIG0(pt[26]) + pt[25];
            pt[42] = SSIG1(pt[40]) + pt[35] + SSIG0(pt[27]) + pt[26];
            pt[43] = SSIG1(pt[41]) + pt[36] + SSIG0(pt[28]) + pt[27];
            pt[44] = SSIG1(pt[42]) + pt[37] + SSIG0(pt[29]) + pt[28];
            pt[45] = SSIG1(pt[43]) + pt[38] + SSIG0(pt[30]) + pt[29];
            pt[46] = SSIG1(pt[44]) + pt[39] + SSIG0(pt[31]) + pt[30];
            pt[47] = SSIG1(pt[45]) + pt[40] + SSIG0(pt[32]) + pt[31];
            pt[48] = SSIG1(pt[46]) + pt[41] + SSIG0(pt[33]) + pt[32];
            pt[49] = SSIG1(pt[47]) + pt[42] + SSIG0(pt[34]) + pt[33];
            pt[50] = SSIG1(pt[48]) + pt[43] + SSIG0(pt[35]) + pt[34];
            pt[51] = SSIG1(pt[49]) + pt[44] + SSIG0(pt[36]) + pt[35];
            pt[52] = SSIG1(pt[50]) + pt[45] + SSIG0(pt[37]) + pt[36];
            pt[53] = SSIG1(pt[51]) + pt[46] + SSIG0(pt[38]) + pt[37];
            pt[54] = SSIG1(pt[52]) + pt[47] + SSIG0(pt[39]) + pt[38];
            pt[55] = SSIG1(pt[53]) + pt[48] + SSIG0(pt[40]) + pt[39];
            pt[56] = SSIG1(pt[54]) + pt[49] + SSIG0(pt[41]) + pt[40];
            pt[57] = SSIG1(pt[55]) + pt[50] + SSIG0(pt[42]) + pt[41];
            pt[58] = SSIG1(pt[56]) + pt[51] + SSIG0(pt[43]) + pt[42];
            pt[59] = SSIG1(pt[57]) + pt[52] + SSIG0(pt[44]) + pt[43];
            pt[60] = SSIG1(pt[58]) + pt[53] + SSIG0(pt[45]) + pt[44];
            pt[61] = SSIG1(pt[59]) + pt[54] + SSIG0(pt[46]) + pt[45];
            pt[62] = SSIG1(pt[60]) + pt[55] + SSIG0(pt[47]) + pt[46];
            pt[63] = SSIG1(pt[61]) + pt[56] + SSIG0(pt[48]) + pt[47];
            pt[64] = SSIG1(pt[62]) + pt[57] + SSIG0(pt[49]) + pt[48];
            pt[65] = SSIG1(pt[63]) + pt[58] + SSIG0(pt[50]) + pt[49];
            pt[66] = SSIG1(pt[64]) + pt[59] + SSIG0(pt[51]) + pt[50];
            pt[67] = SSIG1(pt[65]) + pt[60] + SSIG0(pt[52]) + pt[51];
            pt[68] = SSIG1(pt[66]) + pt[61] + SSIG0(pt[53]) + pt[52];
            pt[69] = SSIG1(pt[67]) + pt[62] + SSIG0(pt[54]) + pt[53];
            pt[70] = SSIG1(pt[68]) + pt[63] + SSIG0(pt[55]) + pt[54];
            pt[71] = SSIG1(pt[69]) + pt[64] + SSIG0(pt[56]) + pt[55];

            CompressBlockWithWSet(pt);
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for
        /// (data.Length == 20) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        public static unsafe void Compress20(uint* pt)
        {
            // w5 = 0b10000000_00000000_00000000_00000000U 
            // w6 to w14 = 0
            // w15 = 160
            pt[24] = SSIG0(pt[9]) + pt[8];
            pt[25] = 4456448 + SSIG0(pt[10]) + pt[9];
            pt[26] = SSIG1(pt[24]) + SSIG0(pt[11]) + pt[10];
            pt[27] = SSIG1(pt[25]) + SSIG0(pt[12]) + pt[11];
            pt[28] = SSIG1(pt[26]) + 285220864 + pt[12];
            pt[29] = SSIG1(pt[27]) + 2147483648;
            pt[30] = SSIG1(pt[28]) + 160;
            pt[31] = SSIG1(pt[29]) + pt[24];
            pt[32] = SSIG1(pt[30]) + pt[25];
            pt[33] = SSIG1(pt[31]) + pt[26];
            pt[34] = SSIG1(pt[32]) + pt[27];
            pt[35] = SSIG1(pt[33]) + pt[28];
            pt[36] = SSIG1(pt[34]) + pt[29];
            pt[37] = SSIG1(pt[35]) + pt[30];
            pt[38] = SSIG1(pt[36]) + pt[31] + 1076363285;
            pt[39] = SSIG1(pt[37]) + pt[32] + SSIG0(pt[24]) + 160;
            pt[40] = SSIG1(pt[38]) + pt[33] + SSIG0(pt[25]) + pt[24];
            pt[41] = SSIG1(pt[39]) + pt[34] + SSIG0(pt[26]) + pt[25];
            pt[42] = SSIG1(pt[40]) + pt[35] + SSIG0(pt[27]) + pt[26];
            pt[43] = SSIG1(pt[41]) + pt[36] + SSIG0(pt[28]) + pt[27];
            pt[44] = SSIG1(pt[42]) + pt[37] + SSIG0(pt[29]) + pt[28];
            pt[45] = SSIG1(pt[43]) + pt[38] + SSIG0(pt[30]) + pt[29];
            pt[46] = SSIG1(pt[44]) + pt[39] + SSIG0(pt[31]) + pt[30];
            pt[47] = SSIG1(pt[45]) + pt[40] + SSIG0(pt[32]) + pt[31];
            pt[48] = SSIG1(pt[46]) + pt[41] + SSIG0(pt[33]) + pt[32];
            pt[49] = SSIG1(pt[47]) + pt[42] + SSIG0(pt[34]) + pt[33];
            pt[50] = SSIG1(pt[48]) + pt[43] + SSIG0(pt[35]) + pt[34];
            pt[51] = SSIG1(pt[49]) + pt[44] + SSIG0(pt[36]) + pt[35];
            pt[52] = SSIG1(pt[50]) + pt[45] + SSIG0(pt[37]) + pt[36];
            pt[53] = SSIG1(pt[51]) + pt[46] + SSIG0(pt[38]) + pt[37];
            pt[54] = SSIG1(pt[52]) + pt[47] + SSIG0(pt[39]) + pt[38];
            pt[55] = SSIG1(pt[53]) + pt[48] + SSIG0(pt[40]) + pt[39];
            pt[56] = SSIG1(pt[54]) + pt[49] + SSIG0(pt[41]) + pt[40];
            pt[57] = SSIG1(pt[55]) + pt[50] + SSIG0(pt[42]) + pt[41];
            pt[58] = SSIG1(pt[56]) + pt[51] + SSIG0(pt[43]) + pt[42];
            pt[59] = SSIG1(pt[57]) + pt[52] + SSIG0(pt[44]) + pt[43];
            pt[60] = SSIG1(pt[58]) + pt[53] + SSIG0(pt[45]) + pt[44];
            pt[61] = SSIG1(pt[59]) + pt[54] + SSIG0(pt[46]) + pt[45];
            pt[62] = SSIG1(pt[60]) + pt[55] + SSIG0(pt[47]) + pt[46];
            pt[63] = SSIG1(pt[61]) + pt[56] + SSIG0(pt[48]) + pt[47];
            pt[64] = SSIG1(pt[62]) + pt[57] + SSIG0(pt[49]) + pt[48];
            pt[65] = SSIG1(pt[63]) + pt[58] + SSIG0(pt[50]) + pt[49];
            pt[66] = SSIG1(pt[64]) + pt[59] + SSIG0(pt[51]) + pt[50];
            pt[67] = SSIG1(pt[65]) + pt[60] + SSIG0(pt[52]) + pt[51];
            pt[68] = SSIG1(pt[66]) + pt[61] + SSIG0(pt[53]) + pt[52];
            pt[69] = SSIG1(pt[67]) + pt[62] + SSIG0(pt[54]) + pt[53];
            pt[70] = SSIG1(pt[68]) + pt[63] + SSIG0(pt[55]) + pt[54];
            pt[71] = SSIG1(pt[69]) + pt[64] + SSIG0(pt[56]) + pt[55];

            CompressBlockWithWSet(pt);
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for
        /// (data.Length == 22) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        public static unsafe void Compress22(uint* pt)
        {
            // w5 = extra values | 0b00000000_00000000_10000000_00000000U
            // w6 to w14 = 0
            // w15 = 176
            pt[24] = SSIG0(pt[9]) + pt[8];
            pt[25] = 5111808 + SSIG0(pt[10]) + pt[9];
            pt[26] = SSIG1(pt[24]) + SSIG0(pt[11]) + pt[10];
            pt[27] = SSIG1(pt[25]) + SSIG0(pt[12]) + pt[11];
            pt[28] = SSIG1(pt[26]) + SSIG0(pt[13]) + pt[12];
            pt[29] = SSIG1(pt[27]) + pt[13];
            pt[30] = SSIG1(pt[28]) + 176;
            pt[31] = SSIG1(pt[29]) + pt[24];
            pt[32] = SSIG1(pt[30]) + pt[25];
            pt[33] = SSIG1(pt[31]) + pt[26];
            pt[34] = SSIG1(pt[32]) + pt[27];
            pt[35] = SSIG1(pt[33]) + pt[28];
            pt[36] = SSIG1(pt[34]) + pt[29];
            pt[37] = SSIG1(pt[35]) + pt[30];
            pt[38] = SSIG1(pt[36]) + pt[31] + 1613496343;
            pt[39] = SSIG1(pt[37]) + pt[32] + SSIG0(pt[24]) + 176;
            pt[40] = SSIG1(pt[38]) + pt[33] + SSIG0(pt[25]) + pt[24];
            pt[41] = SSIG1(pt[39]) + pt[34] + SSIG0(pt[26]) + pt[25];
            pt[42] = SSIG1(pt[40]) + pt[35] + SSIG0(pt[27]) + pt[26];
            pt[43] = SSIG1(pt[41]) + pt[36] + SSIG0(pt[28]) + pt[27];
            pt[44] = SSIG1(pt[42]) + pt[37] + SSIG0(pt[29]) + pt[28];
            pt[45] = SSIG1(pt[43]) + pt[38] + SSIG0(pt[30]) + pt[29];
            pt[46] = SSIG1(pt[44]) + pt[39] + SSIG0(pt[31]) + pt[30];
            pt[47] = SSIG1(pt[45]) + pt[40] + SSIG0(pt[32]) + pt[31];
            pt[48] = SSIG1(pt[46]) + pt[41] + SSIG0(pt[33]) + pt[32];
            pt[49] = SSIG1(pt[47]) + pt[42] + SSIG0(pt[34]) + pt[33];
            pt[50] = SSIG1(pt[48]) + pt[43] + SSIG0(pt[35]) + pt[34];
            pt[51] = SSIG1(pt[49]) + pt[44] + SSIG0(pt[36]) + pt[35];
            pt[52] = SSIG1(pt[50]) + pt[45] + SSIG0(pt[37]) + pt[36];
            pt[53] = SSIG1(pt[51]) + pt[46] + SSIG0(pt[38]) + pt[37];
            pt[54] = SSIG1(pt[52]) + pt[47] + SSIG0(pt[39]) + pt[38];
            pt[55] = SSIG1(pt[53]) + pt[48] + SSIG0(pt[40]) + pt[39];
            pt[56] = SSIG1(pt[54]) + pt[49] + SSIG0(pt[41]) + pt[40];
            pt[57] = SSIG1(pt[55]) + pt[50] + SSIG0(pt[42]) + pt[41];
            pt[58] = SSIG1(pt[56]) + pt[51] + SSIG0(pt[43]) + pt[42];
            pt[59] = SSIG1(pt[57]) + pt[52] + SSIG0(pt[44]) + pt[43];
            pt[60] = SSIG1(pt[58]) + pt[53] + SSIG0(pt[45]) + pt[44];
            pt[61] = SSIG1(pt[59]) + pt[54] + SSIG0(pt[46]) + pt[45];
            pt[62] = SSIG1(pt[60]) + pt[55] + SSIG0(pt[47]) + pt[46];
            pt[63] = SSIG1(pt[61]) + pt[56] + SSIG0(pt[48]) + pt[47];
            pt[64] = SSIG1(pt[62]) + pt[57] + SSIG0(pt[49]) + pt[48];
            pt[65] = SSIG1(pt[63]) + pt[58] + SSIG0(pt[50]) + pt[49];
            pt[66] = SSIG1(pt[64]) + pt[59] + SSIG0(pt[51]) + pt[50];
            pt[67] = SSIG1(pt[65]) + pt[60] + SSIG0(pt[52]) + pt[51];
            pt[68] = SSIG1(pt[66]) + pt[61] + SSIG0(pt[53]) + pt[52];
            pt[69] = SSIG1(pt[67]) + pt[62] + SSIG0(pt[54]) + pt[53];
            pt[70] = SSIG1(pt[68]) + pt[63] + SSIG0(pt[55]) + pt[54];
            pt[71] = SSIG1(pt[69]) + pt[64] + SSIG0(pt[56]) + pt[55];

            CompressBlockWithWSet(pt);
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for
        /// (data.Length == 23) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        public static unsafe void Compress23(uint* pt)
        {
            // w5 = extra values | 0b00000000_00000000_00000000_10000000U
            // w6 to w14 = 0
            // w15 = 184
            pt[24] = SSIG0(pt[9]) + pt[8];
            pt[25] = 4915200 + SSIG0(pt[10]) + pt[9];
            pt[26] = SSIG1(pt[24]) + SSIG0(pt[11]) + pt[10];
            pt[27] = SSIG1(pt[25]) + SSIG0(pt[12]) + pt[11];
            pt[28] = SSIG1(pt[26]) + SSIG0(pt[13]) + pt[12];
            pt[29] = SSIG1(pt[27]) + pt[13];
            pt[30] = SSIG1(pt[28]) + 184;
            pt[31] = SSIG1(pt[29]) + pt[24];
            pt[32] = SSIG1(pt[30]) + pt[25];
            pt[33] = SSIG1(pt[31]) + pt[26];
            pt[34] = SSIG1(pt[32]) + pt[27];
            pt[35] = SSIG1(pt[33]) + pt[28];
            pt[36] = SSIG1(pt[34]) + pt[29];
            pt[37] = SSIG1(pt[35]) + pt[30];
            pt[38] = SSIG1(pt[36]) + pt[31] + 1882062870;
            pt[39] = SSIG1(pt[37]) + pt[32] + SSIG0(pt[24]) + 184;
            pt[40] = SSIG1(pt[38]) + pt[33] + SSIG0(pt[25]) + pt[24];
            pt[41] = SSIG1(pt[39]) + pt[34] + SSIG0(pt[26]) + pt[25];
            pt[42] = SSIG1(pt[40]) + pt[35] + SSIG0(pt[27]) + pt[26];
            pt[43] = SSIG1(pt[41]) + pt[36] + SSIG0(pt[28]) + pt[27];
            pt[44] = SSIG1(pt[42]) + pt[37] + SSIG0(pt[29]) + pt[28];
            pt[45] = SSIG1(pt[43]) + pt[38] + SSIG0(pt[30]) + pt[29];
            pt[46] = SSIG1(pt[44]) + pt[39] + SSIG0(pt[31]) + pt[30];
            pt[47] = SSIG1(pt[45]) + pt[40] + SSIG0(pt[32]) + pt[31];
            pt[48] = SSIG1(pt[46]) + pt[41] + SSIG0(pt[33]) + pt[32];
            pt[49] = SSIG1(pt[47]) + pt[42] + SSIG0(pt[34]) + pt[33];
            pt[50] = SSIG1(pt[48]) + pt[43] + SSIG0(pt[35]) + pt[34];
            pt[51] = SSIG1(pt[49]) + pt[44] + SSIG0(pt[36]) + pt[35];
            pt[52] = SSIG1(pt[50]) + pt[45] + SSIG0(pt[37]) + pt[36];
            pt[53] = SSIG1(pt[51]) + pt[46] + SSIG0(pt[38]) + pt[37];
            pt[54] = SSIG1(pt[52]) + pt[47] + SSIG0(pt[39]) + pt[38];
            pt[55] = SSIG1(pt[53]) + pt[48] + SSIG0(pt[40]) + pt[39];
            pt[56] = SSIG1(pt[54]) + pt[49] + SSIG0(pt[41]) + pt[40];
            pt[57] = SSIG1(pt[55]) + pt[50] + SSIG0(pt[42]) + pt[41];
            pt[58] = SSIG1(pt[56]) + pt[51] + SSIG0(pt[43]) + pt[42];
            pt[59] = SSIG1(pt[57]) + pt[52] + SSIG0(pt[44]) + pt[43];
            pt[60] = SSIG1(pt[58]) + pt[53] + SSIG0(pt[45]) + pt[44];
            pt[61] = SSIG1(pt[59]) + pt[54] + SSIG0(pt[46]) + pt[45];
            pt[62] = SSIG1(pt[60]) + pt[55] + SSIG0(pt[47]) + pt[46];
            pt[63] = SSIG1(pt[61]) + pt[56] + SSIG0(pt[48]) + pt[47];
            pt[64] = SSIG1(pt[62]) + pt[57] + SSIG0(pt[49]) + pt[48];
            pt[65] = SSIG1(pt[63]) + pt[58] + SSIG0(pt[50]) + pt[49];
            pt[66] = SSIG1(pt[64]) + pt[59] + SSIG0(pt[51]) + pt[50];
            pt[67] = SSIG1(pt[65]) + pt[60] + SSIG0(pt[52]) + pt[51];
            pt[68] = SSIG1(pt[66]) + pt[61] + SSIG0(pt[53]) + pt[52];
            pt[69] = SSIG1(pt[67]) + pt[62] + SSIG0(pt[54]) + pt[53];
            pt[70] = SSIG1(pt[68]) + pt[63] + SSIG0(pt[55]) + pt[54];
            pt[71] = SSIG1(pt[69]) + pt[64] + SSIG0(pt[56]) + pt[55];

            CompressBlockWithWSet(pt);
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for
        /// (data.Length == 24) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        public static unsafe void Compress24(uint* pt)
        {
            // w6 = 0b10000000_00000000_00000000_00000000U 
            // w7 to w14 = 0
            // w15 = 192
            pt[24] = SSIG0(pt[9]) + pt[8];
            pt[25] = 7864320 + SSIG0(pt[10]) + pt[9];
            pt[26] = SSIG1(pt[24]) + SSIG0(pt[11]) + pt[10];
            pt[27] = SSIG1(pt[25]) + SSIG0(pt[12]) + pt[11];
            pt[28] = SSIG1(pt[26]) + SSIG0(pt[13]) + pt[12];
            pt[29] = SSIG1(pt[27]) + 285220864 + pt[13];
            pt[30] = SSIG1(pt[28]) + 192 + 2147483648;
            pt[31] = SSIG1(pt[29]) + pt[24];
            pt[32] = SSIG1(pt[30]) + pt[25];
            pt[33] = SSIG1(pt[31]) + pt[26];
            pt[34] = SSIG1(pt[32]) + pt[27];
            pt[35] = SSIG1(pt[33]) + pt[28];
            pt[36] = SSIG1(pt[34]) + pt[29];
            pt[37] = SSIG1(pt[35]) + pt[30];
            pt[38] = SSIG1(pt[36]) + pt[31] + 2150629401;
            pt[39] = SSIG1(pt[37]) + pt[32] + SSIG0(pt[24]) + 192;
            pt[40] = SSIG1(pt[38]) + pt[33] + SSIG0(pt[25]) + pt[24];
            pt[41] = SSIG1(pt[39]) + pt[34] + SSIG0(pt[26]) + pt[25];
            pt[42] = SSIG1(pt[40]) + pt[35] + SSIG0(pt[27]) + pt[26];
            pt[43] = SSIG1(pt[41]) + pt[36] + SSIG0(pt[28]) + pt[27];
            pt[44] = SSIG1(pt[42]) + pt[37] + SSIG0(pt[29]) + pt[28];
            pt[45] = SSIG1(pt[43]) + pt[38] + SSIG0(pt[30]) + pt[29];
            pt[46] = SSIG1(pt[44]) + pt[39] + SSIG0(pt[31]) + pt[30];
            pt[47] = SSIG1(pt[45]) + pt[40] + SSIG0(pt[32]) + pt[31];
            pt[48] = SSIG1(pt[46]) + pt[41] + SSIG0(pt[33]) + pt[32];
            pt[49] = SSIG1(pt[47]) + pt[42] + SSIG0(pt[34]) + pt[33];
            pt[50] = SSIG1(pt[48]) + pt[43] + SSIG0(pt[35]) + pt[34];
            pt[51] = SSIG1(pt[49]) + pt[44] + SSIG0(pt[36]) + pt[35];
            pt[52] = SSIG1(pt[50]) + pt[45] + SSIG0(pt[37]) + pt[36];
            pt[53] = SSIG1(pt[51]) + pt[46] + SSIG0(pt[38]) + pt[37];
            pt[54] = SSIG1(pt[52]) + pt[47] + SSIG0(pt[39]) + pt[38];
            pt[55] = SSIG1(pt[53]) + pt[48] + SSIG0(pt[40]) + pt[39];
            pt[56] = SSIG1(pt[54]) + pt[49] + SSIG0(pt[41]) + pt[40];
            pt[57] = SSIG1(pt[55]) + pt[50] + SSIG0(pt[42]) + pt[41];
            pt[58] = SSIG1(pt[56]) + pt[51] + SSIG0(pt[43]) + pt[42];
            pt[59] = SSIG1(pt[57]) + pt[52] + SSIG0(pt[44]) + pt[43];
            pt[60] = SSIG1(pt[58]) + pt[53] + SSIG0(pt[45]) + pt[44];
            pt[61] = SSIG1(pt[59]) + pt[54] + SSIG0(pt[46]) + pt[45];
            pt[62] = SSIG1(pt[60]) + pt[55] + SSIG0(pt[47]) + pt[46];
            pt[63] = SSIG1(pt[61]) + pt[56] + SSIG0(pt[48]) + pt[47];
            pt[64] = SSIG1(pt[62]) + pt[57] + SSIG0(pt[49]) + pt[48];
            pt[65] = SSIG1(pt[63]) + pt[58] + SSIG0(pt[50]) + pt[49];
            pt[66] = SSIG1(pt[64]) + pt[59] + SSIG0(pt[51]) + pt[50];
            pt[67] = SSIG1(pt[65]) + pt[60] + SSIG0(pt[52]) + pt[51];
            pt[68] = SSIG1(pt[66]) + pt[61] + SSIG0(pt[53]) + pt[52];
            pt[69] = SSIG1(pt[67]) + pt[62] + SSIG0(pt[54]) + pt[53];
            pt[70] = SSIG1(pt[68]) + pt[63] + SSIG0(pt[55]) + pt[54];
            pt[71] = SSIG1(pt[69]) + pt[64] + SSIG0(pt[56]) + pt[55];

            CompressBlockWithWSet(pt);
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for
        /// (data.Length == 26) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        public static unsafe void Compress26(uint* pt)
        {
            // w6 = extra value | 0b00000000_00000000_10000000_00000000U 
            // w7 to w14 = 0
            // w15 = 208
            pt[24] = SSIG0(pt[9]) + pt[8];
            pt[25] = 7471104 + SSIG0(pt[10]) + pt[9];
            pt[26] = SSIG1(pt[24]) + SSIG0(pt[11]) + pt[10];
            pt[27] = SSIG1(pt[25]) + SSIG0(pt[12]) + pt[11];
            pt[28] = SSIG1(pt[26]) + SSIG0(pt[13]) + pt[12];
            pt[29] = SSIG1(pt[27]) + SSIG0(pt[14]) + pt[13];
            pt[30] = SSIG1(pt[28]) + 208 + pt[14];
            pt[31] = SSIG1(pt[29]) + pt[24];
            pt[32] = SSIG1(pt[30]) + pt[25];
            pt[33] = SSIG1(pt[31]) + pt[26];
            pt[34] = SSIG1(pt[32]) + pt[27];
            pt[35] = SSIG1(pt[33]) + pt[28];
            pt[36] = SSIG1(pt[34]) + pt[29];
            pt[37] = SSIG1(pt[35]) + pt[30];
            pt[38] = SSIG1(pt[36]) + pt[31] + 2687762459;
            pt[39] = SSIG1(pt[37]) + pt[32] + SSIG0(pt[24]) + 208;
            pt[40] = SSIG1(pt[38]) + pt[33] + SSIG0(pt[25]) + pt[24];
            pt[41] = SSIG1(pt[39]) + pt[34] + SSIG0(pt[26]) + pt[25];
            pt[42] = SSIG1(pt[40]) + pt[35] + SSIG0(pt[27]) + pt[26];
            pt[43] = SSIG1(pt[41]) + pt[36] + SSIG0(pt[28]) + pt[27];
            pt[44] = SSIG1(pt[42]) + pt[37] + SSIG0(pt[29]) + pt[28];
            pt[45] = SSIG1(pt[43]) + pt[38] + SSIG0(pt[30]) + pt[29];
            pt[46] = SSIG1(pt[44]) + pt[39] + SSIG0(pt[31]) + pt[30];
            pt[47] = SSIG1(pt[45]) + pt[40] + SSIG0(pt[32]) + pt[31];
            pt[48] = SSIG1(pt[46]) + pt[41] + SSIG0(pt[33]) + pt[32];
            pt[49] = SSIG1(pt[47]) + pt[42] + SSIG0(pt[34]) + pt[33];
            pt[50] = SSIG1(pt[48]) + pt[43] + SSIG0(pt[35]) + pt[34];
            pt[51] = SSIG1(pt[49]) + pt[44] + SSIG0(pt[36]) + pt[35];
            pt[52] = SSIG1(pt[50]) + pt[45] + SSIG0(pt[37]) + pt[36];
            pt[53] = SSIG1(pt[51]) + pt[46] + SSIG0(pt[38]) + pt[37];
            pt[54] = SSIG1(pt[52]) + pt[47] + SSIG0(pt[39]) + pt[38];
            pt[55] = SSIG1(pt[53]) + pt[48] + SSIG0(pt[40]) + pt[39];
            pt[56] = SSIG1(pt[54]) + pt[49] + SSIG0(pt[41]) + pt[40];
            pt[57] = SSIG1(pt[55]) + pt[50] + SSIG0(pt[42]) + pt[41];
            pt[58] = SSIG1(pt[56]) + pt[51] + SSIG0(pt[43]) + pt[42];
            pt[59] = SSIG1(pt[57]) + pt[52] + SSIG0(pt[44]) + pt[43];
            pt[60] = SSIG1(pt[58]) + pt[53] + SSIG0(pt[45]) + pt[44];
            pt[61] = SSIG1(pt[59]) + pt[54] + SSIG0(pt[46]) + pt[45];
            pt[62] = SSIG1(pt[60]) + pt[55] + SSIG0(pt[47]) + pt[46];
            pt[63] = SSIG1(pt[61]) + pt[56] + SSIG0(pt[48]) + pt[47];
            pt[64] = SSIG1(pt[62]) + pt[57] + SSIG0(pt[49]) + pt[48];
            pt[65] = SSIG1(pt[63]) + pt[58] + SSIG0(pt[50]) + pt[49];
            pt[66] = SSIG1(pt[64]) + pt[59] + SSIG0(pt[51]) + pt[50];
            pt[67] = SSIG1(pt[65]) + pt[60] + SSIG0(pt[52]) + pt[51];
            pt[68] = SSIG1(pt[66]) + pt[61] + SSIG0(pt[53]) + pt[52];
            pt[69] = SSIG1(pt[67]) + pt[62] + SSIG0(pt[54]) + pt[53];
            pt[70] = SSIG1(pt[68]) + pt[63] + SSIG0(pt[55]) + pt[54];
            pt[71] = SSIG1(pt[69]) + pt[64] + SSIG0(pt[56]) + pt[55];

            CompressBlockWithWSet(pt);
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for
        /// (data.Length == 27) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        public static unsafe void Compress27(uint* pt)
        {
            // w6 = extra value | 0b00000000_00000000_00000000_10000000U 
            // w7 to w14 = 0
            // w15 = 216
            pt[24] = SSIG0(pt[9]) + pt[8];
            pt[25] = 7798784 + SSIG0(pt[10]) + pt[9];
            pt[26] = SSIG1(pt[24]) + SSIG0(pt[11]) + pt[10];
            pt[27] = SSIG1(pt[25]) + SSIG0(pt[12]) + pt[11];
            pt[28] = SSIG1(pt[26]) + SSIG0(pt[13]) + pt[12];
            pt[29] = SSIG1(pt[27]) + SSIG0(pt[14]) + pt[13];
            pt[30] = SSIG1(pt[28]) + 216 + pt[14];
            pt[31] = SSIG1(pt[29]) + pt[24];
            pt[32] = SSIG1(pt[30]) + pt[25];
            pt[33] = SSIG1(pt[31]) + pt[26];
            pt[34] = SSIG1(pt[32]) + pt[27];
            pt[35] = SSIG1(pt[33]) + pt[28];
            pt[36] = SSIG1(pt[34]) + pt[29];
            pt[37] = SSIG1(pt[35]) + pt[30];
            pt[38] = SSIG1(pt[36]) + pt[31] + 2956328986;
            pt[39] = SSIG1(pt[37]) + pt[32] + SSIG0(pt[24]) + 216;
            pt[40] = SSIG1(pt[38]) + pt[33] + SSIG0(pt[25]) + pt[24];
            pt[41] = SSIG1(pt[39]) + pt[34] + SSIG0(pt[26]) + pt[25];
            pt[42] = SSIG1(pt[40]) + pt[35] + SSIG0(pt[27]) + pt[26];
            pt[43] = SSIG1(pt[41]) + pt[36] + SSIG0(pt[28]) + pt[27];
            pt[44] = SSIG1(pt[42]) + pt[37] + SSIG0(pt[29]) + pt[28];
            pt[45] = SSIG1(pt[43]) + pt[38] + SSIG0(pt[30]) + pt[29];
            pt[46] = SSIG1(pt[44]) + pt[39] + SSIG0(pt[31]) + pt[30];
            pt[47] = SSIG1(pt[45]) + pt[40] + SSIG0(pt[32]) + pt[31];
            pt[48] = SSIG1(pt[46]) + pt[41] + SSIG0(pt[33]) + pt[32];
            pt[49] = SSIG1(pt[47]) + pt[42] + SSIG0(pt[34]) + pt[33];
            pt[50] = SSIG1(pt[48]) + pt[43] + SSIG0(pt[35]) + pt[34];
            pt[51] = SSIG1(pt[49]) + pt[44] + SSIG0(pt[36]) + pt[35];
            pt[52] = SSIG1(pt[50]) + pt[45] + SSIG0(pt[37]) + pt[36];
            pt[53] = SSIG1(pt[51]) + pt[46] + SSIG0(pt[38]) + pt[37];
            pt[54] = SSIG1(pt[52]) + pt[47] + SSIG0(pt[39]) + pt[38];
            pt[55] = SSIG1(pt[53]) + pt[48] + SSIG0(pt[40]) + pt[39];
            pt[56] = SSIG1(pt[54]) + pt[49] + SSIG0(pt[41]) + pt[40];
            pt[57] = SSIG1(pt[55]) + pt[50] + SSIG0(pt[42]) + pt[41];
            pt[58] = SSIG1(pt[56]) + pt[51] + SSIG0(pt[43]) + pt[42];
            pt[59] = SSIG1(pt[57]) + pt[52] + SSIG0(pt[44]) + pt[43];
            pt[60] = SSIG1(pt[58]) + pt[53] + SSIG0(pt[45]) + pt[44];
            pt[61] = SSIG1(pt[59]) + pt[54] + SSIG0(pt[46]) + pt[45];
            pt[62] = SSIG1(pt[60]) + pt[55] + SSIG0(pt[47]) + pt[46];
            pt[63] = SSIG1(pt[61]) + pt[56] + SSIG0(pt[48]) + pt[47];
            pt[64] = SSIG1(pt[62]) + pt[57] + SSIG0(pt[49]) + pt[48];
            pt[65] = SSIG1(pt[63]) + pt[58] + SSIG0(pt[50]) + pt[49];
            pt[66] = SSIG1(pt[64]) + pt[59] + SSIG0(pt[51]) + pt[50];
            pt[67] = SSIG1(pt[65]) + pt[60] + SSIG0(pt[52]) + pt[51];
            pt[68] = SSIG1(pt[66]) + pt[61] + SSIG0(pt[53]) + pt[52];
            pt[69] = SSIG1(pt[67]) + pt[62] + SSIG0(pt[54]) + pt[53];
            pt[70] = SSIG1(pt[68]) + pt[63] + SSIG0(pt[55]) + pt[54];
            pt[71] = SSIG1(pt[69]) + pt[64] + SSIG0(pt[56]) + pt[55];

            CompressBlockWithWSet(pt);
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for
        /// (data.Length == 28) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        public static unsafe void Compress28(uint* pt)
        {
            // w7 = 0b10000000_00000000_00000000_00000000U 
            // w8 to w14 = 0
            // w15 = 224
            pt[24] = SSIG0(pt[9]) + pt[8];
            pt[25] = 7077888 + SSIG0(pt[10]) + pt[9];
            pt[26] = SSIG1(pt[24]) + SSIG0(pt[11]) + pt[10];
            pt[27] = SSIG1(pt[25]) + SSIG0(pt[12]) + pt[11];
            pt[28] = SSIG1(pt[26]) + SSIG0(pt[13]) + pt[12];
            pt[29] = SSIG1(pt[27]) + SSIG0(pt[14]) + pt[13];
            pt[30] = SSIG1(pt[28]) + 285221088 + pt[14];
            pt[31] = SSIG1(pt[29]) + pt[24] + 2147483648;
            pt[32] = SSIG1(pt[30]) + pt[25];
            pt[33] = SSIG1(pt[31]) + pt[26];
            pt[34] = SSIG1(pt[32]) + pt[27];
            pt[35] = SSIG1(pt[33]) + pt[28];
            pt[36] = SSIG1(pt[34]) + pt[29];
            pt[37] = SSIG1(pt[35]) + pt[30];
            pt[38] = SSIG1(pt[36]) + pt[31] + 3224895517;
            pt[39] = SSIG1(pt[37]) + pt[32] + SSIG0(pt[24]) + 224;
            pt[40] = SSIG1(pt[38]) + pt[33] + SSIG0(pt[25]) + pt[24];
            pt[41] = SSIG1(pt[39]) + pt[34] + SSIG0(pt[26]) + pt[25];
            pt[42] = SSIG1(pt[40]) + pt[35] + SSIG0(pt[27]) + pt[26];
            pt[43] = SSIG1(pt[41]) + pt[36] + SSIG0(pt[28]) + pt[27];
            pt[44] = SSIG1(pt[42]) + pt[37] + SSIG0(pt[29]) + pt[28];
            pt[45] = SSIG1(pt[43]) + pt[38] + SSIG0(pt[30]) + pt[29];
            pt[46] = SSIG1(pt[44]) + pt[39] + SSIG0(pt[31]) + pt[30];
            pt[47] = SSIG1(pt[45]) + pt[40] + SSIG0(pt[32]) + pt[31];
            pt[48] = SSIG1(pt[46]) + pt[41] + SSIG0(pt[33]) + pt[32];
            pt[49] = SSIG1(pt[47]) + pt[42] + SSIG0(pt[34]) + pt[33];
            pt[50] = SSIG1(pt[48]) + pt[43] + SSIG0(pt[35]) + pt[34];
            pt[51] = SSIG1(pt[49]) + pt[44] + SSIG0(pt[36]) + pt[35];
            pt[52] = SSIG1(pt[50]) + pt[45] + SSIG0(pt[37]) + pt[36];
            pt[53] = SSIG1(pt[51]) + pt[46] + SSIG0(pt[38]) + pt[37];
            pt[54] = SSIG1(pt[52]) + pt[47] + SSIG0(pt[39]) + pt[38];
            pt[55] = SSIG1(pt[53]) + pt[48] + SSIG0(pt[40]) + pt[39];
            pt[56] = SSIG1(pt[54]) + pt[49] + SSIG0(pt[41]) + pt[40];
            pt[57] = SSIG1(pt[55]) + pt[50] + SSIG0(pt[42]) + pt[41];
            pt[58] = SSIG1(pt[56]) + pt[51] + SSIG0(pt[43]) + pt[42];
            pt[59] = SSIG1(pt[57]) + pt[52] + SSIG0(pt[44]) + pt[43];
            pt[60] = SSIG1(pt[58]) + pt[53] + SSIG0(pt[45]) + pt[44];
            pt[61] = SSIG1(pt[59]) + pt[54] + SSIG0(pt[46]) + pt[45];
            pt[62] = SSIG1(pt[60]) + pt[55] + SSIG0(pt[47]) + pt[46];
            pt[63] = SSIG1(pt[61]) + pt[56] + SSIG0(pt[48]) + pt[47];
            pt[64] = SSIG1(pt[62]) + pt[57] + SSIG0(pt[49]) + pt[48];
            pt[65] = SSIG1(pt[63]) + pt[58] + SSIG0(pt[50]) + pt[49];
            pt[66] = SSIG1(pt[64]) + pt[59] + SSIG0(pt[51]) + pt[50];
            pt[67] = SSIG1(pt[65]) + pt[60] + SSIG0(pt[52]) + pt[51];
            pt[68] = SSIG1(pt[66]) + pt[61] + SSIG0(pt[53]) + pt[52];
            pt[69] = SSIG1(pt[67]) + pt[62] + SSIG0(pt[54]) + pt[53];
            pt[70] = SSIG1(pt[68]) + pt[63] + SSIG0(pt[55]) + pt[54];
            pt[71] = SSIG1(pt[69]) + pt[64] + SSIG0(pt[56]) + pt[55];

            CompressBlockWithWSet(pt);
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for
        /// (data.Length == 31) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        public static unsafe void Compress30(uint* pt)
        {
            // w7 = extra value | 0b00000000_00000000_10000000_00000000U 
            // w8 to w14 = 0
            // w15 = 240
            pt[24] = SSIG0(pt[9]) + pt[8];
            pt[25] = 6684672 + SSIG0(pt[10]) + pt[9];
            pt[26] = SSIG1(pt[24]) + SSIG0(pt[11]) + pt[10];
            pt[27] = SSIG1(pt[25]) + SSIG0(pt[12]) + pt[11];
            pt[28] = SSIG1(pt[26]) + SSIG0(pt[13]) + pt[12];
            pt[29] = SSIG1(pt[27]) + SSIG0(pt[14]) + pt[13];
            pt[30] = SSIG1(pt[28]) + 240 + SSIG0(pt[15]) + pt[14];
            pt[31] = SSIG1(pt[29]) + pt[24] + pt[15];
            pt[32] = SSIG1(pt[30]) + pt[25];
            pt[33] = SSIG1(pt[31]) + pt[26];
            pt[34] = SSIG1(pt[32]) + pt[27];
            pt[35] = SSIG1(pt[33]) + pt[28];
            pt[36] = SSIG1(pt[34]) + pt[29];
            pt[37] = SSIG1(pt[35]) + pt[30];
            pt[38] = SSIG1(pt[36]) + pt[31] + 3762028575;
            pt[39] = SSIG1(pt[37]) + pt[32] + SSIG0(pt[24]) + 240;
            pt[40] = SSIG1(pt[38]) + pt[33] + SSIG0(pt[25]) + pt[24];
            pt[41] = SSIG1(pt[39]) + pt[34] + SSIG0(pt[26]) + pt[25];
            pt[42] = SSIG1(pt[40]) + pt[35] + SSIG0(pt[27]) + pt[26];
            pt[43] = SSIG1(pt[41]) + pt[36] + SSIG0(pt[28]) + pt[27];
            pt[44] = SSIG1(pt[42]) + pt[37] + SSIG0(pt[29]) + pt[28];
            pt[45] = SSIG1(pt[43]) + pt[38] + SSIG0(pt[30]) + pt[29];
            pt[46] = SSIG1(pt[44]) + pt[39] + SSIG0(pt[31]) + pt[30];
            pt[47] = SSIG1(pt[45]) + pt[40] + SSIG0(pt[32]) + pt[31];
            pt[48] = SSIG1(pt[46]) + pt[41] + SSIG0(pt[33]) + pt[32];
            pt[49] = SSIG1(pt[47]) + pt[42] + SSIG0(pt[34]) + pt[33];
            pt[50] = SSIG1(pt[48]) + pt[43] + SSIG0(pt[35]) + pt[34];
            pt[51] = SSIG1(pt[49]) + pt[44] + SSIG0(pt[36]) + pt[35];
            pt[52] = SSIG1(pt[50]) + pt[45] + SSIG0(pt[37]) + pt[36];
            pt[53] = SSIG1(pt[51]) + pt[46] + SSIG0(pt[38]) + pt[37];
            pt[54] = SSIG1(pt[52]) + pt[47] + SSIG0(pt[39]) + pt[38];
            pt[55] = SSIG1(pt[53]) + pt[48] + SSIG0(pt[40]) + pt[39];
            pt[56] = SSIG1(pt[54]) + pt[49] + SSIG0(pt[41]) + pt[40];
            pt[57] = SSIG1(pt[55]) + pt[50] + SSIG0(pt[42]) + pt[41];
            pt[58] = SSIG1(pt[56]) + pt[51] + SSIG0(pt[43]) + pt[42];
            pt[59] = SSIG1(pt[57]) + pt[52] + SSIG0(pt[44]) + pt[43];
            pt[60] = SSIG1(pt[58]) + pt[53] + SSIG0(pt[45]) + pt[44];
            pt[61] = SSIG1(pt[59]) + pt[54] + SSIG0(pt[46]) + pt[45];
            pt[62] = SSIG1(pt[60]) + pt[55] + SSIG0(pt[47]) + pt[46];
            pt[63] = SSIG1(pt[61]) + pt[56] + SSIG0(pt[48]) + pt[47];
            pt[64] = SSIG1(pt[62]) + pt[57] + SSIG0(pt[49]) + pt[48];
            pt[65] = SSIG1(pt[63]) + pt[58] + SSIG0(pt[50]) + pt[49];
            pt[66] = SSIG1(pt[64]) + pt[59] + SSIG0(pt[51]) + pt[50];
            pt[67] = SSIG1(pt[65]) + pt[60] + SSIG0(pt[52]) + pt[51];
            pt[68] = SSIG1(pt[66]) + pt[61] + SSIG0(pt[53]) + pt[52];
            pt[69] = SSIG1(pt[67]) + pt[62] + SSIG0(pt[54]) + pt[53];
            pt[70] = SSIG1(pt[68]) + pt[63] + SSIG0(pt[55]) + pt[54];
            pt[71] = SSIG1(pt[69]) + pt[64] + SSIG0(pt[56]) + pt[55];

            CompressBlockWithWSet(pt);
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for
        /// (data.Length == 31) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        public static unsafe void Compress31(uint* pt)
        {
            // w7 = extra value | 0b00000000_00000000_00000000_10000000U 
            // w8 to w14 = 0
            // w15 = 248
            pt[24] = SSIG0(pt[9]) + pt[8];
            pt[25] = 6488064 + SSIG0(pt[10]) + pt[9];
            pt[26] = SSIG1(pt[24]) + SSIG0(pt[11]) + pt[10];
            pt[27] = SSIG1(pt[25]) + SSIG0(pt[12]) + pt[11];
            pt[28] = SSIG1(pt[26]) + SSIG0(pt[13]) + pt[12];
            pt[29] = SSIG1(pt[27]) + SSIG0(pt[14]) + pt[13];
            pt[30] = SSIG1(pt[28]) + 248 + SSIG0(pt[15]) + pt[14];
            pt[31] = SSIG1(pt[29]) + pt[24] + pt[15];
            pt[32] = SSIG1(pt[30]) + pt[25];
            pt[33] = SSIG1(pt[31]) + pt[26];
            pt[34] = SSIG1(pt[32]) + pt[27];
            pt[35] = SSIG1(pt[33]) + pt[28];
            pt[36] = SSIG1(pt[34]) + pt[29];
            pt[37] = SSIG1(pt[35]) + pt[30];
            pt[38] = SSIG1(pt[36]) + pt[31] + 4030595102;
            pt[39] = SSIG1(pt[37]) + pt[32] + SSIG0(pt[24]) + 248;
            pt[40] = SSIG1(pt[38]) + pt[33] + SSIG0(pt[25]) + pt[24];
            pt[41] = SSIG1(pt[39]) + pt[34] + SSIG0(pt[26]) + pt[25];
            pt[42] = SSIG1(pt[40]) + pt[35] + SSIG0(pt[27]) + pt[26];
            pt[43] = SSIG1(pt[41]) + pt[36] + SSIG0(pt[28]) + pt[27];
            pt[44] = SSIG1(pt[42]) + pt[37] + SSIG0(pt[29]) + pt[28];
            pt[45] = SSIG1(pt[43]) + pt[38] + SSIG0(pt[30]) + pt[29];
            pt[46] = SSIG1(pt[44]) + pt[39] + SSIG0(pt[31]) + pt[30];
            pt[47] = SSIG1(pt[45]) + pt[40] + SSIG0(pt[32]) + pt[31];
            pt[48] = SSIG1(pt[46]) + pt[41] + SSIG0(pt[33]) + pt[32];
            pt[49] = SSIG1(pt[47]) + pt[42] + SSIG0(pt[34]) + pt[33];
            pt[50] = SSIG1(pt[48]) + pt[43] + SSIG0(pt[35]) + pt[34];
            pt[51] = SSIG1(pt[49]) + pt[44] + SSIG0(pt[36]) + pt[35];
            pt[52] = SSIG1(pt[50]) + pt[45] + SSIG0(pt[37]) + pt[36];
            pt[53] = SSIG1(pt[51]) + pt[46] + SSIG0(pt[38]) + pt[37];
            pt[54] = SSIG1(pt[52]) + pt[47] + SSIG0(pt[39]) + pt[38];
            pt[55] = SSIG1(pt[53]) + pt[48] + SSIG0(pt[40]) + pt[39];
            pt[56] = SSIG1(pt[54]) + pt[49] + SSIG0(pt[41]) + pt[40];
            pt[57] = SSIG1(pt[55]) + pt[50] + SSIG0(pt[42]) + pt[41];
            pt[58] = SSIG1(pt[56]) + pt[51] + SSIG0(pt[43]) + pt[42];
            pt[59] = SSIG1(pt[57]) + pt[52] + SSIG0(pt[44]) + pt[43];
            pt[60] = SSIG1(pt[58]) + pt[53] + SSIG0(pt[45]) + pt[44];
            pt[61] = SSIG1(pt[59]) + pt[54] + SSIG0(pt[46]) + pt[45];
            pt[62] = SSIG1(pt[60]) + pt[55] + SSIG0(pt[47]) + pt[46];
            pt[63] = SSIG1(pt[61]) + pt[56] + SSIG0(pt[48]) + pt[47];
            pt[64] = SSIG1(pt[62]) + pt[57] + SSIG0(pt[49]) + pt[48];
            pt[65] = SSIG1(pt[63]) + pt[58] + SSIG0(pt[50]) + pt[49];
            pt[66] = SSIG1(pt[64]) + pt[59] + SSIG0(pt[51]) + pt[50];
            pt[67] = SSIG1(pt[65]) + pt[60] + SSIG0(pt[52]) + pt[51];
            pt[68] = SSIG1(pt[66]) + pt[61] + SSIG0(pt[53]) + pt[52];
            pt[69] = SSIG1(pt[67]) + pt[62] + SSIG0(pt[54]) + pt[53];
            pt[70] = SSIG1(pt[68]) + pt[63] + SSIG0(pt[55]) + pt[54];
            pt[71] = SSIG1(pt[69]) + pt[64] + SSIG0(pt[56]) + pt[55];

            CompressBlockWithWSet(pt);
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for
        /// (data.Length == 32) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        public static unsafe void Compress32(uint* pt)
        {
            // w8 = 0b10000000_00000000_00000000_00000000U 
            // w9 to w14 = 0
            // w15 = 256
            pt[24] = SSIG0(pt[9]) + pt[8];
            pt[25] = 10485760 + SSIG0(pt[10]) + pt[9];
            pt[26] = SSIG1(pt[24]) + SSIG0(pt[11]) + pt[10];
            pt[27] = SSIG1(pt[25]) + SSIG0(pt[12]) + pt[11];
            pt[28] = SSIG1(pt[26]) + SSIG0(pt[13]) + pt[12];
            pt[29] = SSIG1(pt[27]) + SSIG0(pt[14]) + pt[13];
            pt[30] = SSIG1(pt[28]) + 256 + SSIG0(pt[15]) + pt[14];
            pt[31] = SSIG1(pt[29]) + pt[24] + 285220864 + pt[15];
            pt[32] = SSIG1(pt[30]) + pt[25] + 2147483648;
            pt[33] = SSIG1(pt[31]) + pt[26];
            pt[34] = SSIG1(pt[32]) + pt[27];
            pt[35] = SSIG1(pt[33]) + pt[28];
            pt[36] = SSIG1(pt[34]) + pt[29];
            pt[37] = SSIG1(pt[35]) + pt[30];
            pt[38] = SSIG1(pt[36]) + pt[31] + 4194338;
            pt[39] = SSIG1(pt[37]) + pt[32] + SSIG0(pt[24]) + 256;
            pt[40] = SSIG1(pt[38]) + pt[33] + SSIG0(pt[25]) + pt[24];
            pt[41] = SSIG1(pt[39]) + pt[34] + SSIG0(pt[26]) + pt[25];
            pt[42] = SSIG1(pt[40]) + pt[35] + SSIG0(pt[27]) + pt[26];
            pt[43] = SSIG1(pt[41]) + pt[36] + SSIG0(pt[28]) + pt[27];
            pt[44] = SSIG1(pt[42]) + pt[37] + SSIG0(pt[29]) + pt[28];
            pt[45] = SSIG1(pt[43]) + pt[38] + SSIG0(pt[30]) + pt[29];
            pt[46] = SSIG1(pt[44]) + pt[39] + SSIG0(pt[31]) + pt[30];
            pt[47] = SSIG1(pt[45]) + pt[40] + SSIG0(pt[32]) + pt[31];
            pt[48] = SSIG1(pt[46]) + pt[41] + SSIG0(pt[33]) + pt[32];
            pt[49] = SSIG1(pt[47]) + pt[42] + SSIG0(pt[34]) + pt[33];
            pt[50] = SSIG1(pt[48]) + pt[43] + SSIG0(pt[35]) + pt[34];
            pt[51] = SSIG1(pt[49]) + pt[44] + SSIG0(pt[36]) + pt[35];
            pt[52] = SSIG1(pt[50]) + pt[45] + SSIG0(pt[37]) + pt[36];
            pt[53] = SSIG1(pt[51]) + pt[46] + SSIG0(pt[38]) + pt[37];
            pt[54] = SSIG1(pt[52]) + pt[47] + SSIG0(pt[39]) + pt[38];
            pt[55] = SSIG1(pt[53]) + pt[48] + SSIG0(pt[40]) + pt[39];
            pt[56] = SSIG1(pt[54]) + pt[49] + SSIG0(pt[41]) + pt[40];
            pt[57] = SSIG1(pt[55]) + pt[50] + SSIG0(pt[42]) + pt[41];
            pt[58] = SSIG1(pt[56]) + pt[51] + SSIG0(pt[43]) + pt[42];
            pt[59] = SSIG1(pt[57]) + pt[52] + SSIG0(pt[44]) + pt[43];
            pt[60] = SSIG1(pt[58]) + pt[53] + SSIG0(pt[45]) + pt[44];
            pt[61] = SSIG1(pt[59]) + pt[54] + SSIG0(pt[46]) + pt[45];
            pt[62] = SSIG1(pt[60]) + pt[55] + SSIG0(pt[47]) + pt[46];
            pt[63] = SSIG1(pt[61]) + pt[56] + SSIG0(pt[48]) + pt[47];
            pt[64] = SSIG1(pt[62]) + pt[57] + SSIG0(pt[49]) + pt[48];
            pt[65] = SSIG1(pt[63]) + pt[58] + SSIG0(pt[50]) + pt[49];
            pt[66] = SSIG1(pt[64]) + pt[59] + SSIG0(pt[51]) + pt[50];
            pt[67] = SSIG1(pt[65]) + pt[60] + SSIG0(pt[52]) + pt[51];
            pt[68] = SSIG1(pt[66]) + pt[61] + SSIG0(pt[53]) + pt[52];
            pt[69] = SSIG1(pt[67]) + pt[62] + SSIG0(pt[54]) + pt[53];
            pt[70] = SSIG1(pt[68]) + pt[63] + SSIG0(pt[55]) + pt[54];
            pt[71] = SSIG1(pt[69]) + pt[64] + SSIG0(pt[56]) + pt[55];

            CompressBlockWithWSet(pt);
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for
        /// (data.Length == 33) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        public static unsafe void Compress33(uint* pt)
        {
            // w8 = extra value | 0b00000000_10000000_00000000_00000000U 
            // w9 to w14 = 0
            // w15 = 264
            pt[24] = SSIG0(pt[9]) + pt[8];
            pt[25] = 10813440 + SSIG0(pt[10]) + pt[9];
            pt[26] = SSIG1(pt[24]) + SSIG0(pt[11]) + pt[10];
            pt[27] = SSIG1(pt[25]) + SSIG0(pt[12]) + pt[11];
            pt[28] = SSIG1(pt[26]) + SSIG0(pt[13]) + pt[12];
            pt[29] = SSIG1(pt[27]) + SSIG0(pt[14]) + pt[13];
            pt[30] = SSIG1(pt[28]) + 264 + SSIG0(pt[15]) + pt[14];
            pt[31] = SSIG1(pt[29]) + pt[24] + SSIG0(pt[16]) + pt[15];
            pt[32] = SSIG1(pt[30]) + pt[25] + pt[16];
            pt[33] = SSIG1(pt[31]) + pt[26];
            pt[34] = SSIG1(pt[32]) + pt[27];
            pt[35] = SSIG1(pt[33]) + pt[28];
            pt[36] = SSIG1(pt[34]) + pt[29];
            pt[37] = SSIG1(pt[35]) + pt[30];
            pt[38] = SSIG1(pt[36]) + pt[31] + 272760867;
            pt[39] = SSIG1(pt[37]) + pt[32] + SSIG0(pt[24]) + 264;
            pt[40] = SSIG1(pt[38]) + pt[33] + SSIG0(pt[25]) + pt[24];
            pt[41] = SSIG1(pt[39]) + pt[34] + SSIG0(pt[26]) + pt[25];
            pt[42] = SSIG1(pt[40]) + pt[35] + SSIG0(pt[27]) + pt[26];
            pt[43] = SSIG1(pt[41]) + pt[36] + SSIG0(pt[28]) + pt[27];
            pt[44] = SSIG1(pt[42]) + pt[37] + SSIG0(pt[29]) + pt[28];
            pt[45] = SSIG1(pt[43]) + pt[38] + SSIG0(pt[30]) + pt[29];
            pt[46] = SSIG1(pt[44]) + pt[39] + SSIG0(pt[31]) + pt[30];
            pt[47] = SSIG1(pt[45]) + pt[40] + SSIG0(pt[32]) + pt[31];
            pt[48] = SSIG1(pt[46]) + pt[41] + SSIG0(pt[33]) + pt[32];
            pt[49] = SSIG1(pt[47]) + pt[42] + SSIG0(pt[34]) + pt[33];
            pt[50] = SSIG1(pt[48]) + pt[43] + SSIG0(pt[35]) + pt[34];
            pt[51] = SSIG1(pt[49]) + pt[44] + SSIG0(pt[36]) + pt[35];
            pt[52] = SSIG1(pt[50]) + pt[45] + SSIG0(pt[37]) + pt[36];
            pt[53] = SSIG1(pt[51]) + pt[46] + SSIG0(pt[38]) + pt[37];
            pt[54] = SSIG1(pt[52]) + pt[47] + SSIG0(pt[39]) + pt[38];
            pt[55] = SSIG1(pt[53]) + pt[48] + SSIG0(pt[40]) + pt[39];
            pt[56] = SSIG1(pt[54]) + pt[49] + SSIG0(pt[41]) + pt[40];
            pt[57] = SSIG1(pt[55]) + pt[50] + SSIG0(pt[42]) + pt[41];
            pt[58] = SSIG1(pt[56]) + pt[51] + SSIG0(pt[43]) + pt[42];
            pt[59] = SSIG1(pt[57]) + pt[52] + SSIG0(pt[44]) + pt[43];
            pt[60] = SSIG1(pt[58]) + pt[53] + SSIG0(pt[45]) + pt[44];
            pt[61] = SSIG1(pt[59]) + pt[54] + SSIG0(pt[46]) + pt[45];
            pt[62] = SSIG1(pt[60]) + pt[55] + SSIG0(pt[47]) + pt[46];
            pt[63] = SSIG1(pt[61]) + pt[56] + SSIG0(pt[48]) + pt[47];
            pt[64] = SSIG1(pt[62]) + pt[57] + SSIG0(pt[49]) + pt[48];
            pt[65] = SSIG1(pt[63]) + pt[58] + SSIG0(pt[50]) + pt[49];
            pt[66] = SSIG1(pt[64]) + pt[59] + SSIG0(pt[51]) + pt[50];
            pt[67] = SSIG1(pt[65]) + pt[60] + SSIG0(pt[52]) + pt[51];
            pt[68] = SSIG1(pt[66]) + pt[61] + SSIG0(pt[53]) + pt[52];
            pt[69] = SSIG1(pt[67]) + pt[62] + SSIG0(pt[54]) + pt[53];
            pt[70] = SSIG1(pt[68]) + pt[63] + SSIG0(pt[55]) + pt[54];
            pt[71] = SSIG1(pt[69]) + pt[64] + SSIG0(pt[56]) + pt[55];

            CompressBlockWithWSet(pt);
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for
        /// (data.Length == 65) Init() should be already called
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public static unsafe void Compress65(uint* pt, byte* dPt)
        {
            uint* wPt = pt + HashStateSize;
            // Set and compress first block (64 bytes)
            int dIndex = 0;
            for (int i = 0; i < 16; i++, dIndex += 4)
            {
                wPt[i] = (uint)((dPt[dIndex] << 24) | (dPt[dIndex + 1] << 16) | (dPt[dIndex + 2] << 8) | dPt[dIndex + 3]);
            }
            SetW(wPt);
            CompressBlockWithWSet(pt);

            // Set, pad and compress second block (1 byte data -> 64 byte block)
            wPt[0] = (uint)((dPt[dIndex] << 24) | 0b00000000_10000000_00000000_00000000U);
            wPt[1] = 0;
            wPt[2] = 0;
            wPt[3] = 0;
            wPt[4] = 0;
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
            wPt[15] = 520;

            wPt[16] = wPt[0];
            wPt[17] = 21299200;
            wPt[18] = SSIG1(wPt[16]);
            wPt[19] = SSIG1(wPt[17]);
            wPt[20] = SSIG1(wPt[18]);
            wPt[21] = SSIG1(wPt[19]);
            wPt[22] = SSIG1(wPt[20]) + 520;
            wPt[23] = SSIG1(wPt[21]) + wPt[16];
            wPt[24] = SSIG1(wPt[22]) + wPt[17];
            wPt[25] = SSIG1(wPt[23]) + wPt[18];
            wPt[26] = SSIG1(wPt[24]) + wPt[19];
            wPt[27] = SSIG1(wPt[25]) + wPt[20];
            wPt[28] = SSIG1(wPt[26]) + wPt[21];
            wPt[29] = SSIG1(wPt[27]) + wPt[22];
            wPt[30] = SSIG1(wPt[28]) + wPt[23] + 276955205;
            wPt[31] = SSIG1(wPt[29]) + wPt[24] + SSIG0(wPt[16]) + 520;
            wPt[32] = SSIG1(wPt[30]) + wPt[25] + SSIG0(wPt[17]) + wPt[16];
            wPt[33] = SSIG1(wPt[31]) + wPt[26] + SSIG0(wPt[18]) + wPt[17];
            wPt[34] = SSIG1(wPt[32]) + wPt[27] + SSIG0(wPt[19]) + wPt[18];
            wPt[35] = SSIG1(wPt[33]) + wPt[28] + SSIG0(wPt[20]) + wPt[19];
            wPt[36] = SSIG1(wPt[34]) + wPt[29] + SSIG0(wPt[21]) + wPt[20];
            wPt[37] = SSIG1(wPt[35]) + wPt[30] + SSIG0(wPt[22]) + wPt[21];
            wPt[38] = SSIG1(wPt[36]) + wPt[31] + SSIG0(wPt[23]) + wPt[22];
            wPt[39] = SSIG1(wPt[37]) + wPt[32] + SSIG0(wPt[24]) + wPt[23];
            wPt[40] = SSIG1(wPt[38]) + wPt[33] + SSIG0(wPt[25]) + wPt[24];
            wPt[41] = SSIG1(wPt[39]) + wPt[34] + SSIG0(wPt[26]) + wPt[25];
            wPt[42] = SSIG1(wPt[40]) + wPt[35] + SSIG0(wPt[27]) + wPt[26];
            wPt[43] = SSIG1(wPt[41]) + wPt[36] + SSIG0(wPt[28]) + wPt[27];
            wPt[44] = SSIG1(wPt[42]) + wPt[37] + SSIG0(wPt[29]) + wPt[28];
            wPt[45] = SSIG1(wPt[43]) + wPt[38] + SSIG0(wPt[30]) + wPt[29];
            wPt[46] = SSIG1(wPt[44]) + wPt[39] + SSIG0(wPt[31]) + wPt[30];
            wPt[47] = SSIG1(wPt[45]) + wPt[40] + SSIG0(wPt[32]) + wPt[31];
            wPt[48] = SSIG1(wPt[46]) + wPt[41] + SSIG0(wPt[33]) + wPt[32];
            wPt[49] = SSIG1(wPt[47]) + wPt[42] + SSIG0(wPt[34]) + wPt[33];
            wPt[50] = SSIG1(wPt[48]) + wPt[43] + SSIG0(wPt[35]) + wPt[34];
            wPt[51] = SSIG1(wPt[49]) + wPt[44] + SSIG0(wPt[36]) + wPt[35];
            wPt[52] = SSIG1(wPt[50]) + wPt[45] + SSIG0(wPt[37]) + wPt[36];
            wPt[53] = SSIG1(wPt[51]) + wPt[46] + SSIG0(wPt[38]) + wPt[37];
            wPt[54] = SSIG1(wPt[52]) + wPt[47] + SSIG0(wPt[39]) + wPt[38];
            wPt[55] = SSIG1(wPt[53]) + wPt[48] + SSIG0(wPt[40]) + wPt[39];
            wPt[56] = SSIG1(wPt[54]) + wPt[49] + SSIG0(wPt[41]) + wPt[40];
            wPt[57] = SSIG1(wPt[55]) + wPt[50] + SSIG0(wPt[42]) + wPt[41];
            wPt[58] = SSIG1(wPt[56]) + wPt[51] + SSIG0(wPt[43]) + wPt[42];
            wPt[59] = SSIG1(wPt[57]) + wPt[52] + SSIG0(wPt[44]) + wPt[43];
            wPt[60] = SSIG1(wPt[58]) + wPt[53] + SSIG0(wPt[45]) + wPt[44];
            wPt[61] = SSIG1(wPt[59]) + wPt[54] + SSIG0(wPt[46]) + wPt[45];
            wPt[62] = SSIG1(wPt[60]) + wPt[55] + SSIG0(wPt[47]) + wPt[46];
            wPt[63] = SSIG1(wPt[61]) + wPt[56] + SSIG0(wPt[48]) + wPt[47];

            CompressBlockWithWSet(pt);
        }

        /// <summary>
        /// Computes double SHA256 hash for
        /// (data.Length == 16) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// <para/> Note: wPt[5], wPt[6], wPt[7] and wPt[8] must be set to zero on consecutive calls since 
        /// <see cref="DoSecondHash(uint*, uint*)"/> changes them.
        /// </summary>
        public static unsafe void CompressDouble16(uint* pt)
        {
            // w4 = 0b10000000_10000000_00000000_00000000U
            // w5 to w14 = 0
            // w15 = 128
            pt[24] = SSIG0(pt[9]) + pt[8];
            pt[25] = 5242880 + SSIG0(pt[10]) + pt[9];
            pt[26] = SSIG1(pt[24]) + SSIG0(pt[11]) + pt[10];
            pt[27] = SSIG1(pt[25]) + 285220864 + pt[11];
            pt[28] = SSIG1(pt[26]) + 2147483648;
            pt[29] = SSIG1(pt[27]);
            pt[30] = SSIG1(pt[28]) + 128;
            pt[31] = SSIG1(pt[29]) + pt[24];
            pt[32] = SSIG1(pt[30]) + pt[25];
            pt[33] = SSIG1(pt[31]) + pt[26];
            pt[34] = SSIG1(pt[32]) + pt[27];
            pt[35] = SSIG1(pt[33]) + pt[28];
            pt[36] = SSIG1(pt[34]) + pt[29];
            pt[37] = SSIG1(pt[35]) + pt[30];
            pt[38] = SSIG1(pt[36]) + pt[31] + 2097169;
            pt[39] = SSIG1(pt[37]) + pt[32] + SSIG0(pt[24]) + 128;
            pt[40] = SSIG1(pt[38]) + pt[33] + SSIG0(pt[25]) + pt[24];
            pt[41] = SSIG1(pt[39]) + pt[34] + SSIG0(pt[26]) + pt[25];
            pt[42] = SSIG1(pt[40]) + pt[35] + SSIG0(pt[27]) + pt[26];
            pt[43] = SSIG1(pt[41]) + pt[36] + SSIG0(pt[28]) + pt[27];
            pt[44] = SSIG1(pt[42]) + pt[37] + SSIG0(pt[29]) + pt[28];
            pt[45] = SSIG1(pt[43]) + pt[38] + SSIG0(pt[30]) + pt[29];
            pt[46] = SSIG1(pt[44]) + pt[39] + SSIG0(pt[31]) + pt[30];
            pt[47] = SSIG1(pt[45]) + pt[40] + SSIG0(pt[32]) + pt[31];
            pt[48] = SSIG1(pt[46]) + pt[41] + SSIG0(pt[33]) + pt[32];
            pt[49] = SSIG1(pt[47]) + pt[42] + SSIG0(pt[34]) + pt[33];
            pt[50] = SSIG1(pt[48]) + pt[43] + SSIG0(pt[35]) + pt[34];
            pt[51] = SSIG1(pt[49]) + pt[44] + SSIG0(pt[36]) + pt[35];
            pt[52] = SSIG1(pt[50]) + pt[45] + SSIG0(pt[37]) + pt[36];
            pt[53] = SSIG1(pt[51]) + pt[46] + SSIG0(pt[38]) + pt[37];
            pt[54] = SSIG1(pt[52]) + pt[47] + SSIG0(pt[39]) + pt[38];
            pt[55] = SSIG1(pt[53]) + pt[48] + SSIG0(pt[40]) + pt[39];
            pt[56] = SSIG1(pt[54]) + pt[49] + SSIG0(pt[41]) + pt[40];
            pt[57] = SSIG1(pt[55]) + pt[50] + SSIG0(pt[42]) + pt[41];
            pt[58] = SSIG1(pt[56]) + pt[51] + SSIG0(pt[43]) + pt[42];
            pt[59] = SSIG1(pt[57]) + pt[52] + SSIG0(pt[44]) + pt[43];
            pt[60] = SSIG1(pt[58]) + pt[53] + SSIG0(pt[45]) + pt[44];
            pt[61] = SSIG1(pt[59]) + pt[54] + SSIG0(pt[46]) + pt[45];
            pt[62] = SSIG1(pt[60]) + pt[55] + SSIG0(pt[47]) + pt[46];
            pt[63] = SSIG1(pt[61]) + pt[56] + SSIG0(pt[48]) + pt[47];
            pt[64] = SSIG1(pt[62]) + pt[57] + SSIG0(pt[49]) + pt[48];
            pt[65] = SSIG1(pt[63]) + pt[58] + SSIG0(pt[50]) + pt[49];
            pt[66] = SSIG1(pt[64]) + pt[59] + SSIG0(pt[51]) + pt[50];
            pt[67] = SSIG1(pt[65]) + pt[60] + SSIG0(pt[52]) + pt[51];
            pt[68] = SSIG1(pt[66]) + pt[61] + SSIG0(pt[53]) + pt[52];
            pt[69] = SSIG1(pt[67]) + pt[62] + SSIG0(pt[54]) + pt[53];
            pt[70] = SSIG1(pt[68]) + pt[63] + SSIG0(pt[55]) + pt[54];
            pt[71] = SSIG1(pt[69]) + pt[64] + SSIG0(pt[56]) + pt[55];

            CompressBlockWithWSet(pt);

            // Perform second hash
            DoSecondHash(pt);
        }

        /// <summary>
        /// Computes double SHA256 hash for
        /// (data.Length == 21) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// <para/> Note: wPt[6], wPt[7] and wPt[8] must be set to zero on consecutive calls since 
        /// <see cref="DoSecondHash(uint*, uint*)"/> changes them.
        /// </summary>
        public static unsafe void CompressDouble21(uint* pt)
        {
            // w5 = extra values | 0b00000000_10000000_00000000_00000000U
            // w6 to w14 = 0
            // w15 = 168
            pt[24] = SSIG0(pt[9]) + pt[8];
            pt[25] = 4259840 + SSIG0(pt[10]) + pt[9];
            pt[26] = SSIG1(pt[24]) + SSIG0(pt[11]) + pt[10];
            pt[27] = SSIG1(pt[25]) + SSIG0(pt[12]) + pt[11];
            pt[28] = SSIG1(pt[26]) + SSIG0(pt[13]) + pt[12];
            pt[29] = SSIG1(pt[27]) + SSIG0(pt[14]) + pt[13];
            pt[30] = SSIG1(pt[28]) + 168 + pt[14];
            pt[31] = SSIG1(pt[29]) + pt[24];
            pt[32] = SSIG1(pt[30]) + pt[25];
            pt[33] = SSIG1(pt[31]) + pt[26];
            pt[34] = SSIG1(pt[32]) + pt[27];
            pt[35] = SSIG1(pt[33]) + pt[28];
            pt[36] = SSIG1(pt[34]) + pt[29];
            pt[37] = SSIG1(pt[35]) + pt[30];
            pt[38] = SSIG1(pt[36]) + pt[31] + 1344929812;
            pt[39] = SSIG1(pt[37]) + pt[32] + SSIG0(pt[24]) + 168;
            pt[40] = SSIG1(pt[38]) + pt[33] + SSIG0(pt[25]) + pt[24];
            pt[41] = SSIG1(pt[39]) + pt[34] + SSIG0(pt[26]) + pt[25];
            pt[42] = SSIG1(pt[40]) + pt[35] + SSIG0(pt[27]) + pt[26];
            pt[43] = SSIG1(pt[41]) + pt[36] + SSIG0(pt[28]) + pt[27];
            pt[44] = SSIG1(pt[42]) + pt[37] + SSIG0(pt[29]) + pt[28];
            pt[45] = SSIG1(pt[43]) + pt[38] + SSIG0(pt[30]) + pt[29];
            pt[46] = SSIG1(pt[44]) + pt[39] + SSIG0(pt[31]) + pt[30];
            pt[47] = SSIG1(pt[45]) + pt[40] + SSIG0(pt[32]) + pt[31];
            pt[48] = SSIG1(pt[46]) + pt[41] + SSIG0(pt[33]) + pt[32];
            pt[49] = SSIG1(pt[47]) + pt[42] + SSIG0(pt[34]) + pt[33];
            pt[50] = SSIG1(pt[48]) + pt[43] + SSIG0(pt[35]) + pt[34];
            pt[51] = SSIG1(pt[49]) + pt[44] + SSIG0(pt[36]) + pt[35];
            pt[52] = SSIG1(pt[50]) + pt[45] + SSIG0(pt[37]) + pt[36];
            pt[53] = SSIG1(pt[51]) + pt[46] + SSIG0(pt[38]) + pt[37];
            pt[54] = SSIG1(pt[52]) + pt[47] + SSIG0(pt[39]) + pt[38];
            pt[55] = SSIG1(pt[53]) + pt[48] + SSIG0(pt[40]) + pt[39];
            pt[56] = SSIG1(pt[54]) + pt[49] + SSIG0(pt[41]) + pt[40];
            pt[57] = SSIG1(pt[55]) + pt[50] + SSIG0(pt[42]) + pt[41];
            pt[58] = SSIG1(pt[56]) + pt[51] + SSIG0(pt[43]) + pt[42];
            pt[59] = SSIG1(pt[57]) + pt[52] + SSIG0(pt[44]) + pt[43];
            pt[60] = SSIG1(pt[58]) + pt[53] + SSIG0(pt[45]) + pt[44];
            pt[61] = SSIG1(pt[59]) + pt[54] + SSIG0(pt[46]) + pt[45];
            pt[62] = SSIG1(pt[60]) + pt[55] + SSIG0(pt[47]) + pt[46];
            pt[63] = SSIG1(pt[61]) + pt[56] + SSIG0(pt[48]) + pt[47];
            pt[64] = SSIG1(pt[62]) + pt[57] + SSIG0(pt[49]) + pt[48];
            pt[65] = SSIG1(pt[63]) + pt[58] + SSIG0(pt[50]) + pt[49];
            pt[66] = SSIG1(pt[64]) + pt[59] + SSIG0(pt[51]) + pt[50];
            pt[67] = SSIG1(pt[65]) + pt[60] + SSIG0(pt[52]) + pt[51];
            pt[68] = SSIG1(pt[66]) + pt[61] + SSIG0(pt[53]) + pt[52];
            pt[69] = SSIG1(pt[67]) + pt[62] + SSIG0(pt[54]) + pt[53];
            pt[70] = SSIG1(pt[68]) + pt[63] + SSIG0(pt[55]) + pt[54];
            pt[71] = SSIG1(pt[69]) + pt[64] + SSIG0(pt[56]) + pt[55];

            CompressBlockWithWSet(pt);

            // Perform second hash
            DoSecondHash(pt);
        }

        /// <summary>
        /// Computes double SHA256 hash for
        /// (data.Length == 22) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// <para/> Note: wPt[6], wPt[7] and wPt[8] must be set to zero on consecutive calls since 
        /// <see cref="DoSecondHash(uint*, uint*)"/> changes them.
        /// </summary>
        public static unsafe void CompressDouble22(uint* pt)
        {
            // w5 = extra values | 0b00000000_00000000_10000000_00000000U
            // w6 to w14 = 0
            // w15 = 176
            pt[24] = SSIG0(pt[9]) + pt[8];
            pt[25] = 5111808 + SSIG0(pt[10]) + pt[9];
            pt[26] = SSIG1(pt[24]) + SSIG0(pt[11]) + pt[10];
            pt[27] = SSIG1(pt[25]) + SSIG0(pt[12]) + pt[11];
            pt[28] = SSIG1(pt[26]) + SSIG0(pt[13]) + pt[12];
            pt[29] = SSIG1(pt[27]) + pt[13];
            pt[30] = SSIG1(pt[28]) + 176;
            pt[31] = SSIG1(pt[29]) + pt[24];
            pt[32] = SSIG1(pt[30]) + pt[25];
            pt[33] = SSIG1(pt[31]) + pt[26];
            pt[34] = SSIG1(pt[32]) + pt[27];
            pt[35] = SSIG1(pt[33]) + pt[28];
            pt[36] = SSIG1(pt[34]) + pt[29];
            pt[37] = SSIG1(pt[35]) + pt[30];
            pt[38] = SSIG1(pt[36]) + pt[31] + 1613496343;
            pt[39] = SSIG1(pt[37]) + pt[32] + SSIG0(pt[24]) + 176;
            pt[40] = SSIG1(pt[38]) + pt[33] + SSIG0(pt[25]) + pt[24];
            pt[41] = SSIG1(pt[39]) + pt[34] + SSIG0(pt[26]) + pt[25];
            pt[42] = SSIG1(pt[40]) + pt[35] + SSIG0(pt[27]) + pt[26];
            pt[43] = SSIG1(pt[41]) + pt[36] + SSIG0(pt[28]) + pt[27];
            pt[44] = SSIG1(pt[42]) + pt[37] + SSIG0(pt[29]) + pt[28];
            pt[45] = SSIG1(pt[43]) + pt[38] + SSIG0(pt[30]) + pt[29];
            pt[46] = SSIG1(pt[44]) + pt[39] + SSIG0(pt[31]) + pt[30];
            pt[47] = SSIG1(pt[45]) + pt[40] + SSIG0(pt[32]) + pt[31];
            pt[48] = SSIG1(pt[46]) + pt[41] + SSIG0(pt[33]) + pt[32];
            pt[49] = SSIG1(pt[47]) + pt[42] + SSIG0(pt[34]) + pt[33];
            pt[50] = SSIG1(pt[48]) + pt[43] + SSIG0(pt[35]) + pt[34];
            pt[51] = SSIG1(pt[49]) + pt[44] + SSIG0(pt[36]) + pt[35];
            pt[52] = SSIG1(pt[50]) + pt[45] + SSIG0(pt[37]) + pt[36];
            pt[53] = SSIG1(pt[51]) + pt[46] + SSIG0(pt[38]) + pt[37];
            pt[54] = SSIG1(pt[52]) + pt[47] + SSIG0(pt[39]) + pt[38];
            pt[55] = SSIG1(pt[53]) + pt[48] + SSIG0(pt[40]) + pt[39];
            pt[56] = SSIG1(pt[54]) + pt[49] + SSIG0(pt[41]) + pt[40];
            pt[57] = SSIG1(pt[55]) + pt[50] + SSIG0(pt[42]) + pt[41];
            pt[58] = SSIG1(pt[56]) + pt[51] + SSIG0(pt[43]) + pt[42];
            pt[59] = SSIG1(pt[57]) + pt[52] + SSIG0(pt[44]) + pt[43];
            pt[60] = SSIG1(pt[58]) + pt[53] + SSIG0(pt[45]) + pt[44];
            pt[61] = SSIG1(pt[59]) + pt[54] + SSIG0(pt[46]) + pt[45];
            pt[62] = SSIG1(pt[60]) + pt[55] + SSIG0(pt[47]) + pt[46];
            pt[63] = SSIG1(pt[61]) + pt[56] + SSIG0(pt[48]) + pt[47];
            pt[64] = SSIG1(pt[62]) + pt[57] + SSIG0(pt[49]) + pt[48];
            pt[65] = SSIG1(pt[63]) + pt[58] + SSIG0(pt[50]) + pt[49];
            pt[66] = SSIG1(pt[64]) + pt[59] + SSIG0(pt[51]) + pt[50];
            pt[67] = SSIG1(pt[65]) + pt[60] + SSIG0(pt[52]) + pt[51];
            pt[68] = SSIG1(pt[66]) + pt[61] + SSIG0(pt[53]) + pt[52];
            pt[69] = SSIG1(pt[67]) + pt[62] + SSIG0(pt[54]) + pt[53];
            pt[70] = SSIG1(pt[68]) + pt[63] + SSIG0(pt[55]) + pt[54];
            pt[71] = SSIG1(pt[69]) + pt[64] + SSIG0(pt[56]) + pt[55];

            CompressBlockWithWSet(pt);

            // Perform second hash
            DoSecondHash(pt);
        }

        /// <summary>
        /// Computes double SHA256 hash for
        /// (data.Length == 23) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// <para/> Note: wPt[6], wPt[7] and wPt[8] must be set to zero on consecutive calls since 
        /// <see cref="DoSecondHash(uint*, uint*)"/> changes them.
        /// </summary>
        public static unsafe void CompressDouble23(uint* pt)
        {
            // w5 = extra values | 0b00000000_00000000_00000000_10000000U
            // w6 to w14 = 0
            // w15 = 184
            pt[24] = SSIG0(pt[9]) + pt[8];
            pt[25] = 4915200 + SSIG0(pt[10]) + pt[9];
            pt[26] = SSIG1(pt[24]) + SSIG0(pt[11]) + pt[10];
            pt[27] = SSIG1(pt[25]) + SSIG0(pt[12]) + pt[11];
            pt[28] = SSIG1(pt[26]) + SSIG0(pt[13]) + pt[12];
            pt[29] = SSIG1(pt[27]) + pt[13];
            pt[30] = SSIG1(pt[28]) + 184;
            pt[31] = SSIG1(pt[29]) + pt[24];
            pt[32] = SSIG1(pt[30]) + pt[25];
            pt[33] = SSIG1(pt[31]) + pt[26];
            pt[34] = SSIG1(pt[32]) + pt[27];
            pt[35] = SSIG1(pt[33]) + pt[28];
            pt[36] = SSIG1(pt[34]) + pt[29];
            pt[37] = SSIG1(pt[35]) + pt[30];
            pt[38] = SSIG1(pt[36]) + pt[31] + 1882062870;
            pt[39] = SSIG1(pt[37]) + pt[32] + SSIG0(pt[24]) + 184;
            pt[40] = SSIG1(pt[38]) + pt[33] + SSIG0(pt[25]) + pt[24];
            pt[41] = SSIG1(pt[39]) + pt[34] + SSIG0(pt[26]) + pt[25];
            pt[42] = SSIG1(pt[40]) + pt[35] + SSIG0(pt[27]) + pt[26];
            pt[43] = SSIG1(pt[41]) + pt[36] + SSIG0(pt[28]) + pt[27];
            pt[44] = SSIG1(pt[42]) + pt[37] + SSIG0(pt[29]) + pt[28];
            pt[45] = SSIG1(pt[43]) + pt[38] + SSIG0(pt[30]) + pt[29];
            pt[46] = SSIG1(pt[44]) + pt[39] + SSIG0(pt[31]) + pt[30];
            pt[47] = SSIG1(pt[45]) + pt[40] + SSIG0(pt[32]) + pt[31];
            pt[48] = SSIG1(pt[46]) + pt[41] + SSIG0(pt[33]) + pt[32];
            pt[49] = SSIG1(pt[47]) + pt[42] + SSIG0(pt[34]) + pt[33];
            pt[50] = SSIG1(pt[48]) + pt[43] + SSIG0(pt[35]) + pt[34];
            pt[51] = SSIG1(pt[49]) + pt[44] + SSIG0(pt[36]) + pt[35];
            pt[52] = SSIG1(pt[50]) + pt[45] + SSIG0(pt[37]) + pt[36];
            pt[53] = SSIG1(pt[51]) + pt[46] + SSIG0(pt[38]) + pt[37];
            pt[54] = SSIG1(pt[52]) + pt[47] + SSIG0(pt[39]) + pt[38];
            pt[55] = SSIG1(pt[53]) + pt[48] + SSIG0(pt[40]) + pt[39];
            pt[56] = SSIG1(pt[54]) + pt[49] + SSIG0(pt[41]) + pt[40];
            pt[57] = SSIG1(pt[55]) + pt[50] + SSIG0(pt[42]) + pt[41];
            pt[58] = SSIG1(pt[56]) + pt[51] + SSIG0(pt[43]) + pt[42];
            pt[59] = SSIG1(pt[57]) + pt[52] + SSIG0(pt[44]) + pt[43];
            pt[60] = SSIG1(pt[58]) + pt[53] + SSIG0(pt[45]) + pt[44];
            pt[61] = SSIG1(pt[59]) + pt[54] + SSIG0(pt[46]) + pt[45];
            pt[62] = SSIG1(pt[60]) + pt[55] + SSIG0(pt[47]) + pt[46];
            pt[63] = SSIG1(pt[61]) + pt[56] + SSIG0(pt[48]) + pt[47];
            pt[64] = SSIG1(pt[62]) + pt[57] + SSIG0(pt[49]) + pt[48];
            pt[65] = SSIG1(pt[63]) + pt[58] + SSIG0(pt[50]) + pt[49];
            pt[66] = SSIG1(pt[64]) + pt[59] + SSIG0(pt[51]) + pt[50];
            pt[67] = SSIG1(pt[65]) + pt[60] + SSIG0(pt[52]) + pt[51];
            pt[68] = SSIG1(pt[66]) + pt[61] + SSIG0(pt[53]) + pt[52];
            pt[69] = SSIG1(pt[67]) + pt[62] + SSIG0(pt[54]) + pt[53];
            pt[70] = SSIG1(pt[68]) + pt[63] + SSIG0(pt[55]) + pt[54];
            pt[71] = SSIG1(pt[69]) + pt[64] + SSIG0(pt[56]) + pt[55];

            CompressBlockWithWSet(pt);

            // Perform second hash
            DoSecondHash(pt);
        }

        /// <summary>
        /// Computes double SHA256 hash for
        /// (data.Length == 24) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// <para/> Note: wPt[6], wPt[7] and wPt[8] must be set to zero on consecutive calls since 
        /// <see cref="DoSecondHash(uint*, uint*)"/> changes them.
        /// </summary>
        public static unsafe void CompressDouble24(uint* pt)
        {
            // w6 = extra values | 0b10000000_00000000_00000000_00000000U
            // w7 to w14 = 0
            // w15 = 192
            pt[24] = SSIG0(pt[9]) + pt[8];
            pt[25] = 7864320 + SSIG0(pt[10]) + pt[9];
            pt[26] = SSIG1(pt[24]) + SSIG0(pt[11]) + pt[10];
            pt[27] = SSIG1(pt[25]) + SSIG0(pt[12]) + pt[11];
            pt[28] = SSIG1(pt[26]) + SSIG0(pt[13]) + pt[12];
            pt[29] = SSIG1(pt[27]) + 285220864 + pt[13];
            pt[30] = SSIG1(pt[28]) + 192 + 2147483648;
            pt[31] = SSIG1(pt[29]) + pt[24];
            pt[32] = SSIG1(pt[30]) + pt[25];
            pt[33] = SSIG1(pt[31]) + pt[26];
            pt[34] = SSIG1(pt[32]) + pt[27];
            pt[35] = SSIG1(pt[33]) + pt[28];
            pt[36] = SSIG1(pt[34]) + pt[29];
            pt[37] = SSIG1(pt[35]) + pt[30];
            pt[38] = SSIG1(pt[36]) + pt[31] + 2150629401;
            pt[39] = SSIG1(pt[37]) + pt[32] + SSIG0(pt[24]) + 192;
            pt[40] = SSIG1(pt[38]) + pt[33] + SSIG0(pt[25]) + pt[24];
            pt[41] = SSIG1(pt[39]) + pt[34] + SSIG0(pt[26]) + pt[25];
            pt[42] = SSIG1(pt[40]) + pt[35] + SSIG0(pt[27]) + pt[26];
            pt[43] = SSIG1(pt[41]) + pt[36] + SSIG0(pt[28]) + pt[27];
            pt[44] = SSIG1(pt[42]) + pt[37] + SSIG0(pt[29]) + pt[28];
            pt[45] = SSIG1(pt[43]) + pt[38] + SSIG0(pt[30]) + pt[29];
            pt[46] = SSIG1(pt[44]) + pt[39] + SSIG0(pt[31]) + pt[30];
            pt[47] = SSIG1(pt[45]) + pt[40] + SSIG0(pt[32]) + pt[31];
            pt[48] = SSIG1(pt[46]) + pt[41] + SSIG0(pt[33]) + pt[32];
            pt[49] = SSIG1(pt[47]) + pt[42] + SSIG0(pt[34]) + pt[33];
            pt[50] = SSIG1(pt[48]) + pt[43] + SSIG0(pt[35]) + pt[34];
            pt[51] = SSIG1(pt[49]) + pt[44] + SSIG0(pt[36]) + pt[35];
            pt[52] = SSIG1(pt[50]) + pt[45] + SSIG0(pt[37]) + pt[36];
            pt[53] = SSIG1(pt[51]) + pt[46] + SSIG0(pt[38]) + pt[37];
            pt[54] = SSIG1(pt[52]) + pt[47] + SSIG0(pt[39]) + pt[38];
            pt[55] = SSIG1(pt[53]) + pt[48] + SSIG0(pt[40]) + pt[39];
            pt[56] = SSIG1(pt[54]) + pt[49] + SSIG0(pt[41]) + pt[40];
            pt[57] = SSIG1(pt[55]) + pt[50] + SSIG0(pt[42]) + pt[41];
            pt[58] = SSIG1(pt[56]) + pt[51] + SSIG0(pt[43]) + pt[42];
            pt[59] = SSIG1(pt[57]) + pt[52] + SSIG0(pt[44]) + pt[43];
            pt[60] = SSIG1(pt[58]) + pt[53] + SSIG0(pt[45]) + pt[44];
            pt[61] = SSIG1(pt[59]) + pt[54] + SSIG0(pt[46]) + pt[45];
            pt[62] = SSIG1(pt[60]) + pt[55] + SSIG0(pt[47]) + pt[46];
            pt[63] = SSIG1(pt[61]) + pt[56] + SSIG0(pt[48]) + pt[47];
            pt[64] = SSIG1(pt[62]) + pt[57] + SSIG0(pt[49]) + pt[48];
            pt[65] = SSIG1(pt[63]) + pt[58] + SSIG0(pt[50]) + pt[49];
            pt[66] = SSIG1(pt[64]) + pt[59] + SSIG0(pt[51]) + pt[50];
            pt[67] = SSIG1(pt[65]) + pt[60] + SSIG0(pt[52]) + pt[51];
            pt[68] = SSIG1(pt[66]) + pt[61] + SSIG0(pt[53]) + pt[52];
            pt[69] = SSIG1(pt[67]) + pt[62] + SSIG0(pt[54]) + pt[53];
            pt[70] = SSIG1(pt[68]) + pt[63] + SSIG0(pt[55]) + pt[54];
            pt[71] = SSIG1(pt[69]) + pt[64] + SSIG0(pt[56]) + pt[55];

            CompressBlockWithWSet(pt);

            // Perform second hash
            DoSecondHash(pt);
        }

        /// <summary>
        /// Computes double SHA256 hash for
        /// (data.Length == 32) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public static unsafe void CompressDouble32(uint* pt)
        {
            // w8 = 0b10000000_00000000_00000000_00000000U 
            // w9 to w14 = 0
            // w15 = 256
            pt[24] = SSIG0(pt[9]) + pt[8];
            pt[25] = 10485760 + SSIG0(pt[10]) + pt[9];
            pt[26] = SSIG1(pt[24]) + SSIG0(pt[11]) + pt[10];
            pt[27] = SSIG1(pt[25]) + SSIG0(pt[12]) + pt[11];
            pt[28] = SSIG1(pt[26]) + SSIG0(pt[13]) + pt[12];
            pt[29] = SSIG1(pt[27]) + SSIG0(pt[14]) + pt[13];
            pt[30] = SSIG1(pt[28]) + 256 + SSIG0(pt[15]) + pt[14];
            pt[31] = SSIG1(pt[29]) + pt[24] + 285220864 + pt[15];
            pt[32] = SSIG1(pt[30]) + pt[25] + 2147483648;
            pt[33] = SSIG1(pt[31]) + pt[26];
            pt[34] = SSIG1(pt[32]) + pt[27];
            pt[35] = SSIG1(pt[33]) + pt[28];
            pt[36] = SSIG1(pt[34]) + pt[29];
            pt[37] = SSIG1(pt[35]) + pt[30];
            pt[38] = SSIG1(pt[36]) + pt[31] + 4194338;
            pt[39] = SSIG1(pt[37]) + pt[32] + SSIG0(pt[24]) + 256;
            pt[40] = SSIG1(pt[38]) + pt[33] + SSIG0(pt[25]) + pt[24];
            pt[41] = SSIG1(pt[39]) + pt[34] + SSIG0(pt[26]) + pt[25];
            pt[42] = SSIG1(pt[40]) + pt[35] + SSIG0(pt[27]) + pt[26];
            pt[43] = SSIG1(pt[41]) + pt[36] + SSIG0(pt[28]) + pt[27];
            pt[44] = SSIG1(pt[42]) + pt[37] + SSIG0(pt[29]) + pt[28];
            pt[45] = SSIG1(pt[43]) + pt[38] + SSIG0(pt[30]) + pt[29];
            pt[46] = SSIG1(pt[44]) + pt[39] + SSIG0(pt[31]) + pt[30];
            pt[47] = SSIG1(pt[45]) + pt[40] + SSIG0(pt[32]) + pt[31];
            pt[48] = SSIG1(pt[46]) + pt[41] + SSIG0(pt[33]) + pt[32];
            pt[49] = SSIG1(pt[47]) + pt[42] + SSIG0(pt[34]) + pt[33];
            pt[50] = SSIG1(pt[48]) + pt[43] + SSIG0(pt[35]) + pt[34];
            pt[51] = SSIG1(pt[49]) + pt[44] + SSIG0(pt[36]) + pt[35];
            pt[52] = SSIG1(pt[50]) + pt[45] + SSIG0(pt[37]) + pt[36];
            pt[53] = SSIG1(pt[51]) + pt[46] + SSIG0(pt[38]) + pt[37];
            pt[54] = SSIG1(pt[52]) + pt[47] + SSIG0(pt[39]) + pt[38];
            pt[55] = SSIG1(pt[53]) + pt[48] + SSIG0(pt[40]) + pt[39];
            pt[56] = SSIG1(pt[54]) + pt[49] + SSIG0(pt[41]) + pt[40];
            pt[57] = SSIG1(pt[55]) + pt[50] + SSIG0(pt[42]) + pt[41];
            pt[58] = SSIG1(pt[56]) + pt[51] + SSIG0(pt[43]) + pt[42];
            pt[59] = SSIG1(pt[57]) + pt[52] + SSIG0(pt[44]) + pt[43];
            pt[60] = SSIG1(pt[58]) + pt[53] + SSIG0(pt[45]) + pt[44];
            pt[61] = SSIG1(pt[59]) + pt[54] + SSIG0(pt[46]) + pt[45];
            pt[62] = SSIG1(pt[60]) + pt[55] + SSIG0(pt[47]) + pt[46];
            pt[63] = SSIG1(pt[61]) + pt[56] + SSIG0(pt[48]) + pt[47];
            pt[64] = SSIG1(pt[62]) + pt[57] + SSIG0(pt[49]) + pt[48];
            pt[65] = SSIG1(pt[63]) + pt[58] + SSIG0(pt[50]) + pt[49];
            pt[66] = SSIG1(pt[64]) + pt[59] + SSIG0(pt[51]) + pt[50];
            pt[67] = SSIG1(pt[65]) + pt[60] + SSIG0(pt[52]) + pt[51];
            pt[68] = SSIG1(pt[66]) + pt[61] + SSIG0(pt[53]) + pt[52];
            pt[69] = SSIG1(pt[67]) + pt[62] + SSIG0(pt[54]) + pt[53];
            pt[70] = SSIG1(pt[68]) + pt[63] + SSIG0(pt[55]) + pt[54];
            pt[71] = SSIG1(pt[69]) + pt[64] + SSIG0(pt[56]) + pt[55];

            CompressBlockWithWSet(pt);

            // Perform second hash
            DoSecondHash(pt);
        }

        /// <summary>
        /// Computes double SHA256 hash for
        /// (data.Length == 33) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        public static unsafe void CompressDouble33(uint* pt)
        {
            // w8 = extra values | 0b00000000_10000000_00000000_00000000U 
            // w9 to w14 = 0
            // w15 = 264
            pt[24] = SSIG0(pt[9]) + pt[8];
            pt[25] = 10813440 + SSIG0(pt[10]) + pt[9];
            pt[26] = SSIG1(pt[24]) + SSIG0(pt[11]) + pt[10];
            pt[27] = SSIG1(pt[25]) + SSIG0(pt[12]) + pt[11];
            pt[28] = SSIG1(pt[26]) + SSIG0(pt[13]) + pt[12];
            pt[29] = SSIG1(pt[27]) + SSIG0(pt[14]) + pt[13];
            pt[30] = SSIG1(pt[28]) + 264 + SSIG0(pt[15]) + pt[14];
            pt[31] = SSIG1(pt[29]) + pt[24] + SSIG0(pt[16]) + pt[15];
            pt[32] = SSIG1(pt[30]) + pt[25] + pt[16];
            pt[33] = SSIG1(pt[31]) + pt[26];
            pt[34] = SSIG1(pt[32]) + pt[27];
            pt[35] = SSIG1(pt[33]) + pt[28];
            pt[36] = SSIG1(pt[34]) + pt[29];
            pt[37] = SSIG1(pt[35]) + pt[30];
            pt[38] = SSIG1(pt[36]) + pt[31] + 272760867;
            pt[39] = SSIG1(pt[37]) + pt[32] + SSIG0(pt[24]) + 264;
            pt[40] = SSIG1(pt[38]) + pt[33] + SSIG0(pt[25]) + pt[24];
            pt[41] = SSIG1(pt[39]) + pt[34] + SSIG0(pt[26]) + pt[25];
            pt[42] = SSIG1(pt[40]) + pt[35] + SSIG0(pt[27]) + pt[26];
            pt[43] = SSIG1(pt[41]) + pt[36] + SSIG0(pt[28]) + pt[27];
            pt[44] = SSIG1(pt[42]) + pt[37] + SSIG0(pt[29]) + pt[28];
            pt[45] = SSIG1(pt[43]) + pt[38] + SSIG0(pt[30]) + pt[29];
            pt[46] = SSIG1(pt[44]) + pt[39] + SSIG0(pt[31]) + pt[30];
            pt[47] = SSIG1(pt[45]) + pt[40] + SSIG0(pt[32]) + pt[31];
            pt[48] = SSIG1(pt[46]) + pt[41] + SSIG0(pt[33]) + pt[32];
            pt[49] = SSIG1(pt[47]) + pt[42] + SSIG0(pt[34]) + pt[33];
            pt[50] = SSIG1(pt[48]) + pt[43] + SSIG0(pt[35]) + pt[34];
            pt[51] = SSIG1(pt[49]) + pt[44] + SSIG0(pt[36]) + pt[35];
            pt[52] = SSIG1(pt[50]) + pt[45] + SSIG0(pt[37]) + pt[36];
            pt[53] = SSIG1(pt[51]) + pt[46] + SSIG0(pt[38]) + pt[37];
            pt[54] = SSIG1(pt[52]) + pt[47] + SSIG0(pt[39]) + pt[38];
            pt[55] = SSIG1(pt[53]) + pt[48] + SSIG0(pt[40]) + pt[39];
            pt[56] = SSIG1(pt[54]) + pt[49] + SSIG0(pt[41]) + pt[40];
            pt[57] = SSIG1(pt[55]) + pt[50] + SSIG0(pt[42]) + pt[41];
            pt[58] = SSIG1(pt[56]) + pt[51] + SSIG0(pt[43]) + pt[42];
            pt[59] = SSIG1(pt[57]) + pt[52] + SSIG0(pt[44]) + pt[43];
            pt[60] = SSIG1(pt[58]) + pt[53] + SSIG0(pt[45]) + pt[44];
            pt[61] = SSIG1(pt[59]) + pt[54] + SSIG0(pt[46]) + pt[45];
            pt[62] = SSIG1(pt[60]) + pt[55] + SSIG0(pt[47]) + pt[46];
            pt[63] = SSIG1(pt[61]) + pt[56] + SSIG0(pt[48]) + pt[47];
            pt[64] = SSIG1(pt[62]) + pt[57] + SSIG0(pt[49]) + pt[48];
            pt[65] = SSIG1(pt[63]) + pt[58] + SSIG0(pt[50]) + pt[49];
            pt[66] = SSIG1(pt[64]) + pt[59] + SSIG0(pt[51]) + pt[50];
            pt[67] = SSIG1(pt[65]) + pt[60] + SSIG0(pt[52]) + pt[51];
            pt[68] = SSIG1(pt[66]) + pt[61] + SSIG0(pt[53]) + pt[52];
            pt[69] = SSIG1(pt[67]) + pt[62] + SSIG0(pt[54]) + pt[53];
            pt[70] = SSIG1(pt[68]) + pt[63] + SSIG0(pt[55]) + pt[54];
            pt[71] = SSIG1(pt[69]) + pt[64] + SSIG0(pt[56]) + pt[55];

            CompressBlockWithWSet(pt);

            // Perform second hash
            DoSecondHash(pt);
        }

        /// <summary>
        /// Computes double SHA256 hash for
        /// (data.Length == 34) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        public static unsafe void CompressDouble34(uint* pt)
        {
            // w8 = extra values | 0b00000000_00000000_10000000_00000000U 
            // w9 to w14 = 0
            // w15 = 272
            pt[24] = SSIG0(pt[9]) + pt[8];
            pt[25] = 11141120 + SSIG0(pt[10]) + pt[9];
            pt[26] = SSIG1(pt[24]) + SSIG0(pt[11]) + pt[10];
            pt[27] = SSIG1(pt[25]) + SSIG0(pt[12]) + pt[11];
            pt[28] = SSIG1(pt[26]) + SSIG0(pt[13]) + pt[12];
            pt[29] = SSIG1(pt[27]) + SSIG0(pt[14]) + pt[13];
            pt[30] = SSIG1(pt[28]) + 272 + SSIG0(pt[15]) + pt[14];
            pt[31] = SSIG1(pt[29]) + pt[24] + SSIG0(pt[16]) + pt[15];
            pt[32] = SSIG1(pt[30]) + pt[25] + pt[16];
            pt[33] = SSIG1(pt[31]) + pt[26];
            pt[34] = SSIG1(pt[32]) + pt[27];
            pt[35] = SSIG1(pt[33]) + pt[28];
            pt[36] = SSIG1(pt[34]) + pt[29];
            pt[37] = SSIG1(pt[35]) + pt[30];
            pt[38] = SSIG1(pt[36]) + pt[31] + 541327392;
            pt[39] = SSIG1(pt[37]) + pt[32] + SSIG0(pt[24]) + 272;
            pt[40] = SSIG1(pt[38]) + pt[33] + SSIG0(pt[25]) + pt[24];
            pt[41] = SSIG1(pt[39]) + pt[34] + SSIG0(pt[26]) + pt[25];
            pt[42] = SSIG1(pt[40]) + pt[35] + SSIG0(pt[27]) + pt[26];
            pt[43] = SSIG1(pt[41]) + pt[36] + SSIG0(pt[28]) + pt[27];
            pt[44] = SSIG1(pt[42]) + pt[37] + SSIG0(pt[29]) + pt[28];
            pt[45] = SSIG1(pt[43]) + pt[38] + SSIG0(pt[30]) + pt[29];
            pt[46] = SSIG1(pt[44]) + pt[39] + SSIG0(pt[31]) + pt[30];
            pt[47] = SSIG1(pt[45]) + pt[40] + SSIG0(pt[32]) + pt[31];
            pt[48] = SSIG1(pt[46]) + pt[41] + SSIG0(pt[33]) + pt[32];
            pt[49] = SSIG1(pt[47]) + pt[42] + SSIG0(pt[34]) + pt[33];
            pt[50] = SSIG1(pt[48]) + pt[43] + SSIG0(pt[35]) + pt[34];
            pt[51] = SSIG1(pt[49]) + pt[44] + SSIG0(pt[36]) + pt[35];
            pt[52] = SSIG1(pt[50]) + pt[45] + SSIG0(pt[37]) + pt[36];
            pt[53] = SSIG1(pt[51]) + pt[46] + SSIG0(pt[38]) + pt[37];
            pt[54] = SSIG1(pt[52]) + pt[47] + SSIG0(pt[39]) + pt[38];
            pt[55] = SSIG1(pt[53]) + pt[48] + SSIG0(pt[40]) + pt[39];
            pt[56] = SSIG1(pt[54]) + pt[49] + SSIG0(pt[41]) + pt[40];
            pt[57] = SSIG1(pt[55]) + pt[50] + SSIG0(pt[42]) + pt[41];
            pt[58] = SSIG1(pt[56]) + pt[51] + SSIG0(pt[43]) + pt[42];
            pt[59] = SSIG1(pt[57]) + pt[52] + SSIG0(pt[44]) + pt[43];
            pt[60] = SSIG1(pt[58]) + pt[53] + SSIG0(pt[45]) + pt[44];
            pt[61] = SSIG1(pt[59]) + pt[54] + SSIG0(pt[46]) + pt[45];
            pt[62] = SSIG1(pt[60]) + pt[55] + SSIG0(pt[47]) + pt[46];
            pt[63] = SSIG1(pt[61]) + pt[56] + SSIG0(pt[48]) + pt[47];
            pt[64] = SSIG1(pt[62]) + pt[57] + SSIG0(pt[49]) + pt[48];
            pt[65] = SSIG1(pt[63]) + pt[58] + SSIG0(pt[50]) + pt[49];
            pt[66] = SSIG1(pt[64]) + pt[59] + SSIG0(pt[51]) + pt[50];
            pt[67] = SSIG1(pt[65]) + pt[60] + SSIG0(pt[52]) + pt[51];
            pt[68] = SSIG1(pt[66]) + pt[61] + SSIG0(pt[53]) + pt[52];
            pt[69] = SSIG1(pt[67]) + pt[62] + SSIG0(pt[54]) + pt[53];
            pt[70] = SSIG1(pt[68]) + pt[63] + SSIG0(pt[55]) + pt[54];
            pt[71] = SSIG1(pt[69]) + pt[64] + SSIG0(pt[56]) + pt[55];

            CompressBlockWithWSet(pt);

            // Perform second hash
            DoSecondHash(pt);
        }

        /// <summary>
        /// Computes double SHA256 hash for
        /// (data.Length == 39) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public static unsafe void CompressDouble39(uint* pt)
        {
            // w9 = extra values | 0b00000000_00000000_00000000_10000000U 
            // w10 to w14 = 0
            // w15 = 312
            pt[24] = pt[17] + SSIG0(pt[9]) + pt[8];
            pt[25] = 12255232 + SSIG0(pt[10]) + pt[9];
            pt[26] = SSIG1(pt[24]) + SSIG0(pt[11]) + pt[10];
            pt[27] = SSIG1(pt[25]) + SSIG0(pt[12]) + pt[11];
            pt[28] = SSIG1(pt[26]) + SSIG0(pt[13]) + pt[12];
            pt[29] = SSIG1(pt[27]) + SSIG0(pt[14]) + pt[13];
            pt[30] = SSIG1(pt[28]) + 312 + SSIG0(pt[15]) + pt[14];
            pt[31] = SSIG1(pt[29]) + pt[24] + SSIG0(pt[16]) + pt[15];
            pt[32] = SSIG1(pt[30]) + pt[25] + SSIG0(pt[17]) + pt[16];
            pt[33] = SSIG1(pt[31]) + pt[26] + pt[17];
            pt[34] = SSIG1(pt[32]) + pt[27];
            pt[35] = SSIG1(pt[33]) + pt[28];
            pt[36] = SSIG1(pt[34]) + pt[29];
            pt[37] = SSIG1(pt[35]) + pt[30];
            pt[38] = SSIG1(pt[36]) + pt[31] + 1884160037;
            pt[39] = SSIG1(pt[37]) + pt[32] + SSIG0(pt[24]) + 312;
            pt[40] = SSIG1(pt[38]) + pt[33] + SSIG0(pt[25]) + pt[24];
            pt[41] = SSIG1(pt[39]) + pt[34] + SSIG0(pt[26]) + pt[25];
            pt[42] = SSIG1(pt[40]) + pt[35] + SSIG0(pt[27]) + pt[26];
            pt[43] = SSIG1(pt[41]) + pt[36] + SSIG0(pt[28]) + pt[27];
            pt[44] = SSIG1(pt[42]) + pt[37] + SSIG0(pt[29]) + pt[28];
            pt[45] = SSIG1(pt[43]) + pt[38] + SSIG0(pt[30]) + pt[29];
            pt[46] = SSIG1(pt[44]) + pt[39] + SSIG0(pt[31]) + pt[30];
            pt[47] = SSIG1(pt[45]) + pt[40] + SSIG0(pt[32]) + pt[31];
            pt[48] = SSIG1(pt[46]) + pt[41] + SSIG0(pt[33]) + pt[32];
            pt[49] = SSIG1(pt[47]) + pt[42] + SSIG0(pt[34]) + pt[33];
            pt[50] = SSIG1(pt[48]) + pt[43] + SSIG0(pt[35]) + pt[34];
            pt[51] = SSIG1(pt[49]) + pt[44] + SSIG0(pt[36]) + pt[35];
            pt[52] = SSIG1(pt[50]) + pt[45] + SSIG0(pt[37]) + pt[36];
            pt[53] = SSIG1(pt[51]) + pt[46] + SSIG0(pt[38]) + pt[37];
            pt[54] = SSIG1(pt[52]) + pt[47] + SSIG0(pt[39]) + pt[38];
            pt[55] = SSIG1(pt[53]) + pt[48] + SSIG0(pt[40]) + pt[39];
            pt[56] = SSIG1(pt[54]) + pt[49] + SSIG0(pt[41]) + pt[40];
            pt[57] = SSIG1(pt[55]) + pt[50] + SSIG0(pt[42]) + pt[41];
            pt[58] = SSIG1(pt[56]) + pt[51] + SSIG0(pt[43]) + pt[42];
            pt[59] = SSIG1(pt[57]) + pt[52] + SSIG0(pt[44]) + pt[43];
            pt[60] = SSIG1(pt[58]) + pt[53] + SSIG0(pt[45]) + pt[44];
            pt[61] = SSIG1(pt[59]) + pt[54] + SSIG0(pt[46]) + pt[45];
            pt[62] = SSIG1(pt[60]) + pt[55] + SSIG0(pt[47]) + pt[46];
            pt[63] = SSIG1(pt[61]) + pt[56] + SSIG0(pt[48]) + pt[47];
            pt[64] = SSIG1(pt[62]) + pt[57] + SSIG0(pt[49]) + pt[48];
            pt[65] = SSIG1(pt[63]) + pt[58] + SSIG0(pt[50]) + pt[49];
            pt[66] = SSIG1(pt[64]) + pt[59] + SSIG0(pt[51]) + pt[50];
            pt[67] = SSIG1(pt[65]) + pt[60] + SSIG0(pt[52]) + pt[51];
            pt[68] = SSIG1(pt[66]) + pt[61] + SSIG0(pt[53]) + pt[52];
            pt[69] = SSIG1(pt[67]) + pt[62] + SSIG0(pt[54]) + pt[53];
            pt[70] = SSIG1(pt[68]) + pt[63] + SSIG0(pt[55]) + pt[54];
            pt[71] = SSIG1(pt[69]) + pt[64] + SSIG0(pt[56]) + pt[55];

            CompressBlockWithWSet(pt);

            // Perform second hash
            DoSecondHash(pt);
        }

        /// <summary>
        /// Computes double SHA256 hash for
        /// (data.Length == 40) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public static unsafe void CompressDouble40(uint* pt)
        {
            // w10 = 0b10000000_00000000_00000000_00000000U 
            // w11 to w14 = 0
            // w15 = 320
            pt[24] = pt[17] + SSIG0(pt[9]) + pt[8];
            pt[25] = 8912896 + 2147483648 + SSIG0(pt[10]) + pt[9];
            pt[26] = SSIG1(pt[24]) + SSIG0(pt[11]) + pt[10];
            pt[27] = SSIG1(pt[25]) + SSIG0(pt[12]) + pt[11];
            pt[28] = SSIG1(pt[26]) + SSIG0(pt[13]) + pt[12];
            pt[29] = SSIG1(pt[27]) + SSIG0(pt[14]) + pt[13];
            pt[30] = SSIG1(pt[28]) + 320 + SSIG0(pt[15]) + pt[14];
            pt[31] = SSIG1(pt[29]) + pt[24] + SSIG0(pt[16]) + pt[15];
            pt[32] = SSIG1(pt[30]) + pt[25] + SSIG0(pt[17]) + pt[16];
            pt[33] = SSIG1(pt[31]) + pt[26] + 285220864 + pt[17];
            pt[34] = SSIG1(pt[32]) + pt[27] + 2147483648;
            pt[35] = SSIG1(pt[33]) + pt[28];
            pt[36] = SSIG1(pt[34]) + pt[29];
            pt[37] = SSIG1(pt[35]) + pt[30];
            pt[38] = SSIG1(pt[36]) + pt[31] + 2152726570;
            pt[39] = SSIG1(pt[37]) + pt[32] + SSIG0(pt[24]) + 320;
            pt[40] = SSIG1(pt[38]) + pt[33] + SSIG0(pt[25]) + pt[24];
            pt[41] = SSIG1(pt[39]) + pt[34] + SSIG0(pt[26]) + pt[25];
            pt[42] = SSIG1(pt[40]) + pt[35] + SSIG0(pt[27]) + pt[26];
            pt[43] = SSIG1(pt[41]) + pt[36] + SSIG0(pt[28]) + pt[27];
            pt[44] = SSIG1(pt[42]) + pt[37] + SSIG0(pt[29]) + pt[28];
            pt[45] = SSIG1(pt[43]) + pt[38] + SSIG0(pt[30]) + pt[29];
            pt[46] = SSIG1(pt[44]) + pt[39] + SSIG0(pt[31]) + pt[30];
            pt[47] = SSIG1(pt[45]) + pt[40] + SSIG0(pt[32]) + pt[31];
            pt[48] = SSIG1(pt[46]) + pt[41] + SSIG0(pt[33]) + pt[32];
            pt[49] = SSIG1(pt[47]) + pt[42] + SSIG0(pt[34]) + pt[33];
            pt[50] = SSIG1(pt[48]) + pt[43] + SSIG0(pt[35]) + pt[34];
            pt[51] = SSIG1(pt[49]) + pt[44] + SSIG0(pt[36]) + pt[35];
            pt[52] = SSIG1(pt[50]) + pt[45] + SSIG0(pt[37]) + pt[36];
            pt[53] = SSIG1(pt[51]) + pt[46] + SSIG0(pt[38]) + pt[37];
            pt[54] = SSIG1(pt[52]) + pt[47] + SSIG0(pt[39]) + pt[38];
            pt[55] = SSIG1(pt[53]) + pt[48] + SSIG0(pt[40]) + pt[39];
            pt[56] = SSIG1(pt[54]) + pt[49] + SSIG0(pt[41]) + pt[40];
            pt[57] = SSIG1(pt[55]) + pt[50] + SSIG0(pt[42]) + pt[41];
            pt[58] = SSIG1(pt[56]) + pt[51] + SSIG0(pt[43]) + pt[42];
            pt[59] = SSIG1(pt[57]) + pt[52] + SSIG0(pt[44]) + pt[43];
            pt[60] = SSIG1(pt[58]) + pt[53] + SSIG0(pt[45]) + pt[44];
            pt[61] = SSIG1(pt[59]) + pt[54] + SSIG0(pt[46]) + pt[45];
            pt[62] = SSIG1(pt[60]) + pt[55] + SSIG0(pt[47]) + pt[46];
            pt[63] = SSIG1(pt[61]) + pt[56] + SSIG0(pt[48]) + pt[47];
            pt[64] = SSIG1(pt[62]) + pt[57] + SSIG0(pt[49]) + pt[48];
            pt[65] = SSIG1(pt[63]) + pt[58] + SSIG0(pt[50]) + pt[49];
            pt[66] = SSIG1(pt[64]) + pt[59] + SSIG0(pt[51]) + pt[50];
            pt[67] = SSIG1(pt[65]) + pt[60] + SSIG0(pt[52]) + pt[51];
            pt[68] = SSIG1(pt[66]) + pt[61] + SSIG0(pt[53]) + pt[52];
            pt[69] = SSIG1(pt[67]) + pt[62] + SSIG0(pt[54]) + pt[53];
            pt[70] = SSIG1(pt[68]) + pt[63] + SSIG0(pt[55]) + pt[54];
            pt[71] = SSIG1(pt[69]) + pt[64] + SSIG0(pt[56]) + pt[55];

            CompressBlockWithWSet(pt);

            // Perform second hash
            DoSecondHash(pt);
        }

        /// <summary>
        /// Computes double SHA256 hash for
        /// (data.Length == 65)
        /// </summary>
        /// <param name="data">65 byte data</param>
        public static unsafe byte[] CompressDouble65(Span<byte> data)
        {
            Debug.Assert(data != null && data.Length == 65);

            uint* pt = stackalloc uint[UBufferSize];
            fixed (byte* dPt = &data[0])
            {
                Init(pt);
                Compress65(pt, dPt);
                DoSecondHash(pt);
                return GetBytes(pt);
            }
        }

        internal static unsafe void DoSecondHash(uint* pt)
        {
            // Result of previous hash (hashState[]) is now our new block. So copy it here:
            pt[8] = pt[0];
            pt[9] = pt[1];
            pt[10] = pt[2];
            pt[11] = pt[3];
            pt[12] = pt[4];
            pt[13] = pt[5];
            pt[14] = pt[6];
            pt[15] = pt[7]; // 8*4 = 32 byte hash result

            pt[16] = 0b10000000_00000000_00000000_00000000U; // 1 followed by 0 bits to fill pad1
            pt[17] = 0;
            pt[18] = 0;
            pt[19] = 0;
            pt[20] = 0;
            pt[21] = 0;

            pt[22] = 0; // Message length for pad2, since message is the 32 byte result of previous hash, length is 256 bit
            pt[23] = 256;

            // Set the rest of working vector from 16 to 64
            pt[24] = SSIG0(pt[9]) + pt[8];
            pt[25] = 10485760 + SSIG0(pt[10]) + pt[9];
            pt[26] = SSIG1(pt[24]) + SSIG0(pt[11]) + pt[10];
            pt[27] = SSIG1(pt[25]) + SSIG0(pt[12]) + pt[11];
            pt[28] = SSIG1(pt[26]) + SSIG0(pt[13]) + pt[12];
            pt[29] = SSIG1(pt[27]) + SSIG0(pt[14]) + pt[13];
            pt[30] = SSIG1(pt[28]) + 256 + SSIG0(pt[15]) + pt[14];
            pt[31] = SSIG1(pt[29]) + pt[24] + 285220864 + pt[15];
            pt[32] = SSIG1(pt[30]) + pt[25] + 0b10000000_00000000_00000000_00000000U;
            pt[33] = SSIG1(pt[31]) + pt[26];
            pt[34] = SSIG1(pt[32]) + pt[27];
            pt[35] = SSIG1(pt[33]) + pt[28];
            pt[36] = SSIG1(pt[34]) + pt[29];
            pt[37] = SSIG1(pt[35]) + pt[30];
            pt[38] = SSIG1(pt[36]) + pt[31] + 4194338;
            pt[39] = SSIG1(pt[37]) + pt[32] + SSIG0(pt[24]) + 256;
            pt[40] = SSIG1(pt[38]) + pt[33] + SSIG0(pt[25]) + pt[24];
            pt[41] = SSIG1(pt[39]) + pt[34] + SSIG0(pt[26]) + pt[25];
            pt[42] = SSIG1(pt[40]) + pt[35] + SSIG0(pt[27]) + pt[26];
            pt[43] = SSIG1(pt[41]) + pt[36] + SSIG0(pt[28]) + pt[27];
            pt[44] = SSIG1(pt[42]) + pt[37] + SSIG0(pt[29]) + pt[28];
            pt[45] = SSIG1(pt[43]) + pt[38] + SSIG0(pt[30]) + pt[29];
            pt[46] = SSIG1(pt[44]) + pt[39] + SSIG0(pt[31]) + pt[30];
            pt[47] = SSIG1(pt[45]) + pt[40] + SSIG0(pt[32]) + pt[31];
            pt[48] = SSIG1(pt[46]) + pt[41] + SSIG0(pt[33]) + pt[32];
            pt[49] = SSIG1(pt[47]) + pt[42] + SSIG0(pt[34]) + pt[33];
            pt[50] = SSIG1(pt[48]) + pt[43] + SSIG0(pt[35]) + pt[34];
            pt[51] = SSIG1(pt[49]) + pt[44] + SSIG0(pt[36]) + pt[35];
            pt[52] = SSIG1(pt[50]) + pt[45] + SSIG0(pt[37]) + pt[36];
            pt[53] = SSIG1(pt[51]) + pt[46] + SSIG0(pt[38]) + pt[37];
            pt[54] = SSIG1(pt[52]) + pt[47] + SSIG0(pt[39]) + pt[38];
            pt[55] = SSIG1(pt[53]) + pt[48] + SSIG0(pt[40]) + pt[39];
            pt[56] = SSIG1(pt[54]) + pt[49] + SSIG0(pt[41]) + pt[40];
            pt[57] = SSIG1(pt[55]) + pt[50] + SSIG0(pt[42]) + pt[41];
            pt[58] = SSIG1(pt[56]) + pt[51] + SSIG0(pt[43]) + pt[42];
            pt[59] = SSIG1(pt[57]) + pt[52] + SSIG0(pt[44]) + pt[43];
            pt[60] = SSIG1(pt[58]) + pt[53] + SSIG0(pt[45]) + pt[44];
            pt[61] = SSIG1(pt[59]) + pt[54] + SSIG0(pt[46]) + pt[45];
            pt[62] = SSIG1(pt[60]) + pt[55] + SSIG0(pt[47]) + pt[46];
            pt[63] = SSIG1(pt[61]) + pt[56] + SSIG0(pt[48]) + pt[47];
            pt[64] = SSIG1(pt[62]) + pt[57] + SSIG0(pt[49]) + pt[48];
            pt[65] = SSIG1(pt[63]) + pt[58] + SSIG0(pt[50]) + pt[49];
            pt[66] = SSIG1(pt[64]) + pt[59] + SSIG0(pt[51]) + pt[50];
            pt[67] = SSIG1(pt[65]) + pt[60] + SSIG0(pt[52]) + pt[51];
            pt[68] = SSIG1(pt[66]) + pt[61] + SSIG0(pt[53]) + pt[52];
            pt[69] = SSIG1(pt[67]) + pt[62] + SSIG0(pt[54]) + pt[53];
            pt[70] = SSIG1(pt[68]) + pt[63] + SSIG0(pt[55]) + pt[54];
            pt[71] = SSIG1(pt[69]) + pt[64] + SSIG0(pt[56]) + pt[55];

            // Now initialize hashState to compute next round, since this is a new hash
            Init(pt);

            // We only have 1 block so there is no need for a loop.
            CompressBlockWithWSet(pt);
        }


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static unsafe void SetW(uint* wPt, int start = 16)
        {
            for (int i = start; i < WorkingVectorSize; i++)
            {
                wPt[i] = SSIG1(wPt[i - 2]) + wPt[i - 7] + SSIG0(wPt[i - 15]) + wPt[i - 16];
            }
        }


        public static unsafe void CompressBlockWithWSet(uint* pt)
        {
            uint a = pt[0];
            uint b = pt[1];
            uint c = pt[2];
            uint d = pt[3];
            uint e = pt[4];
            uint f = pt[5];
            uint g = pt[6];
            uint h = pt[7];

            uint temp, aa, bb, cc, dd, ee, ff, hh, gg;

            fixed (uint* kPt = &Ks[0])
            {
                for (int j = 0; j < 64;)
                {
                    temp = h + BSIG1(e) + CH(e, f, g) + kPt[j] + pt[HashStateSize + j];
                    ee = d + temp;
                    aa = temp + BSIG0(a) + MAJ(a, b, c);
                    j++;

                    temp = g + BSIG1(ee) + CH(ee, e, f) + kPt[j] + pt[HashStateSize + j];
                    ff = c + temp;
                    bb = temp + BSIG0(aa) + MAJ(aa, a, b);
                    j++;

                    temp = f + BSIG1(ff) + CH(ff, ee, e) + kPt[j] + pt[HashStateSize + j];
                    gg = b + temp;
                    cc = temp + BSIG0(bb) + MAJ(bb, aa, a);
                    j++;

                    temp = e + BSIG1(gg) + CH(gg, ff, ee) + kPt[j] + pt[HashStateSize + j];
                    hh = a + temp;
                    dd = temp + BSIG0(cc) + MAJ(cc, bb, aa);
                    j++;

                    temp = ee + BSIG1(hh) + CH(hh, gg, ff) + kPt[j] + pt[HashStateSize + j];
                    h = aa + temp;
                    d = temp + BSIG0(dd) + MAJ(dd, cc, bb);
                    j++;

                    temp = ff + BSIG1(h) + CH(h, hh, gg) + kPt[j] + pt[HashStateSize + j];
                    g = bb + temp;
                    c = temp + BSIG0(d) + MAJ(d, dd, cc);
                    j++;

                    temp = gg + BSIG1(g) + CH(g, h, hh) + kPt[j] + pt[HashStateSize + j];
                    f = cc + temp;
                    b = temp + BSIG0(c) + MAJ(c, d, dd);
                    j++;

                    temp = hh + BSIG1(f) + CH(f, g, h) + kPt[j] + pt[HashStateSize + j];
                    e = dd + temp;
                    a = temp + BSIG0(b) + MAJ(b, c, d);
                    j++;
                }
            }

            pt[0] += a;
            pt[1] += b;
            pt[2] += c;
            pt[3] += d;
            pt[4] += e;
            pt[5] += f;
            pt[6] += g;
            pt[7] += h;
        }


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint CH(uint x, uint y, uint z) => z ^ (x & (y ^ z));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint MAJ(uint x, uint y, uint z) => (x & y) | (z & (x | y));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint BSIG0(uint x) => (x >> 2 | x << 30) ^ (x >> 13 | x << 19) ^ (x >> 22 | x << 10);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint BSIG1(uint x) => (x >> 6 | x << 26) ^ (x >> 11 | x << 21) ^ (x >> 25 | x << 7);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static uint SSIG0(uint x) => (x >> 7 | x << 25) ^ (x >> 18 | x << 14) ^ (x >> 3);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static uint SSIG1(uint x) => (x >> 17 | x << 15) ^ (x >> 19 | x << 13) ^ (x >> 10);
    }
}
