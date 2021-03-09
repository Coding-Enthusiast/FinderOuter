// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace FinderOuter.Backend.Cryptography.Hashing
{
    /// <summary>
    /// Implementation of 256-bit Secure Hash Algorithm (SHA) base on RFC-6234
    /// <para/> https://tools.ietf.org/html/rfc6234
    /// </summary>
    public class Sha256Fo : IDisposable
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Sha256Fo"/>.
        /// </summary>
        /// <param name="isDouble">Determines whether the hash should be performed twice.</param>
        public Sha256Fo(bool isDouble = false)
        {
            IsDouble = isDouble;
        }



        /// <summary>
        /// Indicates whether the hash function should be performed twice on message.
        /// For example Double SHA256 that bitcoin uses.
        /// </summary>
        public bool IsDouble { get; set; }

        /// <summary>
        /// Size of the hash result in bytes (=32 bytes).
        /// </summary>
        public int HashByteSize => 32;

        /// <summary>
        /// Size of the blocks used in each round (=64 bytes).
        /// </summary>
        public int BlockByteSize => 64;


        public uint[] hashState = new uint[8];
        public uint[] w = new uint[64];


        private readonly uint[] Ks =
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



        /// <summary>
        /// Computes the hash value for the specified byte array.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="ObjectDisposedException"/>
        /// <param name="data">The byte array to compute hash for</param>
        /// <returns>The computed hash</returns>
        public byte[] ComputeHash(byte[] data)
        {
            if (disposedValue)
                throw new ObjectDisposedException("Instance was disposed.");
            if (data == null)
                throw new ArgumentNullException(nameof(data), "Data can not be null.");

            Init();

            DoHash(data, data.Length);

            return GetBytes();
        }


        public unsafe void Init()
        {
            fixed (uint* hPt = &hashState[0])
            {
                Init(hPt);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe void Init(uint* hPt)
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


        public unsafe byte[] GetBytes()
        {
            fixed (uint* hPt = &hashState[0])
                return GetBytes(hPt);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public unsafe byte[] GetBytes(uint* hPt)
        {
            byte[] res = new byte[HashByteSize];
            fixed (byte* bPt = &res[0])
            {
                for (int i = 0, j = 0; i < res.Length; i += 4, j++)
                {
                    bPt[i] = (byte)(hPt[j] >> 24);
                    bPt[i + 1] = (byte)(hPt[j] >> 16);
                    bPt[i + 2] = (byte)(hPt[j] >> 8);
                    bPt[i + 3] = (byte)hPt[j];
                }
            }
            return res;
        }


        internal unsafe void DoHash(byte[] data, int len)
        {
            byte[] finalBlock = new byte[64];

            fixed (byte* dPt = data, fPt = &finalBlock[0]) // If data.Length == 0 => &data[0] will throw an exception
            fixed (uint* hPt = &hashState[0], wPt = &w[0])
            {
                int remainingBytes = data.Length;
                int dIndex = 0;
                while (remainingBytes >= BlockByteSize)
                {
                    for (int i = 0; i < 16; i++, dIndex += 4)
                    {
                        wPt[i] = (uint)((dPt[dIndex] << 24) | (dPt[dIndex + 1] << 16) | (dPt[dIndex + 2] << 8) | dPt[dIndex + 3]);
                    }

                    SetW(wPt);
                    CompressBlockWithWSet(hPt, wPt);

                    remainingBytes -= BlockByteSize;
                }

                // Copy the reamaining bytes into a blockSize length buffer so that we can loop through it easily:
                Buffer.BlockCopy(data, data.Length - remainingBytes, finalBlock, 0, remainingBytes);

                // Append 1 bit followed by zeros. Since we only work with bytes, this is 1 whole byte
                fPt[remainingBytes] = 0b1000_0000;

                if (remainingBytes >= 56) // blockSize - pad2.Len = 64 - 8
                {
                    // This means we have an additional block to compress, which we do it here:

                    for (int i = 0, j = 0; i < 16; i++, j += 4)
                    {
                        wPt[i] = (uint)((fPt[j] << 24) | (fPt[j + 1] << 16) | (fPt[j + 2] << 8) | fPt[j + 3]);
                    }

                    SetW(wPt);
                    CompressBlockWithWSet(hPt, wPt);

                    // Zero out all the items in FinalBlock so it can be reused
                    for (int i = 0; i < 8; i++)
                    {
                        ((ulong*)fPt)[i] = 0;
                    }
                }

                // Add length in bits as the last 8 bytes of final block in big-endian order
                // See MessageLengthTest in Test project to understand what the following shifts are
                fPt[63] = (byte)(len << 3);
                fPt[62] = (byte)(len >> 5);
                fPt[61] = (byte)(len >> 13);
                fPt[60] = (byte)(len >> 21);
                fPt[59] = (byte)(len >> 29);
                // The remainig 3 bytes are always zero
                // The remaining 56 bytes are already set

                for (int i = 0, j = 0; i < 16; i++, j += 4)
                {
                    wPt[i] = (uint)((fPt[j] << 24) | (fPt[j + 1] << 16) | (fPt[j + 2] << 8) | fPt[j + 3]);
                }

                SetW(wPt);
                CompressBlockWithWSet(hPt, wPt);


                if (IsDouble)
                {
                    DoSecondHash(hPt, wPt);
                }
            }
        }



        /// <summary>
        /// Computes _single_ SHA256 hash for
        /// (data.Length == 16) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public unsafe void Compress16(uint* hPt, uint* wPt)
        {
            // w4 = 0b10000000_00000000_00000000_00000000U 
            // w5 to w14 = 0
            // w15 = 128
            wPt[16] = SSIG0(wPt[1]) + wPt[0];
            wPt[17] = 5242880 + SSIG0(wPt[2]) + wPt[1];
            wPt[18] = SSIG1(wPt[16]) + SSIG0(wPt[3]) + wPt[2];
            wPt[19] = SSIG1(wPt[17]) + 285220864 + wPt[3];
            wPt[20] = SSIG1(wPt[18]) + 0b10000000_00000000_00000000_00000000U;
            wPt[21] = SSIG1(wPt[19]);
            wPt[22] = SSIG1(wPt[20]) + 128;
            wPt[23] = SSIG1(wPt[21]) + wPt[16];
            wPt[24] = SSIG1(wPt[22]) + wPt[17];
            wPt[25] = SSIG1(wPt[23]) + wPt[18];
            wPt[26] = SSIG1(wPt[24]) + wPt[19];
            wPt[27] = SSIG1(wPt[25]) + wPt[20];
            wPt[28] = SSIG1(wPt[26]) + wPt[21];
            wPt[29] = SSIG1(wPt[27]) + wPt[22];
            wPt[30] = SSIG1(wPt[28]) + wPt[23] + 2097169;
            wPt[31] = SSIG1(wPt[29]) + wPt[24] + SSIG0(wPt[16]) + 128;
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

            CompressBlockWithWSet(hPt, wPt);
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for
        /// (data.Length == 20) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public unsafe void Compress20(uint* hPt, uint* wPt)
        {
            // w5 = 0b10000000_00000000_00000000_00000000U 
            // w6 to w14 = 0
            // w15 = 160
            wPt[16] = SSIG0(wPt[1]) + wPt[0];
            wPt[17] = 4456448 + SSIG0(wPt[2]) + wPt[1];
            wPt[18] = SSIG1(wPt[16]) + SSIG0(wPt[3]) + wPt[2];
            wPt[19] = SSIG1(wPt[17]) + SSIG0(wPt[4]) + wPt[3];
            wPt[20] = SSIG1(wPt[18]) + 285220864 + wPt[4];
            wPt[21] = SSIG1(wPt[19]) + 0b10000000_00000000_00000000_00000000U;
            wPt[22] = SSIG1(wPt[20]) + 160;
            wPt[23] = SSIG1(wPt[21]) + wPt[16];
            wPt[24] = SSIG1(wPt[22]) + wPt[17];
            wPt[25] = SSIG1(wPt[23]) + wPt[18];
            wPt[26] = SSIG1(wPt[24]) + wPt[19];
            wPt[27] = SSIG1(wPt[25]) + wPt[20];
            wPt[28] = SSIG1(wPt[26]) + wPt[21];
            wPt[29] = SSIG1(wPt[27]) + wPt[22];
            wPt[30] = SSIG1(wPt[28]) + wPt[23] + 1076363285;
            wPt[31] = SSIG1(wPt[29]) + wPt[24] + SSIG0(wPt[16]) + 160;
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

            CompressBlockWithWSet(hPt, wPt);
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for
        /// (data.Length == 22) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public unsafe void Compress22(uint* hPt, uint* wPt)
        {
            // w5 = extra values | 0b00000000_00000000_10000000_00000000U
            // w6 to w14 = 0
            // w15 = 176
            wPt[16] = SSIG0(wPt[1]) + wPt[0];
            wPt[17] = 5111808 + SSIG0(wPt[2]) + wPt[1];
            wPt[18] = SSIG1(wPt[16]) + SSIG0(wPt[3]) + wPt[2];
            wPt[19] = SSIG1(wPt[17]) + SSIG0(wPt[4]) + wPt[3];
            wPt[20] = SSIG1(wPt[18]) + SSIG0(wPt[5]) + wPt[4];
            wPt[21] = SSIG1(wPt[19]) + wPt[5];
            wPt[22] = SSIG1(wPt[20]) + 176;
            wPt[23] = SSIG1(wPt[21]) + wPt[16];
            wPt[24] = SSIG1(wPt[22]) + wPt[17];
            wPt[25] = SSIG1(wPt[23]) + wPt[18];
            wPt[26] = SSIG1(wPt[24]) + wPt[19];
            wPt[27] = SSIG1(wPt[25]) + wPt[20];
            wPt[28] = SSIG1(wPt[26]) + wPt[21];
            wPt[29] = SSIG1(wPt[27]) + wPt[22];
            wPt[30] = SSIG1(wPt[28]) + wPt[23] + 1613496343;
            wPt[31] = SSIG1(wPt[29]) + wPt[24] + SSIG0(wPt[16]) + 176;
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

            CompressBlockWithWSet(hPt, wPt);
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for
        /// (data.Length == 23) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public unsafe void Compress23(uint* hPt, uint* wPt)
        {
            // w5 = extra values | 0b00000000_00000000_00000000_10000000U
            // w6 to w14 = 0
            // w15 = 184
            wPt[16] = SSIG0(wPt[1]) + wPt[0];
            wPt[17] = 4915200 + SSIG0(wPt[2]) + wPt[1];
            wPt[18] = SSIG1(wPt[16]) + SSIG0(wPt[3]) + wPt[2];
            wPt[19] = SSIG1(wPt[17]) + SSIG0(wPt[4]) + wPt[3];
            wPt[20] = SSIG1(wPt[18]) + SSIG0(wPt[5]) + wPt[4];
            wPt[21] = SSIG1(wPt[19]) + wPt[5];
            wPt[22] = SSIG1(wPt[20]) + 184;
            wPt[23] = SSIG1(wPt[21]) + wPt[16];
            wPt[24] = SSIG1(wPt[22]) + wPt[17];
            wPt[25] = SSIG1(wPt[23]) + wPt[18];
            wPt[26] = SSIG1(wPt[24]) + wPt[19];
            wPt[27] = SSIG1(wPt[25]) + wPt[20];
            wPt[28] = SSIG1(wPt[26]) + wPt[21];
            wPt[29] = SSIG1(wPt[27]) + wPt[22];
            wPt[30] = SSIG1(wPt[28]) + wPt[23] + 1882062870;
            wPt[31] = SSIG1(wPt[29]) + wPt[24] + SSIG0(wPt[16]) + 184;
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

            CompressBlockWithWSet(hPt, wPt);
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for
        /// (data.Length == 24) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public unsafe void Compress24(uint* hPt, uint* wPt)
        {
            // w6 = 0b10000000_00000000_00000000_00000000U 
            // w7 to w14 = 0
            // w15 = 192
            wPt[16] = SSIG0(wPt[1]) + wPt[0];
            wPt[17] = 7864320 + SSIG0(wPt[2]) + wPt[1];
            wPt[18] = SSIG1(wPt[16]) + SSIG0(wPt[3]) + wPt[2];
            wPt[19] = SSIG1(wPt[17]) + SSIG0(wPt[4]) + wPt[3];
            wPt[20] = SSIG1(wPt[18]) + SSIG0(wPt[5]) + wPt[4];
            wPt[21] = SSIG1(wPt[19]) + 285220864 + wPt[5];
            wPt[22] = SSIG1(wPt[20]) + 0x800000c0U;
            wPt[23] = SSIG1(wPt[21]) + wPt[16];
            wPt[24] = SSIG1(wPt[22]) + wPt[17];
            wPt[25] = SSIG1(wPt[23]) + wPt[18];
            wPt[26] = SSIG1(wPt[24]) + wPt[19];
            wPt[27] = SSIG1(wPt[25]) + wPt[20];
            wPt[28] = SSIG1(wPt[26]) + wPt[21];
            wPt[29] = SSIG1(wPt[27]) + wPt[22];
            wPt[30] = SSIG1(wPt[28]) + wPt[23] + 2150629401;
            wPt[31] = SSIG1(wPt[29]) + wPt[24] + SSIG0(wPt[16]) + 192;
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

            CompressBlockWithWSet(hPt, wPt);
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for
        /// (data.Length == 26) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public unsafe void Compress26(uint* hPt, uint* wPt)
        {
            // w6 = extra value | 0b00000000_00000000_10000000_00000000U 
            // w7 to w14 = 0
            // w15 = 208
            wPt[16] = SSIG0(wPt[1]) + wPt[0];
            wPt[17] = 7471104 + SSIG0(wPt[2]) + wPt[1];
            wPt[18] = SSIG1(wPt[16]) + SSIG0(wPt[3]) + wPt[2];
            wPt[19] = SSIG1(wPt[17]) + SSIG0(wPt[4]) + wPt[3];
            wPt[20] = SSIG1(wPt[18]) + SSIG0(wPt[5]) + wPt[4];
            wPt[21] = SSIG1(wPt[19]) + SSIG0(wPt[6]) + wPt[5];
            wPt[22] = SSIG1(wPt[20]) + 208 + wPt[6];
            wPt[23] = SSIG1(wPt[21]) + wPt[16];
            wPt[24] = SSIG1(wPt[22]) + wPt[17];
            wPt[25] = SSIG1(wPt[23]) + wPt[18];
            wPt[26] = SSIG1(wPt[24]) + wPt[19];
            wPt[27] = SSIG1(wPt[25]) + wPt[20];
            wPt[28] = SSIG1(wPt[26]) + wPt[21];
            wPt[29] = SSIG1(wPt[27]) + wPt[22];
            wPt[30] = SSIG1(wPt[28]) + wPt[23] + 2687762459;
            wPt[31] = SSIG1(wPt[29]) + wPt[24] + SSIG0(wPt[16]) + 208;
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

            CompressBlockWithWSet(hPt, wPt);
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for
        /// (data.Length == 27) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public unsafe void Compress27(uint* hPt, uint* wPt)
        {
            // w6 = extra value | 0b00000000_00000000_00000000_10000000U 
            // w7 to w14 = 0
            // w15 = 216
            wPt[16] = SSIG0(wPt[1]) + wPt[0];
            wPt[17] = 7798784 + SSIG0(wPt[2]) + wPt[1];
            wPt[18] = SSIG1(wPt[16]) + SSIG0(wPt[3]) + wPt[2];
            wPt[19] = SSIG1(wPt[17]) + SSIG0(wPt[4]) + wPt[3];
            wPt[20] = SSIG1(wPt[18]) + SSIG0(wPt[5]) + wPt[4];
            wPt[21] = SSIG1(wPt[19]) + SSIG0(wPt[6]) + wPt[5];
            wPt[22] = SSIG1(wPt[20]) + 216 + wPt[6];
            wPt[23] = SSIG1(wPt[21]) + wPt[16];
            wPt[24] = SSIG1(wPt[22]) + wPt[17];
            wPt[25] = SSIG1(wPt[23]) + wPt[18];
            wPt[26] = SSIG1(wPt[24]) + wPt[19];
            wPt[27] = SSIG1(wPt[25]) + wPt[20];
            wPt[28] = SSIG1(wPt[26]) + wPt[21];
            wPt[29] = SSIG1(wPt[27]) + wPt[22];
            wPt[30] = SSIG1(wPt[28]) + wPt[23] + 2956328986;
            wPt[31] = SSIG1(wPt[29]) + wPt[24] + SSIG0(wPt[16]) + 216;
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

            CompressBlockWithWSet(hPt, wPt);
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for
        /// (data.Length == 28) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public unsafe void Compress28(uint* hPt, uint* wPt)
        {
            // w7 = 0b10000000_00000000_00000000_00000000U 
            // w8 to w14 = 0
            // w15 = 224
            wPt[16] = SSIG0(wPt[1]) + wPt[0];
            wPt[17] = 7077888 + SSIG0(wPt[2]) + wPt[1];
            wPt[18] = SSIG1(wPt[16]) + SSIG0(wPt[3]) + wPt[2];
            wPt[19] = SSIG1(wPt[17]) + SSIG0(wPt[4]) + wPt[3];
            wPt[20] = SSIG1(wPt[18]) + SSIG0(wPt[5]) + wPt[4];
            wPt[21] = SSIG1(wPt[19]) + SSIG0(wPt[6]) + wPt[5];
            wPt[22] = SSIG1(wPt[20]) + 285221088 + wPt[6];
            wPt[23] = SSIG1(wPt[21]) + wPt[16] + 0b10000000_00000000_00000000_00000000U;
            wPt[24] = SSIG1(wPt[22]) + wPt[17];
            wPt[25] = SSIG1(wPt[23]) + wPt[18];
            wPt[26] = SSIG1(wPt[24]) + wPt[19];
            wPt[27] = SSIG1(wPt[25]) + wPt[20];
            wPt[28] = SSIG1(wPt[26]) + wPt[21];
            wPt[29] = SSIG1(wPt[27]) + wPt[22];
            wPt[30] = SSIG1(wPt[28]) + wPt[23] + 3224895517;
            wPt[31] = SSIG1(wPt[29]) + wPt[24] + SSIG0(wPt[16]) + 224;
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

            CompressBlockWithWSet(hPt, wPt);
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for
        /// (data.Length == 31) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public unsafe void Compress30(uint* hPt, uint* wPt)
        {
            // w7 = extra value | 0b00000000_00000000_10000000_00000000U 
            // w8 to w14 = 0
            // w15 = 240
            wPt[16] = SSIG0(wPt[1]) + wPt[0];
            wPt[17] = 6684672 + 0 + SSIG0(wPt[2]) + wPt[1];
            wPt[18] = SSIG1(wPt[16]) + SSIG0(wPt[3]) + wPt[2];
            wPt[19] = SSIG1(wPt[17]) + SSIG0(wPt[4]) + wPt[3];
            wPt[20] = SSIG1(wPt[18]) + SSIG0(wPt[5]) + wPt[4];
            wPt[21] = SSIG1(wPt[19]) + SSIG0(wPt[6]) + wPt[5];
            wPt[22] = SSIG1(wPt[20]) + 240 + SSIG0(wPt[7]) + wPt[6];
            wPt[23] = SSIG1(wPt[21]) + wPt[16] + wPt[7];
            wPt[24] = SSIG1(wPt[22]) + wPt[17];
            wPt[25] = SSIG1(wPt[23]) + wPt[18];
            wPt[26] = SSIG1(wPt[24]) + wPt[19];
            wPt[27] = SSIG1(wPt[25]) + wPt[20];
            wPt[28] = SSIG1(wPt[26]) + wPt[21];
            wPt[29] = SSIG1(wPt[27]) + wPt[22];
            wPt[30] = SSIG1(wPt[28]) + wPt[23] + 3762028575;
            wPt[31] = SSIG1(wPt[29]) + wPt[24] + SSIG0(wPt[16]) + 240;
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

            CompressBlockWithWSet(hPt, wPt);
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for
        /// (data.Length == 31) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public unsafe void Compress31(uint* hPt, uint* wPt)
        {
            // w7 = extra value | 0b00000000_00000000_00000000_10000000U 
            // w8 to w14 = 0
            // w15 = 248
            wPt[16] = 0 + 0 + SSIG0(wPt[1]) + wPt[0];
            wPt[17] = 6488064 + 0 + SSIG0(wPt[2]) + wPt[1];
            wPt[18] = SSIG1(wPt[16]) + SSIG0(wPt[3]) + wPt[2];
            wPt[19] = SSIG1(wPt[17]) + SSIG0(wPt[4]) + wPt[3];
            wPt[20] = SSIG1(wPt[18]) + SSIG0(wPt[5]) + wPt[4];
            wPt[21] = SSIG1(wPt[19]) + SSIG0(wPt[6]) + wPt[5];
            wPt[22] = SSIG1(wPt[20]) + 248 + SSIG0(wPt[7]) + wPt[6];
            wPt[23] = SSIG1(wPt[21]) + wPt[16] + wPt[7];
            wPt[24] = SSIG1(wPt[22]) + wPt[17];
            wPt[25] = SSIG1(wPt[23]) + wPt[18];
            wPt[26] = SSIG1(wPt[24]) + wPt[19];
            wPt[27] = SSIG1(wPt[25]) + wPt[20];
            wPt[28] = SSIG1(wPt[26]) + wPt[21];
            wPt[29] = SSIG1(wPt[27]) + wPt[22];
            wPt[30] = SSIG1(wPt[28]) + wPt[23] + 4030595102;
            wPt[31] = SSIG1(wPt[29]) + wPt[24] + SSIG0(wPt[16]) + 248;
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

            CompressBlockWithWSet(hPt, wPt);
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for
        /// (data.Length == 32) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public unsafe void Compress32(uint* hPt, uint* wPt)
        {
            // w8 = 0b10000000_00000000_00000000_00000000U 
            // w9 to w14 = 0
            // w15 = 256
            wPt[16] = SSIG0(wPt[1]) + wPt[0];
            wPt[17] = 10485760 + SSIG0(wPt[2]) + wPt[1];
            wPt[18] = SSIG1(wPt[16]) + SSIG0(wPt[3]) + wPt[2];
            wPt[19] = SSIG1(wPt[17]) + SSIG0(wPt[4]) + wPt[3];
            wPt[20] = SSIG1(wPt[18]) + SSIG0(wPt[5]) + wPt[4];
            wPt[21] = SSIG1(wPt[19]) + SSIG0(wPt[6]) + wPt[5];
            wPt[22] = SSIG1(wPt[20]) + 256 + SSIG0(wPt[7]) + wPt[6];
            wPt[23] = SSIG1(wPt[21]) + wPt[16] + 285220864 + wPt[7];
            wPt[24] = SSIG1(wPt[22]) + wPt[17] + 0b10000000_00000000_00000000_00000000U;
            wPt[25] = SSIG1(wPt[23]) + wPt[18];
            wPt[26] = SSIG1(wPt[24]) + wPt[19];
            wPt[27] = SSIG1(wPt[25]) + wPt[20];
            wPt[28] = SSIG1(wPt[26]) + wPt[21];
            wPt[29] = SSIG1(wPt[27]) + wPt[22];
            wPt[30] = SSIG1(wPt[28]) + wPt[23] + 4194338;
            wPt[31] = SSIG1(wPt[29]) + wPt[24] + SSIG0(wPt[16]) + 256;
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

            CompressBlockWithWSet(hPt, wPt);
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for
        /// (data.Length == 33) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public unsafe void Compress33(uint* hPt, uint* wPt)
        {
            // w8 = extra value | 0b00000000_10000000_00000000_00000000U 
            // w9 to w14 = 0
            // w15 = 264
            wPt[16] = SSIG0(wPt[1]) + wPt[0];
            wPt[17] = 10813440 + 0 + SSIG0(wPt[2]) + wPt[1];
            wPt[18] = SSIG1(wPt[16]) + SSIG0(wPt[3]) + wPt[2];
            wPt[19] = SSIG1(wPt[17]) + SSIG0(wPt[4]) + wPt[3];
            wPt[20] = SSIG1(wPt[18]) + SSIG0(wPt[5]) + wPt[4];
            wPt[21] = SSIG1(wPt[19]) + SSIG0(wPt[6]) + wPt[5];
            wPt[22] = SSIG1(wPt[20]) + 264 + SSIG0(wPt[7]) + wPt[6];
            wPt[23] = SSIG1(wPt[21]) + wPt[16] + SSIG0(wPt[8]) + wPt[7];
            wPt[24] = SSIG1(wPt[22]) + wPt[17] + wPt[8];
            wPt[25] = SSIG1(wPt[23]) + wPt[18];
            wPt[26] = SSIG1(wPt[24]) + wPt[19];
            wPt[27] = SSIG1(wPt[25]) + wPt[20];
            wPt[28] = SSIG1(wPt[26]) + wPt[21];
            wPt[29] = SSIG1(wPt[27]) + wPt[22];
            wPt[30] = SSIG1(wPt[28]) + wPt[23] + 272760867;
            wPt[31] = SSIG1(wPt[29]) + wPt[24] + SSIG0(wPt[16]) + 264;
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

            CompressBlockWithWSet(hPt, wPt);
        }

        /// <summary>
        /// Computes _single_ SHA256 hash for
        /// (data.Length == 65) Init() should be already called
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public unsafe void Compress65(byte* dPt, uint* hPt, uint* wPt)
        {
            // Set and compress first block (64 bytes)
            int dIndex = 0;
            for (int i = 0; i < 16; i++, dIndex += 4)
            {
                wPt[i] = (uint)((dPt[dIndex] << 24) | (dPt[dIndex + 1] << 16) | (dPt[dIndex + 2] << 8) | dPt[dIndex + 3]);
            }
            CompressBlock(hPt, wPt);

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

            CompressBlockWithWSet(hPt, wPt);
        }


        /// <summary>
        /// Computes double SHA256 hash for
        /// (data.Length == 16) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// <para/> Note: wPt[5], wPt[6], wPt[7] and wPt[8] must be set to zero on consecutive calls since 
        /// <see cref="DoSecondHash(uint*, uint*)"/> changes them.
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public unsafe void CompressDouble16(uint* hPt, uint* wPt)
        {
            // w4 = 0b10000000_10000000_00000000_00000000U
            // w5 to w14 = 0
            // w15 = 128
            wPt[16] = SSIG0(wPt[1]) + wPt[0];
            wPt[17] = 5242880 + SSIG0(wPt[2]) + wPt[1];
            wPt[18] = SSIG1(wPt[16]) + SSIG0(wPt[3]) + wPt[2];
            wPt[19] = SSIG1(wPt[17]) + 285220864 + wPt[3];
            wPt[20] = SSIG1(wPt[18]) + 2147483648;
            wPt[21] = SSIG1(wPt[19]);
            wPt[22] = SSIG1(wPt[20]) + 128;
            wPt[23] = SSIG1(wPt[21]) + wPt[16];
            wPt[24] = SSIG1(wPt[22]) + wPt[17];
            wPt[25] = SSIG1(wPt[23]) + wPt[18];
            wPt[26] = SSIG1(wPt[24]) + wPt[19];
            wPt[27] = SSIG1(wPt[25]) + wPt[20];
            wPt[28] = SSIG1(wPt[26]) + wPt[21];
            wPt[29] = SSIG1(wPt[27]) + wPt[22];
            wPt[30] = SSIG1(wPt[28]) + wPt[23] + 2097169;
            wPt[31] = SSIG1(wPt[29]) + wPt[24] + SSIG0(wPt[16]) + 128;
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


            CompressBlockWithWSet(hPt, wPt);

            // Perform second hash
            DoSecondHash(hPt, wPt);
        }

        /// <summary>
        /// Computes double SHA256 hash for
        /// (data.Length == 21) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// <para/> Note: wPt[6], wPt[7] and wPt[8] must be set to zero on consecutive calls since 
        /// <see cref="DoSecondHash(uint*, uint*)"/> changes them.
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public unsafe void CompressDouble21(uint* hPt, uint* wPt)
        {
            // w5 = extra values | 0b00000000_10000000_00000000_00000000U
            // w6 to w14 = 0
            // w15 = 168
            wPt[16] = SSIG0(wPt[1]) + wPt[0];
            wPt[17] = 4259840 + SSIG0(wPt[2]) + wPt[1];
            wPt[18] = SSIG1(wPt[16]) + SSIG0(wPt[3]) + wPt[2];
            wPt[19] = SSIG1(wPt[17]) + SSIG0(wPt[4]) + wPt[3];
            wPt[20] = SSIG1(wPt[18]) + SSIG0(wPt[5]) + wPt[4];
            wPt[21] = SSIG1(wPt[19]) + SSIG0(wPt[6]) + wPt[5];
            wPt[22] = SSIG1(wPt[20]) + 168 + wPt[6];
            wPt[23] = SSIG1(wPt[21]) + wPt[16];
            wPt[24] = SSIG1(wPt[22]) + wPt[17];
            wPt[25] = SSIG1(wPt[23]) + wPt[18];
            wPt[26] = SSIG1(wPt[24]) + wPt[19];
            wPt[27] = SSIG1(wPt[25]) + wPt[20];
            wPt[28] = SSIG1(wPt[26]) + wPt[21];
            wPt[29] = SSIG1(wPt[27]) + wPt[22];
            wPt[30] = SSIG1(wPt[28]) + wPt[23] + 1344929812;
            wPt[31] = SSIG1(wPt[29]) + wPt[24] + SSIG0(wPt[16]) + 168;
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

            CompressBlockWithWSet(hPt, wPt);

            // Perform second hash
            DoSecondHash(hPt, wPt);
        }

        /// <summary>
        /// Computes double SHA256 hash for
        /// (data.Length == 22) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// <para/> Note: wPt[6], wPt[7] and wPt[8] must be set to zero on consecutive calls since 
        /// <see cref="DoSecondHash(uint*, uint*)"/> changes them.
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public unsafe void CompressDouble22(uint* hPt, uint* wPt)
        {
            // w5 = extra values | 0b00000000_00000000_10000000_00000000U
            // w6 to w14 = 0
            // w15 = 176
            wPt[16] = SSIG0(wPt[1]) + wPt[0];
            wPt[17] = 5111808 + SSIG0(wPt[2]) + wPt[1];
            wPt[18] = SSIG1(wPt[16]) + SSIG0(wPt[3]) + wPt[2];
            wPt[19] = SSIG1(wPt[17]) + SSIG0(wPt[4]) + wPt[3];
            wPt[20] = SSIG1(wPt[18]) + SSIG0(wPt[5]) + wPt[4];
            wPt[21] = SSIG1(wPt[19]) + wPt[5];
            wPt[22] = SSIG1(wPt[20]) + 176;
            wPt[23] = SSIG1(wPt[21]) + wPt[16];
            wPt[24] = SSIG1(wPt[22]) + wPt[17];
            wPt[25] = SSIG1(wPt[23]) + wPt[18];
            wPt[26] = SSIG1(wPt[24]) + wPt[19];
            wPt[27] = SSIG1(wPt[25]) + wPt[20];
            wPt[28] = SSIG1(wPt[26]) + wPt[21];
            wPt[29] = SSIG1(wPt[27]) + wPt[22];
            wPt[30] = SSIG1(wPt[28]) + wPt[23] + 1613496343;
            wPt[31] = SSIG1(wPt[29]) + wPt[24] + SSIG0(wPt[16]) + 176;
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

            CompressBlockWithWSet(hPt, wPt);

            // Perform second hash
            DoSecondHash(hPt, wPt);
        }

        /// <summary>
        /// Computes double SHA256 hash for
        /// (data.Length == 23) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// <para/> Note: wPt[6], wPt[7] and wPt[8] must be set to zero on consecutive calls since 
        /// <see cref="DoSecondHash(uint*, uint*)"/> changes them.
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public unsafe void CompressDouble23(uint* hPt, uint* wPt)
        {
            // w5 = extra values | 0b00000000_00000000_00000000_10000000U
            // w6 to w14 = 0
            // w15 = 184
            wPt[16] = SSIG0(wPt[1]) + wPt[0];
            wPt[17] = 4915200 + SSIG0(wPt[2]) + wPt[1];
            wPt[18] = SSIG1(wPt[16]) + SSIG0(wPt[3]) + wPt[2];
            wPt[19] = SSIG1(wPt[17]) + SSIG0(wPt[4]) + wPt[3];
            wPt[20] = SSIG1(wPt[18]) + SSIG0(wPt[5]) + wPt[4];
            wPt[21] = SSIG1(wPt[19]) + wPt[5];
            wPt[22] = SSIG1(wPt[20]) + 184;
            wPt[23] = SSIG1(wPt[21]) + wPt[16];
            wPt[24] = SSIG1(wPt[22]) + wPt[17];
            wPt[25] = SSIG1(wPt[23]) + wPt[18];
            wPt[26] = SSIG1(wPt[24]) + wPt[19];
            wPt[27] = SSIG1(wPt[25]) + wPt[20];
            wPt[28] = SSIG1(wPt[26]) + wPt[21];
            wPt[29] = SSIG1(wPt[27]) + wPt[22];
            wPt[30] = SSIG1(wPt[28]) + wPt[23] + 1882062870;
            wPt[31] = SSIG1(wPt[29]) + wPt[24] + SSIG0(wPt[16]) + 184;
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

            CompressBlockWithWSet(hPt, wPt);

            // Perform second hash
            DoSecondHash(hPt, wPt);
        }

        /// <summary>
        /// Computes double SHA256 hash for
        /// (data.Length == 33) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public unsafe void CompressDouble33(uint* hPt, uint* wPt)
        {
            // w8 = extra values | 0b00000000_10000000_00000000_00000000U 
            // w9 to w14 = 0
            // w15 = 272
            wPt[16] = SSIG0(wPt[1]) + wPt[0];
            wPt[17] = 10813440 + SSIG0(wPt[2]) + wPt[1];
            wPt[18] = SSIG1(wPt[16]) + SSIG0(wPt[3]) + wPt[2];
            wPt[19] = SSIG1(wPt[17]) + SSIG0(wPt[4]) + wPt[3];
            wPt[20] = SSIG1(wPt[18]) + SSIG0(wPt[5]) + wPt[4];
            wPt[21] = SSIG1(wPt[19]) + SSIG0(wPt[6]) + wPt[5];
            wPt[22] = SSIG1(wPt[20]) + 264 + SSIG0(wPt[7]) + wPt[6];
            wPt[23] = SSIG1(wPt[21]) + wPt[16] + SSIG0(wPt[8]) + wPt[7];
            wPt[24] = SSIG1(wPt[22]) + wPt[17] + wPt[8];
            wPt[25] = SSIG1(wPt[23]) + wPt[18];
            wPt[26] = SSIG1(wPt[24]) + wPt[19];
            wPt[27] = SSIG1(wPt[25]) + wPt[20];
            wPt[28] = SSIG1(wPt[26]) + wPt[21];
            wPt[29] = SSIG1(wPt[27]) + wPt[22];
            wPt[30] = SSIG1(wPt[28]) + wPt[23] + 272760867;
            wPt[31] = SSIG1(wPt[29]) + wPt[24] + SSIG0(wPt[16]) + 264;
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

            CompressBlockWithWSet(hPt, wPt);

            // Perform second hash
            DoSecondHash(hPt, wPt);
        }

        /// <summary>
        /// Computes double SHA256 hash for
        /// (data.Length == 34) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public unsafe void CompressDouble34(uint* hPt, uint* wPt)
        {
            // w8 = extra values | 0b00000000_00000000_10000000_00000000U 
            // w9 to w14 = 0
            // w15 = 264
            wPt[16] = SSIG0(wPt[1]) + wPt[0];
            wPt[17] = 11141120 + SSIG0(wPt[2]) + wPt[1];
            wPt[18] = SSIG1(wPt[16]) + SSIG0(wPt[3]) + wPt[2];
            wPt[19] = SSIG1(wPt[17]) + SSIG0(wPt[4]) + wPt[3];
            wPt[20] = SSIG1(wPt[18]) + SSIG0(wPt[5]) + wPt[4];
            wPt[21] = SSIG1(wPt[19]) + SSIG0(wPt[6]) + wPt[5];
            wPt[22] = SSIG1(wPt[20]) + 272 + SSIG0(wPt[7]) + wPt[6];
            wPt[23] = SSIG1(wPt[21]) + wPt[16] + SSIG0(wPt[8]) + wPt[7];
            wPt[24] = SSIG1(wPt[22]) + wPt[17] + wPt[8];
            wPt[25] = SSIG1(wPt[23]) + wPt[18];
            wPt[26] = SSIG1(wPt[24]) + wPt[19];
            wPt[27] = SSIG1(wPt[25]) + wPt[20];
            wPt[28] = SSIG1(wPt[26]) + wPt[21];
            wPt[29] = SSIG1(wPt[27]) + wPt[22];
            wPt[30] = SSIG1(wPt[28]) + wPt[23] + 541327392;
            wPt[31] = SSIG1(wPt[29]) + wPt[24] + SSIG0(wPt[16]) + 272;
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

            CompressBlockWithWSet(hPt, wPt);

            // Perform second hash
            DoSecondHash(hPt, wPt);
        }

        /// <summary>
        /// Computes double SHA256 hash for
        /// (data.Length == 39) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public unsafe void CompressDouble39(uint* hPt, uint* wPt)
        {
            // w9 = extra values | 0b00000000_00000000_00000000_10000000U 
            // w10 to w14 = 0
            // w15 = 312
            wPt[16] = wPt[9] + SSIG0(wPt[1]) + wPt[0];
            wPt[17] = 12255232 + SSIG0(wPt[2]) + wPt[1];
            wPt[18] = SSIG1(wPt[16]) + SSIG0(wPt[3]) + wPt[2];
            wPt[19] = SSIG1(wPt[17]) + SSIG0(wPt[4]) + wPt[3];
            wPt[20] = SSIG1(wPt[18]) + SSIG0(wPt[5]) + wPt[4];
            wPt[21] = SSIG1(wPt[19]) + SSIG0(wPt[6]) + wPt[5];
            wPt[22] = SSIG1(wPt[20]) + 312 + SSIG0(wPt[7]) + wPt[6];
            wPt[23] = SSIG1(wPt[21]) + wPt[16] + SSIG0(wPt[8]) + wPt[7];
            wPt[24] = SSIG1(wPt[22]) + wPt[17] + SSIG0(wPt[9]) + wPt[8];
            wPt[25] = SSIG1(wPt[23]) + wPt[18] + wPt[9];
            wPt[26] = SSIG1(wPt[24]) + wPt[19];
            wPt[27] = SSIG1(wPt[25]) + wPt[20];
            wPt[28] = SSIG1(wPt[26]) + wPt[21];
            wPt[29] = SSIG1(wPt[27]) + wPt[22];
            wPt[30] = SSIG1(wPt[28]) + wPt[23] + 1884160037;
            wPt[31] = SSIG1(wPt[29]) + wPt[24] + SSIG0(wPt[16]) + 312;
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

            CompressBlockWithWSet(hPt, wPt);

            // Perform second hash
            DoSecondHash(hPt, wPt);
        }

        /// <summary>
        /// Computes double SHA256 hash for
        /// (data.Length == 65)
        /// </summary>
        /// <param name="data">65 byte data</param>
        public unsafe byte[] CompressDouble65(byte[] data)
        {
            Debug.Assert(data != null && data.Length == 65);

            fixed (byte* dPt = &data[0])
            fixed (uint* hPt = &hashState[0], wPt = &w[0])
            {
                Init(hPt);
                Compress65(dPt, hPt, wPt);
                DoSecondHash(hPt, wPt);
                return GetBytes(hPt);
            }
        }

        internal unsafe void DoSecondHash(uint* hPt, uint* wPt)
        {
            // Result of previous hash (hashState[]) is now our new block. So copy it here:
            wPt[0] = hPt[0];
            wPt[1] = hPt[1];
            wPt[2] = hPt[2];
            wPt[3] = hPt[3];
            wPt[4] = hPt[4];
            wPt[5] = hPt[5];
            wPt[6] = hPt[6];
            wPt[7] = hPt[7]; // 8*4 = 32 byte hash result

            wPt[8] = 0b10000000_00000000_00000000_00000000U; // 1 followed by 0 bits to fill pad1
            wPt[9] = 0;
            wPt[10] = 0;
            wPt[11] = 0;
            wPt[12] = 0;
            wPt[13] = 0;

            wPt[14] = 0; // Message length for pad2, since message is the 32 byte result of previous hash, length is 256 bit
            wPt[15] = 256;

            // Set the rest of working vector from 16 to 64
            wPt[16] = SSIG0(wPt[1]) + wPt[0];
            wPt[17] = 10485760 + SSIG0(wPt[2]) + wPt[1];
            wPt[18] = SSIG1(wPt[16]) + SSIG0(wPt[3]) + wPt[2];
            wPt[19] = SSIG1(wPt[17]) + SSIG0(wPt[4]) + wPt[3];
            wPt[20] = SSIG1(wPt[18]) + SSIG0(wPt[5]) + wPt[4];
            wPt[21] = SSIG1(wPt[19]) + SSIG0(wPt[6]) + wPt[5];
            wPt[22] = SSIG1(wPt[20]) + 256 + SSIG0(wPt[7]) + wPt[6];
            wPt[23] = SSIG1(wPt[21]) + wPt[16] + 285220864 + wPt[7];
            wPt[24] = SSIG1(wPt[22]) + wPt[17] + 0b10000000_00000000_00000000_00000000U;
            wPt[25] = SSIG1(wPt[23]) + wPt[18];
            wPt[26] = SSIG1(wPt[24]) + wPt[19];
            wPt[27] = SSIG1(wPt[25]) + wPt[20];
            wPt[28] = SSIG1(wPt[26]) + wPt[21];
            wPt[29] = SSIG1(wPt[27]) + wPt[22];
            wPt[30] = SSIG1(wPt[28]) + wPt[23] + 4194338;
            wPt[31] = SSIG1(wPt[29]) + wPt[24] + SSIG0(wPt[16]) + 256;
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


            // Now initialize hashState to compute next round, since this is a new hash
            Init(hPt);

            // We only have 1 block so there is no need for a loop.
            CompressBlockWithWSet(hPt, wPt);
        }

        public unsafe void SetW(uint* wPt, int start = 16)
        {
            for (int i = start; i < w.Length; i++)
            {
                wPt[i] = SSIG1(wPt[i - 2]) + wPt[i - 7] + SSIG0(wPt[i - 15]) + wPt[i - 16];
            }
        }

        // This method will become obsolete soon:
        internal unsafe void CompressBlock(uint* hPt, uint* wPt)
        {
            for (int i = 16; i < w.Length; i++)
            {
                wPt[i] = SSIG1(wPt[i - 2]) + wPt[i - 7] + SSIG0(wPt[i - 15]) + wPt[i - 16];
            }

            uint a = hPt[0];
            uint b = hPt[1];
            uint c = hPt[2];
            uint d = hPt[3];
            uint e = hPt[4];
            uint f = hPt[5];
            uint g = hPt[6];
            uint h = hPt[7];

            uint temp, aa, bb, cc, dd, ee, ff, hh, gg;

            fixed (uint* kPt = &Ks[0])
            {
                for (int j = 0; j < 64;)
                {
                    temp = h + BSIG1(e) + CH(e, f, g) + kPt[j] + wPt[j];
                    ee = d + temp;
                    aa = temp + BSIG0(a) + MAJ(a, b, c);
                    j++;

                    temp = g + BSIG1(ee) + CH(ee, e, f) + kPt[j] + wPt[j];
                    ff = c + temp;
                    bb = temp + BSIG0(aa) + MAJ(aa, a, b);
                    j++;

                    temp = f + BSIG1(ff) + CH(ff, ee, e) + kPt[j] + wPt[j];
                    gg = b + temp;
                    cc = temp + BSIG0(bb) + MAJ(bb, aa, a);
                    j++;

                    temp = e + BSIG1(gg) + CH(gg, ff, ee) + kPt[j] + wPt[j];
                    hh = a + temp;
                    dd = temp + BSIG0(cc) + MAJ(cc, bb, aa);
                    j++;

                    temp = ee + BSIG1(hh) + CH(hh, gg, ff) + kPt[j] + wPt[j];
                    h = aa + temp;
                    d = temp + BSIG0(dd) + MAJ(dd, cc, bb);
                    j++;

                    temp = ff + BSIG1(h) + CH(h, hh, gg) + kPt[j] + wPt[j];
                    g = bb + temp;
                    c = temp + BSIG0(d) + MAJ(d, dd, cc);
                    j++;

                    temp = gg + BSIG1(g) + CH(g, h, hh) + kPt[j] + wPt[j];
                    f = cc + temp;
                    b = temp + BSIG0(c) + MAJ(c, d, dd);
                    j++;

                    temp = hh + BSIG1(f) + CH(f, g, h) + kPt[j] + wPt[j];
                    e = dd + temp;
                    a = temp + BSIG0(b) + MAJ(b, c, d);
                    j++;
                }
            }

            hPt[0] += a;
            hPt[1] += b;
            hPt[2] += c;
            hPt[3] += d;
            hPt[4] += e;
            hPt[5] += f;
            hPt[6] += g;
            hPt[7] += h;
        }

        internal unsafe void CompressBlockWithWSet(uint* hPt, uint* wPt)
        {
            uint a = hPt[0];
            uint b = hPt[1];
            uint c = hPt[2];
            uint d = hPt[3];
            uint e = hPt[4];
            uint f = hPt[5];
            uint g = hPt[6];
            uint h = hPt[7];

            uint temp, aa, bb, cc, dd, ee, ff, hh, gg;

            fixed (uint* kPt = &Ks[0])
            {
                for (int j = 0; j < 64;)
                {
                    temp = h + BSIG1(e) + CH(e, f, g) + kPt[j] + wPt[j];
                    ee = d + temp;
                    aa = temp + BSIG0(a) + MAJ(a, b, c);
                    j++;

                    temp = g + BSIG1(ee) + CH(ee, e, f) + kPt[j] + wPt[j];
                    ff = c + temp;
                    bb = temp + BSIG0(aa) + MAJ(aa, a, b);
                    j++;

                    temp = f + BSIG1(ff) + CH(ff, ee, e) + kPt[j] + wPt[j];
                    gg = b + temp;
                    cc = temp + BSIG0(bb) + MAJ(bb, aa, a);
                    j++;

                    temp = e + BSIG1(gg) + CH(gg, ff, ee) + kPt[j] + wPt[j];
                    hh = a + temp;
                    dd = temp + BSIG0(cc) + MAJ(cc, bb, aa);
                    j++;

                    temp = ee + BSIG1(hh) + CH(hh, gg, ff) + kPt[j] + wPt[j];
                    h = aa + temp;
                    d = temp + BSIG0(dd) + MAJ(dd, cc, bb);
                    j++;

                    temp = ff + BSIG1(h) + CH(h, hh, gg) + kPt[j] + wPt[j];
                    g = bb + temp;
                    c = temp + BSIG0(d) + MAJ(d, dd, cc);
                    j++;

                    temp = gg + BSIG1(g) + CH(g, h, hh) + kPt[j] + wPt[j];
                    f = cc + temp;
                    b = temp + BSIG0(c) + MAJ(c, d, dd);
                    j++;

                    temp = hh + BSIG1(f) + CH(f, g, h) + kPt[j] + wPt[j];
                    e = dd + temp;
                    a = temp + BSIG0(b) + MAJ(b, c, d);
                    j++;
                }
            }

            hPt[0] += a;
            hPt[1] += b;
            hPt[2] += c;
            hPt[3] += d;
            hPt[4] += e;
            hPt[5] += f;
            hPt[6] += g;
            hPt[7] += h;
        }


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint CH(uint x, uint y, uint z) => z ^ (x & (y ^ z));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint MAJ(uint x, uint y, uint z) => (x & y) | (z & (x | y));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint BSIG0(uint x) => (x >> 2 | x << 30) ^ (x >> 13 | x << 19) ^ (x >> 22 | x << 10);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint BSIG1(uint x) => (x >> 6 | x << 26) ^ (x >> 11 | x << 21) ^ (x >> 25 | x << 7);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal uint SSIG0(uint x) => (x >> 7 | x << 25) ^ (x >> 18 | x << 14) ^ (x >> 3);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal uint SSIG1(uint x) => (x >> 17 | x << 15) ^ (x >> 19 | x << 13) ^ (x >> 10);


        private bool disposedValue = false;

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    if (hashState != null)
                        Array.Clear(hashState, 0, hashState.Length);
                    hashState = null;

                    if (w != null)
                        Array.Clear(w, 0, w.Length);
                    w = null;
                }

                disposedValue = true;
            }
        }

        /// <summary>
        /// Releases all resources used by the current instance of the <see cref="Sha256Fo"/> class.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
        }
    }
}
