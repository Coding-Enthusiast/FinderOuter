// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System;
using System.Diagnostics;

namespace FinderOuter.Backend.Hashing
{
    /// <summary>
    /// Performs RIPEMD160 hash function on the result of SHA256 also known as HASH160
    /// <para/> This is more optimized and a lot faster than using .Net functions individually 
    /// specially when computing hash for small byte arrays such as 33 bytes (bitcoin public keys used in P2PKH scripts)
    /// </summary>
    public static class Hash160Fo
    {
        /// <summary>
        /// Size of the hash result in bytes.
        /// </summary>
        public const int HashByteSize = 20;


        public static unsafe byte[] Compress22(Span<byte> data)
        {
            uint* pt = stackalloc uint[Sha256Fo.UBufferSize];
            fixed (byte* dPt = data)
            {
                // Step 1: compute SHA256 of data then copy result of hash (HashState) into RIPEMD160 block
                Sha256Fo.Init(pt);

                pt[8] = (uint)((dPt[0] << 24) | (dPt[1] << 16) | (dPt[2] << 8) | dPt[3]);
                pt[9] = (uint)((dPt[4] << 24) | (dPt[5] << 16) | (dPt[6] << 8) | dPt[7]);
                pt[10] = (uint)((dPt[8] << 24) | (dPt[9] << 16) | (dPt[10] << 8) | dPt[11]);
                pt[11] = (uint)((dPt[12] << 24) | (dPt[13] << 16) | (dPt[14] << 8) | dPt[15]);
                pt[12] = (uint)((dPt[16] << 24) | (dPt[17] << 16) | (dPt[18] << 8) | dPt[19]);
                pt[13] = (uint)((dPt[20] << 24) | (dPt[21] << 16) | 0b00000000_00000000_10000000_00000000U);
                pt[23] = 176; // 22*8

                Sha256Fo.Compress22(pt);

                // First 8 items (32 byte) of pt is SHA256 hashState now and has to be converted to RIPEMD160 block
                // SHA256 and RIPEMD160 use different endianness
                // RIPMED160 hashState is 20 bytes (or 5 items) and block starts from 6th item (index 5)
                // Set in reverse since each item is going to change
                pt[12] = (pt[7] >> 24) | (pt[7] << 24) | ((pt[7] >> 8) & 0xff00) | ((pt[7] << 8) & 0xff0000);
                pt[11] = (pt[6] >> 24) | (pt[6] << 24) | ((pt[6] >> 8) & 0xff00) | ((pt[6] << 8) & 0xff0000);
                pt[10] = (pt[5] >> 24) | (pt[5] << 24) | ((pt[5] >> 8) & 0xff00) | ((pt[5] << 8) & 0xff0000);
                pt[9] = (pt[4] >> 24) | (pt[4] << 24) | ((pt[4] >> 8) & 0xff00) | ((pt[4] << 8) & 0xff0000);
                pt[8] = (pt[3] >> 24) | (pt[3] << 24) | ((pt[3] >> 8) & 0xff00) | ((pt[3] << 8) & 0xff0000);
                pt[7] = (pt[2] >> 24) | (pt[2] << 24) | ((pt[2] >> 8) & 0xff00) | ((pt[2] << 8) & 0xff0000);
                pt[6] = (pt[1] >> 24) | (pt[1] << 24) | ((pt[1] >> 8) & 0xff00) | ((pt[1] << 8) & 0xff0000);
                pt[5] = (pt[0] >> 24) | (pt[0] << 24) |                       // Swap byte 1 and 4
                        ((pt[0] >> 8) & 0xff00) | ((pt[0] << 8) & 0xff0000);  // Swap byte 2 and 3
                pt[13] = 0b00000000_00000000_00000000_10000000U;
                pt[19] = 256;

                Ripemd160Fo.Init(pt);
                Ripemd160Fo.CompressBlock(pt);

                return Ripemd160Fo.GetBytes(pt);
            }
        }

        /// <summary>
        /// Returns HASH160(OP_0 | Push(HASH160(33_bytes)))
        /// </summary>
        public static unsafe byte[] Compress33_P2sh(Span<byte> data)
        {
            uint* pt = stackalloc uint[Sha256Fo.UBufferSize];
            fixed (byte* dPt = data)
            {
                pt[8] = (uint)((dPt[0] << 24) | (dPt[1] << 16) | (dPt[2] << 8) | dPt[3]);
                pt[9] = (uint)((dPt[4] << 24) | (dPt[5] << 16) | (dPt[6] << 8) | dPt[7]);
                pt[10] = (uint)((dPt[8] << 24) | (dPt[9] << 16) | (dPt[10] << 8) | dPt[11]);
                pt[11] = (uint)((dPt[12] << 24) | (dPt[13] << 16) | (dPt[14] << 8) | dPt[15]);
                pt[12] = (uint)((dPt[16] << 24) | (dPt[17] << 16) | (dPt[18] << 8) | dPt[19]);
                pt[13] = (uint)((dPt[20] << 24) | (dPt[21] << 16) | (dPt[22] << 8) | dPt[23]);
                pt[14] = (uint)((dPt[24] << 24) | (dPt[25] << 16) | (dPt[26] << 8) | dPt[27]);
                pt[15] = (uint)((dPt[28] << 24) | (dPt[29] << 16) | (dPt[30] << 8) | dPt[31]);
                pt[16] = (uint)((dPt[32] << 24) | 0b00000000_10000000_00000000_00000000U);
                pt[23] = 264;

                Sha256Fo.Init(pt);
                Sha256Fo.Compress33(pt);

                pt[12] = (pt[7] >> 24) | (pt[7] << 24) | ((pt[7] >> 8) & 0xff00) | ((pt[7] << 8) & 0xff0000);
                pt[11] = (pt[6] >> 24) | (pt[6] << 24) | ((pt[6] >> 8) & 0xff00) | ((pt[6] << 8) & 0xff0000);
                pt[10] = (pt[5] >> 24) | (pt[5] << 24) | ((pt[5] >> 8) & 0xff00) | ((pt[5] << 8) & 0xff0000);
                pt[9] = (pt[4] >> 24) | (pt[4] << 24) | ((pt[4] >> 8) & 0xff00) | ((pt[4] << 8) & 0xff0000);
                pt[8] = (pt[3] >> 24) | (pt[3] << 24) | ((pt[3] >> 8) & 0xff00) | ((pt[3] << 8) & 0xff0000);
                pt[7] = (pt[2] >> 24) | (pt[2] << 24) | ((pt[2] >> 8) & 0xff00) | ((pt[2] << 8) & 0xff0000);
                pt[6] = (pt[1] >> 24) | (pt[1] << 24) | ((pt[1] >> 8) & 0xff00) | ((pt[1] << 8) & 0xff0000);
                pt[5] = (pt[0] >> 24) | (pt[0] << 24) |                       // Swap byte 1 and 4
                        ((pt[0] >> 8) & 0xff00) | ((pt[0] << 8) & 0xff0000);  // Swap byte 2 and 3
                pt[13] = 0b00000000_00000000_00000000_10000000U;
                pt[14] = 0;
                pt[15] = 0;
                pt[16] = 0;
                pt[19] = 256;

                Ripemd160Fo.Init(pt);
                Ripemd160Fo.CompressBlock(pt);

                // Compute second HASH160
                pt[8] = 0x00140000U | ((pt[0] << 8) & 0xff00) | ((pt[0] >> 8) & 0xff);
                pt[9] = ((pt[0] << 8) & 0xff000000) | ((pt[0] >> 8) & 0x00ff0000) |
                        ((pt[1] << 8) & 0x0000ff00) | ((pt[1] >> 8) & 0x000000ff);
                pt[10] = ((pt[1] << 8) & 0xff000000) | ((pt[1] >> 8) & 0x00ff0000) |
                         ((pt[2] << 8) & 0x0000ff00) | ((pt[2] >> 8) & 0x000000ff);
                pt[11] = ((pt[2] << 8) & 0xff000000) | ((pt[2] >> 8) & 0x00ff0000) |
                         ((pt[3] << 8) & 0x0000ff00) | ((pt[3] >> 8) & 0x000000ff);
                pt[12] = ((pt[3] << 8) & 0xff000000) | ((pt[3] >> 8) & 0x00ff0000) |
                         ((pt[4] << 8) & 0x0000ff00) | ((pt[4] >> 8) & 0x000000ff);
                pt[13] = ((pt[4] << 8) & 0xff000000) | ((pt[4] >> 8) & 0x00ff0000) |
                         0b00000000_00000000_10000000_00000000U;
                pt[19] = 0;
                pt[23] = 176; // 22*8

                Sha256Fo.Init(pt);
                Sha256Fo.Compress22(pt);

                pt[12] = (pt[7] >> 24) | (pt[7] << 24) | ((pt[7] >> 8) & 0xff00) | ((pt[7] << 8) & 0xff0000);
                pt[11] = (pt[6] >> 24) | (pt[6] << 24) | ((pt[6] >> 8) & 0xff00) | ((pt[6] << 8) & 0xff0000);
                pt[10] = (pt[5] >> 24) | (pt[5] << 24) | ((pt[5] >> 8) & 0xff00) | ((pt[5] << 8) & 0xff0000);
                pt[9] = (pt[4] >> 24) | (pt[4] << 24) | ((pt[4] >> 8) & 0xff00) | ((pt[4] << 8) & 0xff0000);
                pt[8] = (pt[3] >> 24) | (pt[3] << 24) | ((pt[3] >> 8) & 0xff00) | ((pt[3] << 8) & 0xff0000);
                pt[7] = (pt[2] >> 24) | (pt[2] << 24) | ((pt[2] >> 8) & 0xff00) | ((pt[2] << 8) & 0xff0000);
                pt[6] = (pt[1] >> 24) | (pt[1] << 24) | ((pt[1] >> 8) & 0xff00) | ((pt[1] << 8) & 0xff0000);
                pt[5] = (pt[0] >> 24) | (pt[0] << 24) |                       // Swap byte 1 and 4
                        ((pt[0] >> 8) & 0xff00) | ((pt[0] << 8) & 0xff0000);  // Swap byte 2 and 3
                pt[13] = 0b00000000_00000000_00000000_10000000U;
                pt[14] = 0;
                pt[15] = 0;
                pt[16] = 0;
                pt[19] = 256;

                Ripemd160Fo.Init(pt);
                Ripemd160Fo.CompressBlock(pt);

                return Ripemd160Fo.GetBytes(pt);
            }
        }

        public static unsafe byte[] Compress33(Span<byte> data)
        {
            uint* pt = stackalloc uint[Sha256Fo.UBufferSize];
            fixed (byte* dPt = data)
            {
                pt[8] = (uint)((dPt[0] << 24) | (dPt[1] << 16) | (dPt[2] << 8) | dPt[3]);
                pt[9] = (uint)((dPt[4] << 24) | (dPt[5] << 16) | (dPt[6] << 8) | dPt[7]);
                pt[10] = (uint)((dPt[8] << 24) | (dPt[9] << 16) | (dPt[10] << 8) | dPt[11]);
                pt[11] = (uint)((dPt[12] << 24) | (dPt[13] << 16) | (dPt[14] << 8) | dPt[15]);
                pt[12] = (uint)((dPt[16] << 24) | (dPt[17] << 16) | (dPt[18] << 8) | dPt[19]);
                pt[13] = (uint)((dPt[20] << 24) | (dPt[21] << 16) | (dPt[22] << 8) | dPt[23]);
                pt[14] = (uint)((dPt[24] << 24) | (dPt[25] << 16) | (dPt[26] << 8) | dPt[27]);
                pt[15] = (uint)((dPt[28] << 24) | (dPt[29] << 16) | (dPt[30] << 8) | dPt[31]);
                pt[16] = (uint)((dPt[32] << 24) | 0b00000000_10000000_00000000_00000000U);
                pt[23] = 264;

                Sha256Fo.Init(pt);
                Sha256Fo.Compress33(pt);

                // Compute RIPEMD160
                pt[12] = (pt[7] >> 24) | (pt[7] << 24) | ((pt[7] >> 8) & 0xff00) | ((pt[7] << 8) & 0xff0000);
                pt[11] = (pt[6] >> 24) | (pt[6] << 24) | ((pt[6] >> 8) & 0xff00) | ((pt[6] << 8) & 0xff0000);
                pt[10] = (pt[5] >> 24) | (pt[5] << 24) | ((pt[5] >> 8) & 0xff00) | ((pt[5] << 8) & 0xff0000);
                pt[9] = (pt[4] >> 24) | (pt[4] << 24) | ((pt[4] >> 8) & 0xff00) | ((pt[4] << 8) & 0xff0000);
                pt[8] = (pt[3] >> 24) | (pt[3] << 24) | ((pt[3] >> 8) & 0xff00) | ((pt[3] << 8) & 0xff0000);
                pt[7] = (pt[2] >> 24) | (pt[2] << 24) | ((pt[2] >> 8) & 0xff00) | ((pt[2] << 8) & 0xff0000);
                pt[6] = (pt[1] >> 24) | (pt[1] << 24) | ((pt[1] >> 8) & 0xff00) | ((pt[1] << 8) & 0xff0000);
                pt[5] = (pt[0] >> 24) | (pt[0] << 24) |                       // Swap byte 1 and 4
                        ((pt[0] >> 8) & 0xff00) | ((pt[0] << 8) & 0xff0000);  // Swap byte 2 and 3
                pt[13] = 0b00000000_00000000_00000000_10000000U;
                pt[14] = 0;
                pt[15] = 0;
                pt[16] = 0;
                pt[19] = 256;

                Ripemd160Fo.Init(pt);
                Ripemd160Fo.CompressBlock(pt);

                return Ripemd160Fo.GetBytes(pt);
            }
        }

        public static unsafe byte[] Compress65(Span<byte> data)
        {
            Debug.Assert(data != null && data.Length == 65);

            uint* pt = stackalloc uint[Sha256Fo.UBufferSize];
            fixed (byte* dPt = &data[0])
            {
                Sha256Fo.Init(pt);
                Sha256Fo.Compress65(pt, dPt);

                // Compute RIPEMD160
                pt[12] = (pt[7] >> 24) | (pt[7] << 24) | ((pt[7] >> 8) & 0xff00) | ((pt[7] << 8) & 0xff0000);
                pt[11] = (pt[6] >> 24) | (pt[6] << 24) | ((pt[6] >> 8) & 0xff00) | ((pt[6] << 8) & 0xff0000);
                pt[10] = (pt[5] >> 24) | (pt[5] << 24) | ((pt[5] >> 8) & 0xff00) | ((pt[5] << 8) & 0xff0000);
                pt[9] = (pt[4] >> 24) | (pt[4] << 24) | ((pt[4] >> 8) & 0xff00) | ((pt[4] << 8) & 0xff0000);
                pt[8] = (pt[3] >> 24) | (pt[3] << 24) | ((pt[3] >> 8) & 0xff00) | ((pt[3] << 8) & 0xff0000);
                pt[7] = (pt[2] >> 24) | (pt[2] << 24) | ((pt[2] >> 8) & 0xff00) | ((pt[2] << 8) & 0xff0000);
                pt[6] = (pt[1] >> 24) | (pt[1] << 24) | ((pt[1] >> 8) & 0xff00) | ((pt[1] << 8) & 0xff0000);
                pt[5] = (pt[0] >> 24) | (pt[0] << 24) |                       // Swap byte 1 and 4
                        ((pt[0] >> 8) & 0xff00) | ((pt[0] << 8) & 0xff0000);  // Swap byte 2 and 3
                pt[13] = 0b00000000_00000000_00000000_10000000U;
                pt[14] = 0;
                pt[15] = 0;
                pt[16] = 0;
                pt[17] = 0;
                pt[18] = 0;
                pt[19] = 256;
                pt[20] = 0;

                Ripemd160Fo.Init(pt);
                Ripemd160Fo.CompressBlock(pt);

                return Ripemd160Fo.GetBytes(pt);
            }
        }
    }
}
