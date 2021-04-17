// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System.Runtime.CompilerServices;

namespace FinderOuter.Backend.ECC
{
    /// <summary>
    /// 256-bit unsigned integer using radix-2^32 representation
    /// </summary>
    public readonly struct UInt256_8x32
    {
        public UInt256_8x32(uint u0, uint u1, uint u2, uint u3, uint u4, uint u5, uint u6, uint u7)
        {
            b0 = u0; b1 = u1; b2 = u2; b3 = u3;
            b4 = u4; b5 = u5; b6 = u6; b7 = u7;
        }


        public readonly uint b0, b1, b2, b3, b4, b5, b6, b7;


        public readonly UInt256_10x26 ToUInt256_10x26()
        {
            uint r0 = b0 & 0x03FFFFFFU;
            uint r1 = b0 >> 26 | ((b1 << 6) & 0x03FFFFFFU);
            uint r2 = b1 >> 20 | ((b2 << 12) & 0x03FFFFFFU);
            uint r3 = b2 >> 14 | ((b3 << 18) & 0x03FFFFFFU);
            uint r4 = b3 >> 8 | ((b4 << 24) & 0x03FFFFFFU);
            uint r5 = (b4 >> 2) & 0x03FFFFFFU;
            uint r6 = b4 >> 28 | ((b5 << 4) & 0x03FFFFFFU);
            uint r7 = b5 >> 22 | ((b6 << 10) & 0x03FFFFFFU);
            uint r8 = b6 >> 16 | ((b7 << 16) & 0x03FFFFFFU);
            uint r9 = b7 >> 10;

            return new UInt256_10x26(r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, 1, true);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void CMov(ref UInt256_8x32 r, in UInt256_8x32 a, int flag)
        {
            uint mask0, mask1;
            mask0 = (uint)flag + ~(uint)0;
            mask1 = ~mask0;
            r = new UInt256_8x32(
                (r.b0 & mask0) | (a.b0 & mask1),
                (r.b1 & mask0) | (a.b1 & mask1),
                (r.b2 & mask0) | (a.b2 & mask1),
                (r.b3 & mask0) | (a.b3 & mask1),
                (r.b4 & mask0) | (a.b4 & mask1),
                (r.b5 & mask0) | (a.b5 & mask1),
                (r.b6 & mask0) | (a.b6 & mask1),
                (r.b7 & mask0) | (a.b7 & mask1));
        }
    }
}
