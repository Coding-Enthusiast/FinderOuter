// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System.Runtime.CompilerServices;

namespace FinderOuter.Backend.ECC
{
    /// <summary>
    /// 256-bit unsigned integer using radix-2^64 representation
    /// </summary>
    public readonly struct UInt256_4x64
    {
        public UInt256_4x64(ulong u0, ulong u1, ulong u2, ulong u3)
        {
            b0 = u0;
            b1 = u1;
            b2 = u2;
            b3 = u3;
        }


        private readonly ulong b0, b1, b2, b3;


        public readonly UInt256_5x52 ToUInt256_5x52() => new(b0, b1, b2, b3);


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void CMov(ref UInt256_4x64 r, in UInt256_4x64 a, int flag)
        {
            ulong mask0, mask1;
            mask0 = (ulong)flag + ~(ulong)0;
            mask1 = ~mask0;
            r = new UInt256_4x64(
                (r.b0 & mask0) | (a.b0 & mask1),
                (r.b1 & mask0) | (a.b1 & mask1),
                (r.b2 & mask0) | (a.b2 & mask1),
                (r.b3 & mask0) | (a.b3 & mask1));
        }
    }
}
