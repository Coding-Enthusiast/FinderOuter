// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System.Runtime.CompilerServices;

namespace FinderOuter.Backend.ECC
{
    public readonly struct PointStorage
    {
        public PointStorage(in UInt256_10x26 x26, in UInt256_10x26 y26)
        {
            x = x26.Normalize().ToUInt256_8x32();
            y = y26.Normalize().ToUInt256_8x32();
        }

        public PointStorage(in UInt256_8x32 x32, in UInt256_8x32 y32)
        {
            x = x32;
            y = y32;
        }


        public readonly UInt256_8x32 x, y;


        public readonly Point ToPoint() => new(x.ToUInt256_10x26(), y.ToUInt256_10x26());


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void CMov(ref PointStorage r, in PointStorage a, int flag)
        {
            UInt256_8x32 rx = r.x;
            UInt256_8x32 ry = r.y;
            UInt256_8x32.CMov(ref rx, a.x, flag);
            UInt256_8x32.CMov(ref ry, a.y, flag);
            r = new PointStorage(rx, ry);
        }
    }
}
