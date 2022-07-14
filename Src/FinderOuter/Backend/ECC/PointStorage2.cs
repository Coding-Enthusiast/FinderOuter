// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System.Runtime.CompilerServices;

namespace FinderOuter.Backend.ECC
{
    public readonly struct PointStorage2
    {
        public PointStorage2(in UInt256_5x52 x52, in UInt256_5x52 y52)
        {
            x = x52.Normalize().ToUInt256_4x64();
            y = y52.Normalize().ToUInt256_4x64();
        }

        public PointStorage2(in UInt256_4x64 x32, in UInt256_4x64 y32)
        {
            x = x32;
            y = y32;
        }


        public readonly UInt256_4x64 x, y;


        public readonly Point2 ToPoint() => new(x.ToUInt256_5x52(), y.ToUInt256_5x52());


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void CMov(ref PointStorage2 r, in PointStorage2 a, int flag)
        {
            UInt256_4x64 rx = r.x;
            UInt256_4x64 ry = r.y;
            UInt256_4x64.CMov(ref rx, a.x, flag);
            UInt256_4x64.CMov(ref ry, a.y, flag);
            r = new PointStorage2(rx, ry);
        }
    }
}
