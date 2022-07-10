// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

namespace FinderOuter.Backend.ECC
{
    public readonly struct UInt128
    {
        public UInt128(ulong u0, ulong u1)
        {
            b0 = u0;
            b1 = u1;
        }

        public UInt128(uint u0, uint u1, uint u2, uint u3)
        {
            b0 = u0 | (ulong)u1 << 32;
            b1 = u2 | (ulong)u3 << 32;
        }

        public UInt128(int i)
        {
            b0 = (ulong)i;
            b1 = 0;
        }


        public readonly ulong b0, b1;


        public bool IsEven => (b0 & 1) == 0;
        public bool IsOne => b0 == 1 && b1 == 0;
        public bool IsZero => (b0 | b1) == 0;


        public static UInt128 operator +(UInt128 left, UInt128 right)
        {
            ulong u0 = left.b0 + right.b0;
            ulong u1 = left.b1 + right.b1 + ((u0 < left.b0) ? 1U : 0U);
            return new UInt128(u0, u1);
        }
        public static UInt128 operator +(UInt128 left, ulong right)
        {
            ulong u0 = left.b0 + right;
            ulong u1 = left.b1 + ((u0 < left.b0) ? 1U : 0U);
            return new UInt128(u0, u1);
        }


        public static UInt128 operator *(UInt128 left, UInt128 right)
        {
            uint x0 = (uint)left.b0;
            uint x1 = (uint)(left.b0 >> 32);
            uint x2 = (uint)left.b1;
            uint x3 = (uint)(left.b1 >> 32);
            uint y0 = (uint)right.b0;
            uint y1 = (uint)(right.b0 >> 32);
            uint y2 = (uint)right.b1;
            uint y3 = (uint)(right.b1 >> 32);

            ulong uv = x0 * y0;
            uint w0 = (uint)uv; ulong c = uv >> 32;
            uv = (x1 * y0) + c;
            uint w1 = (uint)uv; c = uv >> 32;
            uv = (x2 * y0) + c;
            uint w2 = (uint)uv; c = uv >> 32;
            uv = (x3 * y0) + c;
            uint w3 = (uint)uv;

            uv = w1 + (x0 * y1);
            w1 = (uint)uv; c = uv >> 32;
            uv = w2 + (x1 * y1) + c;
            w2 = (uint)uv; c = uv >> 32;
            uv = w3 + (x2 * y1) + c;
            w3 = (uint)uv;

            uv = w2 + (x0 * y2);
            w2 = (uint)uv; c = uv >> 32;
            uv = w3 + (x1 * y2) + c;
            w3 = (uint)uv;

            uv = w3 + (x0 * y3);
            w3 = (uint)uv;

            return new UInt128(w0, w1, w2, w3);
        }
        public static UInt128 operator *(UInt128 left, ulong right)
        {
            uint x0 = (uint)left.b0;
            uint x1 = (uint)(left.b0 >> 32);
            uint x2 = (uint)left.b1;
            uint x3 = (uint)(left.b1 >> 32);
            uint y0 = (uint)right;
            uint y1 = (uint)(right >> 32);

            ulong uv = x0 * y0;
            uint w0 = (uint)uv; ulong c = uv >> 32;
            uv = (x1 * y0) + c;
            uint w1 = (uint)uv; c = uv >> 32;
            uv = (x2 * y0) + c;
            uint w2 = (uint)uv; c = uv >> 32;
            uv = (x3 * y0) + c;
            uint w3 = (uint)uv;

            uv = w1 + (x0 * y1);
            w1 = (uint)uv; c = uv >> 32;
            uv = w2 + (x1 * y1) + c;
            w2 = (uint)uv; c = uv >> 32;
            uv = w3 + (x2 * y1) + c;
            w3 = (uint)uv;

            return new UInt128(w0, w1, w2, w3);
        }

        public static UInt128 operator &(UInt128 left, UInt128 right) => new(left.b0 & right.b0, left.b1 & right.b1);
        public static UInt128 operator &(UInt128 left, ulong right) => new(left.b0 & right, left.b1);
        public static UInt128 operator |(UInt128 left, UInt128 right) => new(left.b0 | right.b0, left.b1 | right.b1);
        public static UInt128 operator ^(UInt128 left, UInt128 right) => new(left.b0 ^ right.b0, left.b1 ^ right.b1);

        public static UInt128 operator >>(UInt128 left, int shift)
        {
            if (shift == 0)
            {
                return left;
            }
            else if (shift < 64)
            {
                return new((left.b0 >> shift) | (left.b1 << (64 - shift)), left.b1 >> shift);
            }
            else
            {
                return new(left.b1 >> (shift - 64), 0);
            }
        }

        public static explicit operator UInt128(int val) => new(val);
        public static explicit operator UInt128(ulong val) => new(val, 0);

        public static explicit operator ulong(UInt128 val) => val.b0;
    }
}
