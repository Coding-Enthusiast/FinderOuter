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


        public static UInt128 Multiply(ulong left, ulong right)
        {
            ulong x0 = (uint)left;
            ulong x1 = left >> 32;
            ulong y0 = (uint)right;
            ulong y1 = right >> 32;

            // The following needs benchmark to be replaced by below code
            //ulong hi = x1 * y1;
            //ulong mid = x0 * y1;
            //ulong lo = x0 * y0;
            //ulong mid2 = y0 * x1;
            //mid += mid2;
            //hi += mid >> 32;
            //if (mid < mid2) hi += 1ul << 32;
            //mid <<= 32;
            //lo += mid;
            //if (lo < mid) hi++;
            //return new UInt128(lo, hi);

            ulong uv = x0 * y0;
            uint w0 = (uint)uv; ulong c = uv >> 32;
            uv = (x1 * y0) + c;
            uint w1 = (uint)uv;
            uint w2 = (uint)(uv >> 32);

            uv = w1 + (x0 * y1);
            w1 = (uint)uv; c = uv >> 32;
            uv = w2 + (x1 * y1) + c;
            w2 = (uint)uv;
            uint w3 = (uint)(uv >> 32);

            return new UInt128(w0, w1, w2, w3);
        }

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
        public static UInt128 operator +(ulong right, UInt128 left) => left + right;


        public static UInt128 operator *(UInt128 left, UInt128 right)
        {
            ulong x0 = (uint)left.b0;
            ulong x1 = (uint)(left.b0 >> 32);
            ulong x2 = (uint)left.b1;
            ulong x3 = (uint)(left.b1 >> 32);
            ulong y0 = (uint)right.b0;
            ulong y1 = (uint)(right.b0 >> 32);
            ulong y2 = (uint)right.b1;
            ulong y3 = (uint)(right.b1 >> 32);

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
            ulong x0 = (uint)left.b0;
            ulong x1 = (uint)(left.b0 >> 32);
            ulong x2 = (uint)left.b1;
            ulong x3 = (uint)(left.b1 >> 32);
            ulong y0 = (uint)right;
            ulong y1 = (uint)(right >> 32);

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
        public static UInt128 operator *(ulong right, UInt128 left) => left * right;


        public static UInt128 operator &(UInt128 left, UInt128 right) => new(left.b0 & right.b0, left.b1 & right.b1);
        public static UInt128 operator &(UInt128 left, ulong right) => new(left.b0 & right, 0);
        public static UInt128 operator &(ulong right, UInt128 left) => new(left.b0 & right, 0);
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
