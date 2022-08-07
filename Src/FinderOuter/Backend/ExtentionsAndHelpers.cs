// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using Autarkysoft.Bitcoin.Cryptography.EllipticCurve;
using System;
using System.Diagnostics;
using System.Numerics;
using System.Text;

namespace FinderOuter.Backend
{
    public static class Scalar8x32Extentions
    {
        // Secp256k1 curve order
        public const uint N0 = 0xD0364141U;
        public const uint N1 = 0xBFD25E8CU;
        public const uint N2 = 0xAF48A03BU;
        public const uint N3 = 0xBAAEDCE6U;
        public const uint N4 = 0xFFFFFFFEU;
        public const uint N5 = 0xFFFFFFFFU;
        public const uint N6 = 0xFFFFFFFFU;
        public const uint N7 = 0xFFFFFFFFU;

        // 2^256 - N
        public const uint NC0 = ~N0 + 1;
        public const uint NC1 = ~N1;
        public const uint NC2 = ~N2;
        public const uint NC3 = ~N3;
        public const uint NC4 = 1;

        // N/2
        public const uint NH0 = 0x681B20A0U;
        public const uint NH1 = 0xDFE92F46U;
        public const uint NH2 = 0x57A4501DU;
        public const uint NH3 = 0x5D576E73U;
        public const uint NH4 = 0xFFFFFFFFU;
        public const uint NH5 = 0xFFFFFFFFU;
        public const uint NH6 = 0xFFFFFFFFU;
        public const uint NH7 = 0x7FFFFFFFU;


        public static Scalar8x32 Add(this in Scalar8x32 a, in Scalar8x32 other, out int overflow)
        {
            ulong t = (ulong)a.b0 + other.b0;
            uint r0 = (uint)t; t >>= 32;
            t += (ulong)a.b1 + other.b1;
            uint r1 = (uint)t; t >>= 32;
            t += (ulong)a.b2 + other.b2;
            uint r2 = (uint)t; t >>= 32;
            t += (ulong)a.b3 + other.b3;
            uint r3 = (uint)t; t >>= 32;
            t += (ulong)a.b4 + other.b4;
            uint r4 = (uint)t; t >>= 32;
            t += (ulong)a.b5 + other.b5;
            uint r5 = (uint)t; t >>= 32;
            t += (ulong)a.b6 + other.b6;
            uint r6 = (uint)t; t >>= 32;
            t += (ulong)a.b7 + other.b7;
            uint r7 = (uint)t; t >>= 32;


            int yes = 0;
            int no = 0;
            no |= (r7 < N7 ? 1 : 0);
            no |= (r6 < N6 ? 1 : 0);
            no |= (r5 < N5 ? 1 : 0);
            no |= (r4 < N4 ? 1 : 0);
            yes |= (r4 > N4 ? 1 : 0) & ~no;
            no |= (r3 < N3 ? 1 : 0) & ~yes;
            yes |= (r3 > N3 ? 1 : 0) & ~no;
            no |= (r2 < N2 ? 1 : 0) & ~yes;
            yes |= (r2 > N2 ? 1 : 0) & ~no;
            no |= (r1 < N1 ? 1 : 0) & ~yes;
            yes |= (r1 > N1 ? 1 : 0) & ~no;
            yes |= (r0 >= N0 ? 1 : 0) & ~no;

            overflow = yes | (int)t;
            Debug.Assert(overflow == 0 || overflow == 1);

            t = (ulong)r0 + (uint)overflow * NC0;
            r0 = (uint)t; t >>= 32;
            t += (ulong)r1 + (uint)overflow * NC1;
            r1 = (uint)t; t >>= 32;
            t += (ulong)r2 + (uint)overflow * NC2;
            r2 = (uint)t; t >>= 32;
            t += (ulong)r3 + (uint)overflow * NC3;
            r3 = (uint)t; t >>= 32;
            t += (ulong)r4 + (uint)overflow * NC4;
            r4 = (uint)t; t >>= 32;
            t += r5;
            r5 = (uint)t; t >>= 32;
            t += r6;
            r6 = (uint)t; t >>= 32;
            t += r7;
            r7 = (uint)t;

            return new Scalar8x32(r0, r1, r2, r3, r4, r5, r6, r7);
        }

        public static Scalar8x32 Multiply(this Scalar8x32 a, in Scalar8x32 other)
        {
            Span<uint> val1 = new uint[8] { a.b0, a.b1, a.b2, a.b3, a.b4, a.b5, a.b6, a.b7 };
            Span<uint> val2 = stackalloc uint[16];
            Mul512(val2, a, other);
            Reduce512(val1, val2);
            return new Scalar8x32(val1);
        }

        private static void Mul512(Span<uint> l, in Scalar8x32 a, in Scalar8x32 b)
        {
            /* 160 bit accumulator. */
            ulong v;
            ulong acc0 = 0;
            uint acc1 = 0;

            /* l[0..15] = a[0..7] * b[0..7]. */
            v = (ulong)a.b0 * b.b0; acc0 += v; Debug.Assert(acc0 >= v); // muladd_fast(a.d0, b.d0);
            l[0] = (uint)acc0; acc0 >>= 32; Debug.Assert(acc1 == 0); // extract_fast(out l[0]);
            v = (ulong)a.b0 * b.b1; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d0, b.d1);
            v = (ulong)a.b1 * b.b0; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d1, b.d0);
            l[1] = (uint)acc0; acc0 >>= 32; acc0 |= (ulong)acc1 << 32; acc1 = 0;  // extract(out l[1]);
            v = (ulong)a.b0 * b.b2; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d0, b.d2);
            v = (ulong)a.b1 * b.b1; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d1, b.d1);
            v = (ulong)a.b2 * b.b0; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d2, b.d0);
            l[2] = (uint)acc0; acc0 >>= 32; acc0 |= (ulong)acc1 << 32; acc1 = 0;  // extract(out l[2]);
            v = (ulong)a.b0 * b.b3; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d0, b.d3);
            v = (ulong)a.b1 * b.b2; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d1, b.d2);
            v = (ulong)a.b2 * b.b1; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d2, b.d1);
            v = (ulong)a.b3 * b.b0; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d3, b.d0);
            l[3] = (uint)acc0; acc0 >>= 32; acc0 |= (ulong)acc1 << 32; acc1 = 0;  // extract(out l[3]);
            v = (ulong)a.b0 * b.b4; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d0, b.d4);
            v = (ulong)a.b1 * b.b3; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d1, b.d3);
            v = (ulong)a.b2 * b.b2; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d2, b.d2);
            v = (ulong)a.b3 * b.b1; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d3, b.d1);
            v = (ulong)a.b4 * b.b0; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d4, b.d0);
            l[4] = (uint)acc0; acc0 >>= 32; acc0 |= (ulong)acc1 << 32; acc1 = 0;  // extract(out l[4]);
            v = (ulong)a.b0 * b.b5; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d0, b.d5);
            v = (ulong)a.b1 * b.b4; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d1, b.d4);
            v = (ulong)a.b2 * b.b3; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d2, b.d3);
            v = (ulong)a.b3 * b.b2; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d3, b.d2);
            v = (ulong)a.b4 * b.b1; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d4, b.d1);
            v = (ulong)a.b5 * b.b0; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d5, b.d0);
            l[5] = (uint)acc0; acc0 >>= 32; acc0 |= (ulong)acc1 << 32; acc1 = 0;  // extract(out l[5]);
            v = (ulong)a.b0 * b.b6; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d0, b.d6);
            v = (ulong)a.b1 * b.b5; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d1, b.d5);
            v = (ulong)a.b2 * b.b4; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d2, b.d4);
            v = (ulong)a.b3 * b.b3; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d3, b.d3);
            v = (ulong)a.b4 * b.b2; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d4, b.d2);
            v = (ulong)a.b5 * b.b1; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d5, b.d1);
            v = (ulong)a.b6 * b.b0; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d6, b.d0);
            l[6] = (uint)acc0; acc0 >>= 32; acc0 |= (ulong)acc1 << 32; acc1 = 0;  // extract(out l[6]);
            v = (ulong)a.b0 * b.b7; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d0, b.d7);
            v = (ulong)a.b1 * b.b6; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d1, b.d6);
            v = (ulong)a.b2 * b.b5; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d2, b.d5);
            v = (ulong)a.b3 * b.b4; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d3, b.d4);
            v = (ulong)a.b4 * b.b3; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d4, b.d3);
            v = (ulong)a.b5 * b.b2; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d5, b.d2);
            v = (ulong)a.b6 * b.b1; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d6, b.d1);
            v = (ulong)a.b7 * b.b0; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d7, b.d0);
            l[7] = (uint)acc0; acc0 >>= 32; acc0 |= (ulong)acc1 << 32; acc1 = 0;  // extract(out l[7]);
            v = (ulong)a.b1 * b.b7; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d1, b.d7);
            v = (ulong)a.b2 * b.b6; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d2, b.d6);
            v = (ulong)a.b3 * b.b5; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d3, b.d5);
            v = (ulong)a.b4 * b.b4; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d4, b.d4);
            v = (ulong)a.b5 * b.b3; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d5, b.d3);
            v = (ulong)a.b6 * b.b2; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d6, b.d2);
            v = (ulong)a.b7 * b.b1; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d7, b.d1);
            l[8] = (uint)acc0; acc0 >>= 32; acc0 |= (ulong)acc1 << 32; acc1 = 0;  // extract(out l[8]);
            v = (ulong)a.b2 * b.b7; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d2, b.d7);
            v = (ulong)a.b3 * b.b6; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d3, b.d6);
            v = (ulong)a.b4 * b.b5; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d4, b.d5);
            v = (ulong)a.b5 * b.b4; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d5, b.d4);
            v = (ulong)a.b6 * b.b3; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d6, b.d3);
            v = (ulong)a.b7 * b.b2; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d7, b.d2);
            l[9] = (uint)acc0; acc0 >>= 32; acc0 |= (ulong)acc1 << 32; acc1 = 0;  // extract(out l[9]);
            v = (ulong)a.b3 * b.b7; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d3, b.d7);
            v = (ulong)a.b4 * b.b6; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d4, b.d6);
            v = (ulong)a.b5 * b.b5; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d5, b.d5);
            v = (ulong)a.b6 * b.b4; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d6, b.d4);
            v = (ulong)a.b7 * b.b3; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d7, b.d3);
            l[10] = (uint)acc0; acc0 >>= 32; acc0 |= (ulong)acc1 << 32; acc1 = 0;  // extract(out l[10]);
            v = (ulong)a.b4 * b.b7; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d4, b.d7);
            v = (ulong)a.b5 * b.b6; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d5, b.d6);
            v = (ulong)a.b6 * b.b5; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d6, b.d5);
            v = (ulong)a.b7 * b.b4; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d7, b.d4);
            l[11] = (uint)acc0; acc0 >>= 32; acc0 |= (ulong)acc1 << 32; acc1 = 0;  // extract(out l[11]);
            v = (ulong)a.b5 * b.b7; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d5, b.d7);
            v = (ulong)a.b6 * b.b6; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d6, b.d6);
            v = (ulong)a.b7 * b.b5; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d7, b.d5);
            l[12] = (uint)acc0; acc0 >>= 32; acc0 |= (ulong)acc1 << 32; acc1 = 0;  // extract(out l[12]);
            v = (ulong)a.b6 * b.b7; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d6, b.d7);
            v = (ulong)a.b7 * b.b6; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(a.d7, b.d6);
            l[13] = (uint)acc0; acc0 >>= 32; acc0 |= (ulong)acc1 << 32; acc1 = 0;  // extract(out l[13]);
            v = (ulong)a.b7 * b.b7; acc0 += v; Debug.Assert(acc0 >= v); // muladd_fast(a.d7, b.d7);
            l[14] = (uint)acc0; acc0 >>= 32; Debug.Assert(acc1 == 0); // extract_fast(out l[14]);
            Debug.Assert((acc0 >> 32) == 0);
            l[15] = (uint)acc0;
        }

        private static void Reduce512(Span<uint> d, Span<uint> l)
        {
            ulong c;
            ulong v;
            uint n0 = l[8], n1 = l[9], n2 = l[10], n3 = l[11], n4 = l[12], n5 = l[13], n6 = l[14], n7 = l[15];
            uint m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12;
            uint p0, p1, p2, p3, p4, p5, p6, p7, p8;

            /* 160 bit accumulator. */
            ulong acc0;
            uint acc1 = 0;

            /* Reduce 512 bits into 385. */
            /* m[0..12] = l[0..7] + n[0..7] * SECP256K1_N_C. */
            acc0 = l[0];
            v = (ulong)n0 * NC0; acc0 += v; Debug.Assert(acc0 >= v); // muladd_fast(n0, NC0);
            m0 = (uint)acc0; acc0 >>= 32; Debug.Assert(acc1 == 0); // extract_fast(out m0);
            acc0 += l[1]; Debug.Assert(((acc0 >> 32) != 0) | ((uint)acc0 >= l[1])); Debug.Assert(acc1 == 0); // sumadd_fast(l[1]);
            v = (ulong)n1 * NC0; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(n1, NC0);
            v = (ulong)n0 * NC1; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(n0, NC1);
            m1 = (uint)acc0; acc0 >>= 32; acc0 |= (ulong)acc1 << 32; acc1 = 0;  // extract(out m1);
            acc0 += l[2]; acc1 += (acc0 < l[2]) ? 1U : 0; // sumadd_fast(l[2]);
            v = (ulong)n2 * NC0; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(n2, NC0);
            v = (ulong)n1 * NC1; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(n1, NC1);
            v = (ulong)n0 * NC2; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(n0, NC2);
            m2 = (uint)acc0; acc0 >>= 32; acc0 |= (ulong)acc1 << 32; acc1 = 0;  // extract(out m2);
            acc0 += l[3]; acc1 += (acc0 < l[3]) ? 1U : 0; // sumadd_fast(l[3]);
            v = (ulong)n3 * NC0; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(n3, NC0);
            v = (ulong)n2 * NC1; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(n2, NC1);
            v = (ulong)n1 * NC2; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(n1, NC2);
            v = (ulong)n0 * NC3; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(n0, NC3);
            m3 = (uint)acc0; acc0 >>= 32; acc0 |= (ulong)acc1 << 32; acc1 = 0;  // extract(out m3);
            acc0 += l[4]; acc1 += (acc0 < l[4]) ? 1U : 0; // sumadd_fast(l[4]);
            v = (ulong)n4 * NC0; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(n4, NC0);
            v = (ulong)n3 * NC1; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(n3, NC1);
            v = (ulong)n2 * NC2; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(n2, NC2);
            v = (ulong)n1 * NC3; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(n1, NC3);
            acc0 += n0; acc1 += (acc0 < n0) ? 1U : 0; // sumadd_fast(n0);
            m4 = (uint)acc0; acc0 >>= 32; acc0 |= (ulong)acc1 << 32; acc1 = 0;  // extract(out m4);
            acc0 += l[5]; acc1 += (acc0 < l[5]) ? 1U : 0; // sumadd_fast(l[5]);
            v = (ulong)n5 * NC0; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(n5, NC0);
            v = (ulong)n4 * NC1; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(n4, NC1);
            v = (ulong)n3 * NC2; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(n3, NC2);
            v = (ulong)n2 * NC3; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(n2, NC3);
            acc0 += n1; acc1 += (acc0 < n1) ? 1U : 0; // sumadd_fast(n1);
            m5 = (uint)acc0; acc0 >>= 32; acc0 |= (ulong)acc1 << 32; acc1 = 0;  // extract(out m5);
            acc0 += l[6]; acc1 += (acc0 < l[6]) ? 1U : 0; // sumadd_fast(l[6]);
            v = (ulong)n6 * NC0; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(n6, NC0);
            v = (ulong)n5 * NC1; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(n5, NC1);
            v = (ulong)n4 * NC2; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(n4, NC2);
            v = (ulong)n3 * NC3; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(n3, NC3);
            acc0 += n2; acc1 += (acc0 < n2) ? 1U : 0; // sumadd_fast(n2);
            m6 = (uint)acc0; acc0 >>= 32; acc0 |= (ulong)acc1 << 32; acc1 = 0;  // extract(out m6);
            acc0 += l[7]; acc1 += (acc0 < l[7]) ? 1U : 0; // sumadd_fast(l[7]);
            v = (ulong)n7 * NC0; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(n7, NC0);
            v = (ulong)n6 * NC1; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(n6, NC1);
            v = (ulong)n5 * NC2; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(n5, NC2);
            v = (ulong)n4 * NC3; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(n4, NC3);
            acc0 += n3; acc1 += (acc0 < n3) ? 1U : 0; // sumadd_fast(n3);
            m7 = (uint)acc0; acc0 >>= 32; acc0 |= (ulong)acc1 << 32; acc1 = 0;  // extract(out m7);
            v = (ulong)n7 * NC1; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(n7, NC1);
            v = (ulong)n6 * NC2; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(n6, NC2);
            v = (ulong)n5 * NC3; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(n5, NC3);
            acc0 += n4; acc1 += (acc0 < n4) ? 1U : 0; // sumadd_fast(n4);
            m8 = (uint)acc0; acc0 >>= 32; acc0 |= (ulong)acc1 << 32; acc1 = 0;  // extract(out m8);
            v = (ulong)n7 * NC2; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(n7, NC2);
            v = (ulong)n6 * NC3; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(n6, NC3);
            acc0 += n5; acc1 += (acc0 < n5) ? 1U : 0; // sumadd_fast(n5);
            m9 = (uint)acc0; acc0 >>= 32; acc0 |= (ulong)acc1 << 32; acc1 = 0;  // extract(out m9);
            v = (ulong)n7 * NC3; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(n7, NC3);
            acc0 += n6; acc1 += (acc0 < n6) ? 1U : 0; // sumadd_fast(n6);
            m10 = (uint)acc0; acc0 >>= 32; acc0 |= (ulong)acc1 << 32; acc1 = 0;  // extract(out m10);
            acc0 += n7; Debug.Assert(((acc0 >> 32) != 0) | ((uint)acc0 >= n7)); Debug.Assert(acc1 == 0); // sumadd_fast(n7);
            m11 = (uint)acc0; acc0 >>= 32; Debug.Assert(acc1 == 0); // extract_fast(out m11);
            Debug.Assert((uint)acc0 <= 1);
            m12 = (uint)acc0;

            /* Reduce 385 bits into 258. */
            /* p[0..8] = m[0..7] + m[8..12] * SECP256K1_N_C. */
            acc0 = m0; acc1 = 0;
            v = (ulong)m8 * NC0; acc0 += v; Debug.Assert(acc0 >= v); // muladd_fast(m8, NC0);
            p0 = (uint)acc0; acc0 >>= 32; Debug.Assert(acc1 == 0); // extract_fast(out p0);
            acc0 += m1; Debug.Assert(((acc0 >> 32) != 0) | ((uint)acc0 >= m1)); Debug.Assert(acc1 == 0); // sumadd_fast(m1);
            v = (ulong)m9 * NC0; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(m9, NC0);
            v = (ulong)m8 * NC1; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(m8, NC1);
            p1 = (uint)acc0; acc0 >>= 32; acc0 |= (ulong)acc1 << 32; acc1 = 0;  // extract(out p1);
            acc0 += m2; acc1 += (acc0 < m2) ? 1U : 0; // sumadd_fast(m2);
            v = (ulong)m10 * NC0; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(m10, NC0);
            v = (ulong)m9 * NC1; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(m9, NC1);
            v = (ulong)m8 * NC2; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(m8, NC2);
            p2 = (uint)acc0; acc0 >>= 32; acc0 |= (ulong)acc1 << 32; acc1 = 0;  // extract(out p2);
            acc0 += m3; acc1 += (acc0 < m3) ? 1U : 0; // sumadd_fast(m3);
            v = (ulong)m11 * NC0; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(m11, NC0);
            v = (ulong)m10 * NC1; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(m10, NC1);
            v = (ulong)m9 * NC2; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(m9, NC2);
            v = (ulong)m8 * NC3; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(m8, NC3);
            p3 = (uint)acc0; acc0 >>= 32; acc0 |= (ulong)acc1 << 32; acc1 = 0;  // extract(out p3);
            acc0 += m4; acc1 += (acc0 < m4) ? 1U : 0; // sumadd_fast(m4);
            v = (ulong)m12 * NC0; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(m12, NC0);
            v = (ulong)m11 * NC1; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(m11, NC1);
            v = (ulong)m10 * NC2; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(m10, NC2);
            v = (ulong)m9 * NC3; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(m9, NC3);
            acc0 += m8; acc1 += (acc0 < m8) ? 1U : 0; // sumadd_fast(m8);
            p4 = (uint)acc0; acc0 >>= 32; acc0 |= (ulong)acc1 << 32; acc1 = 0;  // extract(out p4);
            acc0 += m5; acc1 += (acc0 < m5) ? 1U : 0; // sumadd_fast(m5);
            v = (ulong)m12 * NC1; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(m12, NC1);
            v = (ulong)m11 * NC2; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(m11, NC2);
            v = (ulong)m10 * NC3; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(m10, NC3);
            acc0 += m9; acc1 += (acc0 < m9) ? 1U : 0; // sumadd_fast(m9);
            p5 = (uint)acc0; acc0 >>= 32; acc0 |= (ulong)acc1 << 32; acc1 = 0;  // extract(out p5);
            acc0 += m6; acc1 += (acc0 < m6) ? 1U : 0; // sumadd_fast(m6);
            v = (ulong)m12 * NC2; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(m12, NC2);
            v = (ulong)m11 * NC3; acc0 += v; acc1 += (acc0 < v) ? 1U : 0; Debug.Assert((acc0 >= v) || (acc1 != 0)); // muladd(m11, NC3);
            acc0 += m10; acc1 += (acc0 < m10) ? 1U : 0; // sumadd_fast(m10);
            p6 = (uint)acc0; acc0 >>= 32; acc0 |= (ulong)acc1 << 32; acc1 = 0;  // extract(out p6);
            acc0 += m7; Debug.Assert(((acc0 >> 32) != 0) | ((uint)acc0 >= m7)); Debug.Assert(acc1 == 0); // sumadd_fast(m7);
            v = (ulong)m12 * NC3; acc0 += v; Debug.Assert(acc0 >= v); // muladd_fast(m12, NC3);
            acc0 += m11; Debug.Assert(((acc0 >> 32) != 0) | ((uint)acc0 >= m11)); Debug.Assert(acc1 == 0); // sumadd_fast(m11);
            p7 = (uint)acc0; acc0 >>= 32; Debug.Assert(acc1 == 0); // extract_fast(out p7);
            p8 = (uint)acc0 + m12;
            Debug.Assert(p8 <= 2);

            /* Reduce 258 bits into 256. */
            /* r[0..7] = p[0..7] + p[8] * SECP256K1_N_C. */
            c = p0 + (ulong)NC0 * p8;
            d[0] = (uint)c; c >>= 32;
            c += p1 + (ulong)NC1 * p8;
            d[1] = (uint)c; c >>= 32;
            c += p2 + (ulong)NC2 * p8;
            d[2] = (uint)c; c >>= 32;
            c += p3 + (ulong)NC3 * p8;
            d[3] = (uint)c; c >>= 32;
            c += p4 + (ulong)p8;
            d[4] = (uint)c; c >>= 32;
            c += p5;
            d[5] = (uint)c; c >>= 32;
            c += p6;
            d[6] = (uint)c; c >>= 32;
            c += p7;
            d[7] = (uint)c; c >>= 32;

            /* Final reduction of r. */
            Reduce(d, (int)c + GetOverflow(d));
        }

        private static int GetOverflow(Span<uint> d)
        {
            int yes = 0;
            int no = 0;
            no |= (d[7] < N7 ? 1 : 0);
            no |= (d[6] < N6 ? 1 : 0);
            no |= (d[5] < N5 ? 1 : 0);
            no |= (d[4] < N4 ? 1 : 0);
            yes |= (d[4] > N4 ? 1 : 0) & ~no;
            no |= (d[3] < N3 ? 1 : 0) & ~yes;
            yes |= (d[3] > N3 ? 1 : 0) & ~no;
            no |= (d[2] < N2 ? 1 : 0) & ~yes;
            yes |= (d[2] > N2 ? 1 : 0) & ~no;
            no |= (d[1] < N1 ? 1 : 0) & ~yes;
            yes |= (d[1] > N1 ? 1 : 0) & ~no;
            yes |= (d[0] >= N0 ? 1 : 0) & ~no;
            return yes;
        }

        private static int Reduce(Span<uint> d, int overflow)
        {
            ulong t;
            Debug.Assert(overflow == 0 || overflow == 1);
            t = (ulong)d[0] + (uint)overflow * NC0;
            d[0] = (uint)t; t >>= 32;
            t += (ulong)d[1] + (uint)overflow * NC1;
            d[1] = (uint)t; t >>= 32;
            t += (ulong)d[2] + (uint)overflow * NC2;
            d[2] = (uint)t; t >>= 32;
            t += (ulong)d[3] + (uint)overflow * NC3;
            d[3] = (uint)t; t >>= 32;
            t += (ulong)d[4] + (uint)overflow * NC4;
            d[4] = (uint)t; t >>= 32;
            t += d[5];
            d[5] = (uint)t; t >>= 32;
            t += d[6];
            d[6] = (uint)t; t >>= 32;
            t += d[7];
            d[7] = (uint)t;
            return overflow;
        }
    }




    /// <summary>
    /// Helper class for working with byte arrays
    /// </summary>
    public class ByteArray
    {
        /// <summary>
        /// Concatinates a list of arrays together and returns a bigger array containing all the elements.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <param name="arrays">Array of byte arrays to concatinate.</param>
        /// <returns>An array of bytes.</returns>
        public static byte[] ConcatArrays(params byte[][] arrays)
        {
            if (arrays == null)
                throw new ArgumentNullException(nameof(arrays), "Array params can not be null.");

            // Linq is avoided to increase speed.
            int len = 0;
            foreach (byte[] arr in arrays)
            {
                if (arr == null)
                {
                    throw new ArgumentNullException(nameof(arr), "Can't concatinate with null array(s)!");
                }
                len += arr.Length;
            }

            byte[] result = new byte[len];

            int offset = 0;
            foreach (byte[] arr in arrays)
            {
                Buffer.BlockCopy(arr, 0, result, offset, arr.Length);
                offset += arr.Length;
            }

            return result;
        }
    }





    public static class ByteArrayExtension
    {
        /// <summary>
        /// Compares a given byte arrays to another and returns 1 if bigger, -1 if smaller and 0 if equal.
        /// <para/>* Considers byte arrays as representing integral values so both byte arrays should be in big endian 
        /// and starting zeros will be ignored.
        /// </summary>
        /// <remarks>
        /// This is 10 times faster than converting byte arrays to a BigInteger and comparing that.
        /// </remarks>
        /// <exception cref="ArgumentNullException"/>
        /// <param name="first">First byte array for comparison.</param>
        /// <param name="second">The byte array to compare to.</param>
        /// <returns>1 if first is bigger, -1 if first is smaller and 0 if both are equal.</returns>
        public static int CompareTo(this byte[] first, byte[] second)
        {
            if (first == null)
                throw new ArgumentNullException(nameof(first), "First byte array can not be null!");
            if (second == null)
                throw new ArgumentNullException(nameof(second), "Second byte array can not be null!");


            int zeros1 = 0;
            int zeros2 = 0;
            foreach (byte item in first)
            {
                if (item == 0)
                {
                    zeros1++;
                }
                else
                {
                    break;
                }
            }
            foreach (byte item in second)
            {
                if (item == 0)
                {
                    zeros2++;
                }
                else
                {
                    break;
                }
            }

            if (first.Length - zeros1 > second.Length - zeros2)
            {
                return 1;
            }
            else if (first.Length - zeros1 < second.Length - zeros2)
            {
                return -1;
            }
            else if (first.Length - zeros1 == 0 && second.Length - zeros2 == 0)
            {
                return 0;
            }
            else
            {
                unsafe
                {
                    fixed (byte* f = &first[0], s = &second[0])
                    {
                        for (int i = 0; i < first.Length - zeros1; i++)
                        {
                            if (f[i + zeros1] > s[i + zeros2])
                            {
                                return 1;
                            }
                            else if (f[i + zeros1] < s[i + zeros2])
                            {
                                return -1;
                            }
                        }
                    }
                }
            }

            return 0;
        }


        /// <summary>
        /// Returns binary length of the given byte array according to its endianness.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <param name="ba">Bytes to use</param>
        /// <param name="isBigEndian">Endianness of the byte array</param>
        /// <param name="removeZeros">
        /// True will remove both zero bytes and zero bits.
        /// If you want to remove zero bytes and not zero bits, 
        /// call <see cref="TrimStart(byte[])"/> or <see cref="TrimEnd(byte[])"/> depending on endianness, before calling this function.
        /// <para/>Example (big-endian): 0000_0000 0000_0101 -> true:3 false:16
        /// </param>
        /// <returns>Binary length</returns>
        public static int GetBitLength(this byte[] ba, bool isBigEndian, bool removeZeros = true)
        {
            if (ba == null)
                throw new ArgumentNullException(nameof(ba), "Input can not be null!");

            if (ba.Length == 0)
                return 0;

            if (!removeZeros)
            {
                return ba.Length * 8;
            }
            else
            {
                byte[] trimmed = isBigEndian ? ba.TrimStart() : ba.TrimEnd();
                if (trimmed.Length == 0)
                {
                    return 0;
                }

                int len = 0;
                byte last = isBigEndian ? trimmed[0] : trimmed[^1];
                while (last != 0)
                {
                    last >>= 1;
                    len++;
                }
                return len + ((trimmed.Length - 1) * 8);
            }
        }


        /// <summary>
        /// Creates a copy of the given byte array padded with zeros on the left (inserted at index 0) to the given length.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="IndexOutOfRangeException"/>
        /// <param name="ba">Byte array to pad</param>
        /// <param name="finalSize">Desired final size of the returned array.</param>
        /// <returns>A zero padded array of bytes.</returns>
        public static byte[] PadLeft(this byte[] ba, int finalSize)
        {
            if (ba == null)
                throw new ArgumentNullException(nameof(ba), "Input can not be null!");
            if (finalSize < 0)
                throw new IndexOutOfRangeException($"{nameof(finalSize)} can not be negative.");
            if (ba.Length > finalSize)
                throw new IndexOutOfRangeException("Input is longer than final size.");


            byte[] result = new byte[finalSize];
            Buffer.BlockCopy(ba, 0, result, finalSize - ba.Length, ba.Length);
            return result;
        }


        /// <summary>
        /// Creates a copy of the given byte array padded with zeros on the right (inserted after last index) to the given length.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="IndexOutOfRangeException"/>
        /// <param name="ba">Byte array to pad</param>
        /// <param name="finalSize">Desired final size of the returned array.</param>
        /// <returns>A zero padded array of bytes.</returns>
        public static byte[] PadRight(this byte[] ba, int finalSize)
        {
            if (ba == null)
                throw new ArgumentNullException(nameof(ba), "Input can not be null!");
            if (finalSize < 0)
                throw new IndexOutOfRangeException($"{nameof(finalSize)} can not be negative.");
            if (ba.Length > finalSize)
                throw new IndexOutOfRangeException("Input is longer than final size.");


            byte[] result = new byte[finalSize];
            Buffer.BlockCopy(ba, 0, result, 0, ba.Length);
            return result;
        }


        /// <summary>
        /// Converts the given four bytes to a 32-bit signed integer.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <param name="ba">The array of bytes to convert (must be 4 bytes long).</param>
        /// <param name="isBigEndian">Endianness of given bytes.</param>
        /// <returns>A 32-bit signed integer.</returns>
        public static int ToInt32(this byte[] ba, bool isBigEndian)
        {
            if (ba == null)
                throw new ArgumentNullException(nameof(ba), "Byte array can not be null.");
            if (ba.Length != sizeof(int))
                throw new ArgumentOutOfRangeException(nameof(ba), ba.ToBase16(), "Byte array must be 4 bytes.");


            unchecked
            {
                return isBigEndian ?
                    ba[3] | (ba[2] << 8) | (ba[1] << 16) | (ba[0] << 24) :
                    ba[0] | (ba[1] << 8) | (ba[2] << 16) | (ba[3] << 24);
            }
        }


        /// <summary>
        /// Converts the given eight bytes to a 64-bit signed integer.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <param name="ba">The array of bytes to convert (must be 8 bytes long).</param>
        /// <param name="isBigEndian">Endianness of given bytes.</param>
        /// <returns>A 32-bit signed integer.</returns>
        public static long ToInt64(this byte[] ba, bool isBigEndian)
        {
            if (ba == null)
                throw new ArgumentNullException(nameof(ba), "Byte array can not be null.");
            if (ba.Length != sizeof(long))
                throw new ArgumentOutOfRangeException(nameof(ba), ba.ToBase16(), "Byte array must be 8 bytes.");


            unchecked
            {
                return isBigEndian ?
                    ba[7] | ((long)ba[6] << 8) | ((long)ba[5] << 16) | ((long)ba[4] << 24) |
                            ((long)ba[3] << 32) | ((long)ba[2] << 40) | ((long)ba[1] << 48) | ((long)ba[0] << 56) :
                    ba[0] | ((long)ba[1] << 8) | ((long)ba[2] << 16) | ((long)ba[3] << 24) |
                            ((long)ba[4] << 32) | ((long)ba[5] << 40) | ((long)ba[6] << 48) | ((long)ba[7] << 56);
            }
        }


        /// <summary>
        /// Converts the given two bytes to a 16-bit unsigned integer.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <param name="ba">The array of bytes to convert (must be 2 bytes long).</param>
        /// <param name="isBigEndian">Endianness of given bytes.</param>
        /// <returns>A 16-bit unsigned integer.</returns>
        public static ushort ToUInt16(this byte[] ba, bool isBigEndian)
        {
            if (ba == null)
                throw new ArgumentNullException(nameof(ba), "Byte array can not be null.");
            if (ba.Length != sizeof(ushort))
                throw new ArgumentOutOfRangeException(nameof(ba), ba.ToBase16(), "Byte array must be 2 bytes.");


            unchecked
            {
                return isBigEndian ?
                    (ushort)(ba[1] | (ba[0] << 8)) :
                    (ushort)(ba[0] | (ba[1] << 8));
            }
        }

        /// <summary>
        /// Converts the given two bytes to a 32-bit unsigned integer.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <param name="ba">The array of bytes to convert (must be 4 bytes long).</param>
        /// <param name="isBigEndian">Endianness of given bytes.</param>
        /// <returns>A 32-bit unsigned integer.</returns>
        public static uint ToUInt32(this byte[] ba, bool isBigEndian)
        {
            if (ba == null)
                throw new ArgumentNullException(nameof(ba), "Byte array can not be null.");
            if (ba.Length != sizeof(uint))
                throw new ArgumentOutOfRangeException(nameof(ba), ba.ToBase16(), "Byte array must be 4 bytes.");


            unchecked
            {
                return isBigEndian ?
                    (uint)(ba[3] | (ba[2] << 8) | (ba[1] << 16) | (ba[0] << 24)) :
                    (uint)(ba[0] | (ba[1] << 8) | (ba[2] << 16) | (ba[3] << 24));
            }
        }

        /// <summary>
        /// Converts the given two bytes to a 64-bit unsigned integer.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <param name="ba">The array of bytes to convert (must be 8 bytes long).</param>
        /// <param name="isBigEndian">Endianness of given bytes.</param>
        /// <returns>A 64-bit unsigned integer.</returns>
        public static ulong ToUInt64(this byte[] ba, bool isBigEndian)
        {
            if (ba == null)
                throw new ArgumentNullException(nameof(ba), "Byte array can not be null.");
            if (ba.Length != sizeof(ulong))
                throw new ArgumentOutOfRangeException(nameof(ba), ba.ToBase16(), "Byte array must be 8 bytes.");


            unchecked
            {
                return isBigEndian ?
                    ba[7] | ((ulong)ba[6] << 8) | ((ulong)ba[5] << 16) | ((ulong)ba[4] << 24) |
                            ((ulong)ba[3] << 32) | ((ulong)ba[2] << 40) | ((ulong)ba[1] << 48) | ((ulong)ba[0] << 56) :
                    ba[0] | ((ulong)ba[1] << 8) | ((ulong)ba[2] << 16) | ((ulong)ba[3] << 24) |
                            ((ulong)ba[4] << 32) | ((ulong)ba[5] << 40) | ((ulong)ba[6] << 48) | ((ulong)ba[7] << 56);
            }
        }
    }





    public static class LongExtension
    {
        /// <summary>
        /// Converts the given 64-bit signed integer to a base-16 (hexadecimal) encoded string.
        /// </summary>
        /// <param name="i">The 64-bit signed integer to convert.</param>
        /// <param name="bigEndian">Endianness of the byte array to use for encoding.</param>
        /// <returns>A base-16 encoded string.</returns>
        public static string ToBase16(this long i, bool bigEndian)
        {
            return i.ToByteArray(bigEndian).ToBase16();
        }

        /// <summary>
        /// Converts the given 64-bit signed integer to an array of bytes with a desired endianness.
        /// </summary>
        /// <param name="i">The 64-bit signed integer to convert.</param>
        /// <param name="bigEndian">Endianness of the returned byte array.</param>
        /// <returns>An array of bytes.</returns>
        public static byte[] ToByteArray(this long i, bool bigEndian)
        {
            unchecked
            {
                if (bigEndian)
                {
                    return new byte[]
                    {
                        (byte)(i >> 56),
                        (byte)(i >> 48),
                        (byte)(i >> 40),
                        (byte)(i >> 32),
                        (byte)(i >> 24),
                        (byte)(i >> 16),
                        (byte)(i >> 8),
                        (byte)i
                    };
                }
                else
                {
                    return new byte[]
                    {
                        (byte)i,
                        (byte)(i >> 8),
                        (byte)(i >> 16),
                        (byte)(i >> 24),
                        (byte)(i >> 32),
                        (byte)(i >> 40),
                        (byte)(i >> 48),
                        (byte)(i >> 56)
                    };
                }
            }
        }

    }





    public static class UIntExtension
    {
        /// <summary>
        /// Converts the given 8-bit unsigned integer to a base-16 (hexadecimal) encoded string.
        /// </summary>
        /// <param name="i">The 8-bit unsigned integer to convert.</param>
        /// <returns>A base-16 encoded string.</returns>
        public static string ToBase16(this byte i)
        {
            return (new byte[] { i }).ToBase16();
        }

        /// <summary>
        /// Converts the given 16-bit unsigned integer to a base-16 (hexadecimal) encoded string.
        /// </summary>
        /// <param name="i">The 16-bit unsigned integer to convert.</param>
        /// <param name="bigEndian">Endianness of the byte array to use for encoding.</param>
        /// <returns>A base-16 encoded string.</returns>
        public static string ToBase16(this ushort i, bool bigEndian)
        {
            return i.ToByteArray(bigEndian).ToBase16();
        }

        /// <summary>
        /// Converts the given 32-bit unsigned integer to a base-16 (hexadecimal) encoded string.
        /// </summary>
        /// <param name="i">The 32-bit unsigned integer to convert.</param>
        /// <param name="bigEndian">Endianness of the byte array to use for encoding.</param>
        /// <returns>A base-16 encoded string.</returns>
        public static string ToBase16(this uint i, bool bigEndian)
        {
            return i.ToByteArray(bigEndian).ToBase16();
        }

        /// <summary>
        /// Converts the given 64-bit unsigned integer to a base-16 (hexadecimal) encoded string.
        /// </summary>
        /// <param name="i">The 64-bit unsigned integer to convert.</param>
        /// <param name="bigEndian">Endianness of the byte array to use for encoding.</param>
        /// <returns>A base-16 encoded string.</returns>
        public static string ToBase16(this ulong i, bool bigEndian)
        {
            return i.ToByteArray(bigEndian).ToBase16();
        }


        /// <summary>
        /// Converts the given 16-bit unsigned integer to an array of bytes with a desired endianness.
        /// </summary>
        /// <param name="i">The 16-bit unsigned integer to convert.</param>
        /// <param name="bigEndian">Endianness of the returned byte array.</param>
        /// <returns>An array of bytes.</returns>
        public static byte[] ToByteArray(this ushort i, bool bigEndian)
        {
            unchecked
            {
                if (bigEndian)
                {
                    return new byte[]
                    {
                        (byte)(i >> 8),
                        (byte)i
                    };
                }
                else
                {
                    return new byte[]
                    {
                        (byte)i,
                        (byte)(i >> 8)
                    };
                }
            }
        }

        /// <summary>
        /// Converts the given 32-bit unsigned integer to an array of bytes with a desired endianness.
        /// </summary>
        /// <param name="i">The 32-bit unsigned integer to convert.</param>
        /// <param name="bigEndian">Endianness of the returned byte array.</param>
        /// <returns>An array of bytes.</returns>
        public static byte[] ToByteArray(this uint i, bool bigEndian)
        {
            unchecked
            {
                if (bigEndian)
                {
                    return new byte[]
                    {
                        (byte)(i >> 24),
                        (byte)(i >> 16),
                        (byte)(i >> 8),
                        (byte)i
                    };
                }
                else
                {
                    return new byte[]
                    {
                        (byte)i,
                        (byte)(i >> 8),
                        (byte)(i >> 16),
                        (byte)(i >> 24)
                    };
                }
            }
        }

        /// <summary>
        /// Converts the given 64-bit unsigned integer to an array of bytes with a desired endianness.
        /// </summary>
        /// <param name="i">The 64-bit unsigned integer to convert.</param>
        /// <param name="bigEndian">Endianness of the returned byte array.</param>
        /// <returns>An array of bytes.</returns>
        public static byte[] ToByteArray(this ulong i, bool bigEndian)
        {
            unchecked
            {
                if (bigEndian)
                {
                    return new byte[]
                    {
                        (byte)(i >> 56),
                        (byte)(i >> 48),
                        (byte)(i >> 40),
                        (byte)(i >> 32),
                        (byte)(i >> 24),
                        (byte)(i >> 16),
                        (byte)(i >> 8),
                        (byte)i
                    };
                }
                else
                {
                    return new byte[]
                    {
                        (byte)i,
                        (byte)(i >> 8),
                        (byte)(i >> 16),
                        (byte)(i >> 24),
                        (byte)(i >> 32),
                        (byte)(i >> 40),
                        (byte)(i >> 48),
                        (byte)(i >> 56)
                    };
                }
            }
        }

    }





    public static class BigIntegerExtension
    {
        /// <summary>
        /// Returns total number of non-zero bits in binary representation of a positive <see cref="BigInteger"/>. Example:
        /// <para/>0010 = 1
        /// <para/>1010 = 2
        /// </summary>
        /// <remarks>
        /// This uses Brian Kernighan's algorithm with Time Complexity: O(log N)
        /// </remarks>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <param name="big">BigInteger value to use</param>
        /// <returns>Number of 1s.</returns>
        public static int GetBitCount(this BigInteger big)
        {
            if (big < 0)
                throw new ArgumentOutOfRangeException(nameof(big), "Negative numbers are not accepted here!");


            int result = 0;
            while (big != 0)
            {
                result++;
                big &= (big - 1);
            }
            return result;
        }


        /// <summary>
        /// Returns binary length of the given positive <see cref="BigInteger"/>.
        /// </summary>
        /// <remarks>
        /// BigInteger.Log(big, 2) won't work here becasue it is not accurate for very large numbers.
        /// </remarks>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <param name="big">BigInteger value to use</param>
        /// <param name="removeLeadingZeros">
        /// True will remove leading zeros. 
        /// <para/> 0000_0101 -> true:3 false:8
        /// </param>
        /// <returns>Binary length</returns>
        public static int GetBitLength(this BigInteger big, bool removeLeadingZeros)
        {
            if (big < 0)
                throw new ArgumentOutOfRangeException(nameof(big), "Negative numbers are not accepted here!");

            if (big == 0)
            {
                return 0;
            }

            if (!removeLeadingZeros)
            {
                return big.ToByteArrayExt(false, true).Length * 8;
            }
            else
            {
                if (big == 1) return 1;

                int len = 0;
                while (big != 0)
                {
                    big >>= 1;
                    len++;
                }
                return len;
            }
        }


        /// <summary>
        /// Returns square root of the given positive <see cref="BigInteger"/> using Babylonian (aka Heron's) method.
        /// </summary>
        /// <remarks>
        /// The algorithm: https://en.wikipedia.org/wiki/Methods_of_computing_square_roots#Babylonian_method
        /// </remarks>
        /// <exception cref="ArithmeticException"/>
        /// <param name="big">Number to find square root of</param>
        /// <returns>Square root result</returns>
        public static BigInteger Sqrt(this BigInteger big)
        {
            if (big.Sign < 0)
                throw new ArithmeticException("This function doesn't work for negative numbers.");

            if (big == 0)
                return 0;
            if (big < long.MaxValue)
                return new BigInteger((int)Math.Sqrt((double)big));

            // The initial estimate:
            int bitLength = big.GetBitLength(true);
            BigInteger root = BigInteger.One << (bitLength / 2);

            while (!IsSqrt(big, root))
            {
                // 1/2 (x0 + s/x0)
                root = (root + (big / root)) / 2;
            }

            return root;
        }
        private static bool IsSqrt(BigInteger n, BigInteger root)
        {
            BigInteger lowerBound = root * root;
            BigInteger upperBound = (root + 1) * (root + 1);

            return (lowerBound <= n) && (n < upperBound);
        }


        /// <summary>
        /// Converts a <see cref="BigInteger"/> value to its binary representation.
        /// </summary>
        /// <param name="big">Big Integer value to convert.</param>
        /// <returns>A binary representation of the <see cref="BigInteger"/></returns>
        public static string ToBinary(this BigInteger big)
        {
            byte[] bytes = big.ToByteArrayExt(false, true);

            StringBuilder result = new(bytes.Length * 8);
            for (int i = bytes.Length - 1; i >= 0; i--)
            {
                result.Append(Convert.ToString(bytes[i], 2).PadLeft(8, '0'));
            }

            return result.ToString();
        }


        /// <summary>
        /// Converts a <see cref="BigInteger"/> value to a byte array in a desired endianness 
        /// and can remove positive byte sign if available.
        /// </summary>
        /// <remarks>
        /// *Ext is used to make this function different from .Net core's function of the same name.
        /// </remarks>
        /// <param name="big">Big Integer value to convert.</param>
        /// <param name="returnBigEndian">Endianness of bytes in the returned array.</param>
        /// <param name="removePositiveSign">If true will remove the byte indicating positive numbers if available.</param>
        /// <returns>An array of bytes.</returns>
        public static byte[] ToByteArrayExt(this BigInteger big, bool returnBigEndian, bool removePositiveSign)
        {
            byte[] ba = big.ToByteArray(); // Result is always in little-endian

            // Remove positive sign if wanted and if available:
            if (removePositiveSign && ba.Length > 1 && ba[^1] == 0)
            {
                ba = ba.SubArray(0, ba.Length - 1);
            }

            if (returnBigEndian)
            {
                Array.Reverse(ba);
            }

            return ba;
        }
    }
}
