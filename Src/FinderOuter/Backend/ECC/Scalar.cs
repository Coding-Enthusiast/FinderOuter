// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace FinderOuter.Backend.ECC
{
    public readonly struct Scalar
    {
        public Scalar(uint u0, uint u1, uint u2, uint u3, uint u4, uint u5, uint u6, uint u7)
        {
            b0 = u0; b1 = u1; b2 = u2; b3 = u3;
            b4 = u4; b5 = u5; b6 = u6; b7 = u7;
        }

        /// <param name="hPt"><see cref="Cryptography.Hashing.Sha256Fo.hashState"/> pointer</param>
        public unsafe Scalar(uint* hPt, out int overflow)
        {
            b7 = hPt[0]; b6 = hPt[1]; b5 = hPt[2]; b4 = hPt[3];
            b3 = hPt[4]; b2 = hPt[5]; b1 = hPt[6]; b0 = hPt[7];
            overflow = GetOverflow();
        }

        /// <param name="hPt"><see cref="Cryptography.Hashing.Sha512Fo.hashState"/> pointer</param>
        public unsafe Scalar(ulong* hPt, out int overflow)
        {
            b7 = (uint)(hPt[0] >> 32); b6 = (uint)hPt[0];
            b5 = (uint)(hPt[1] >> 32); b4 = (uint)hPt[1];
            b3 = (uint)(hPt[2] >> 32); b2 = (uint)hPt[2];
            b1 = (uint)(hPt[3] >> 32); b0 = (uint)hPt[3];

            overflow = GetOverflow();
        }

        public unsafe Scalar(byte* pt, out int overflow)
        {
            b0 = pt[31] | (uint)pt[30] << 8 | (uint)pt[29] << 16 | (uint)pt[28] << 24;
            b1 = pt[27] | (uint)pt[26] << 8 | (uint)pt[25] << 16 | (uint)pt[24] << 24;
            b2 = pt[23] | (uint)pt[22] << 8 | (uint)pt[21] << 16 | (uint)pt[20] << 24;
            b3 = pt[19] | (uint)pt[18] << 8 | (uint)pt[17] << 16 | (uint)pt[16] << 24;
            b4 = pt[15] | (uint)pt[14] << 8 | (uint)pt[13] << 16 | (uint)pt[12] << 24;
            b5 = pt[11] | (uint)pt[10] << 8 | (uint)pt[09] << 16 | (uint)pt[08] << 24;
            b6 = pt[07] | (uint)pt[06] << 8 | (uint)pt[05] << 16 | (uint)pt[04] << 24;
            b7 = pt[03] | (uint)pt[02] << 8 | (uint)pt[01] << 16 | (uint)pt[00] << 24;

            overflow = GetOverflow();

            Debug.Assert(overflow == 0 || overflow == 1);

            ulong t = (ulong)b0 + (uint)overflow * NC0;
            b0 = (uint)t; t >>= 32;
            t += (ulong)b1 + (uint)overflow * NC1;
            b1 = (uint)t; t >>= 32;
            t += (ulong)b2 + (uint)overflow * NC2;
            b2 = (uint)t; t >>= 32;
            t += (ulong)b3 + (uint)overflow * NC3;
            b3 = (uint)t; t >>= 32;
            t += (ulong)b4 + (uint)overflow * NC4;
            b4 = (uint)t; t >>= 32;
            t += b5;
            b5 = (uint)t; t >>= 32;
            t += b6;
            b6 = (uint)t; t >>= 32;
            t += b7;
            b7 = (uint)t;

            Debug.Assert((overflow == 1 && t >> 32 == 1) || (overflow == 0 && t >> 32 == 0));
            Debug.Assert(GetOverflow() == 0);
        }

        public Scalar(ReadOnlySpan<byte> data, out int overflow)
        {
            if (data.Length != 32)
                throw new ArgumentOutOfRangeException(nameof(data));

            b0 = data[31] | (uint)data[30] << 8 | (uint)data[29] << 16 | (uint)data[28] << 24;
            b1 = data[27] | (uint)data[26] << 8 | (uint)data[25] << 16 | (uint)data[24] << 24;
            b2 = data[23] | (uint)data[22] << 8 | (uint)data[21] << 16 | (uint)data[20] << 24;
            b3 = data[19] | (uint)data[18] << 8 | (uint)data[17] << 16 | (uint)data[16] << 24;
            b4 = data[15] | (uint)data[14] << 8 | (uint)data[13] << 16 | (uint)data[12] << 24;
            b5 = data[11] | (uint)data[10] << 8 | (uint)data[09] << 16 | (uint)data[08] << 24;
            b6 = data[07] | (uint)data[06] << 8 | (uint)data[05] << 16 | (uint)data[04] << 24;
            b7 = data[03] | (uint)data[02] << 8 | (uint)data[01] << 16 | (uint)data[00] << 24;

            overflow = GetOverflow();

            Debug.Assert(overflow == 0 || overflow == 1);

            ulong t = (ulong)b0 + (uint)overflow * NC0;
            b0 = (uint)t; t >>= 32;
            t += (ulong)b1 + (uint)overflow * NC1;
            b1 = (uint)t; t >>= 32;
            t += (ulong)b2 + (uint)overflow * NC2;
            b2 = (uint)t; t >>= 32;
            t += (ulong)b3 + (uint)overflow * NC3;
            b3 = (uint)t; t >>= 32;
            t += (ulong)b4 + (uint)overflow * NC4;
            b4 = (uint)t; t >>= 32;
            t += b5;
            b5 = (uint)t; t >>= 32;
            t += b6;
            b6 = (uint)t; t >>= 32;
            t += b7;
            b7 = (uint)t;

            Debug.Assert((overflow == 1 && t >> 32 == 1) || (overflow == 0 && t >> 32 == 0));
            Debug.Assert(GetOverflow() == 0);
        }

        public Scalar(Span<uint> d)
        {
            b0 = d[0];
            b1 = d[1];
            b2 = d[2];
            b3 = d[3];
            b4 = d[4];
            b5 = d[5];
            b6 = d[6];
            b7 = d[7];

            Debug.Assert(GetOverflow() == 0);
        }


        internal readonly uint b0, b1, b2, b3, b4, b5, b6, b7;

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
        // Since overflow will be less than 2N the result of X % N is X - N
        // X - N ≡ Z (mod N) => X + (2^256 - N) ≡ Z + 2^256 (mod N)
        // 250 ≡ 9 (mod 241) => 250 - 241 ≡ 250 + 256 - 241 ≡ 265 ≡ 265 - 256 ≡ 9 (mod 241)
        //                   => 265=0x0109 256=0x0100 => 265-256: get rid of highest bit => 0x0109≡0x09
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

        public bool IsZero => (b0 | b1 | b2 | b3 | b4 | b5 | b6 | b7) == 0;

        private int GetOverflow()
        {
            int yes = 0;
            int no = 0;
            no |= (b7 < N7 ? 1 : 0);
            no |= (b6 < N6 ? 1 : 0);
            no |= (b5 < N5 ? 1 : 0);
            no |= (b4 < N4 ? 1 : 0);
            yes |= (b4 > N4 ? 1 : 0) & ~no;
            no |= (b3 < N3 ? 1 : 0) & ~yes;
            yes |= (b3 > N3 ? 1 : 0) & ~no;
            no |= (b2 < N2 ? 1 : 0) & ~yes;
            yes |= (b2 > N2 ? 1 : 0) & ~no;
            no |= (b1 < N1 ? 1 : 0) & ~yes;
            yes |= (b1 > N1 ? 1 : 0) & ~no;
            yes |= (b0 >= N0 ? 1 : 0) & ~no;
            return yes;
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

        internal readonly uint GetBits(int offset, int count)
        {
            Debug.Assert(offset >= 0);
            Debug.Assert(count >= 0);
            Debug.Assert((offset + count - 1) >> 5 == offset >> 5);
            return (GetChunk(offset >> 5) >> (offset & 0x1F)) & ((1U << count) - 1);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint GetChunk(int index)
        {
            Debug.Assert(index >= 0 && index <= 7);
#pragma warning disable CS8509 // The switch expression does not handle all possible values of its input type (it is not exhaustive).
            return index switch
#pragma warning restore CS8509
            {
                0 => b0,
                1 => b1,
                2 => b2,
                3 => b3,
                4 => b4,
                5 => b5,
                6 => b6,
                7 => b7,
            };
        }


        public readonly Scalar Add(in Scalar other, out int overflow)
        {
            ulong t = (ulong)b0 + other.b0;
            uint r0 = (uint)t; t >>= 32;
            t += (ulong)b1 + other.b1;
            uint r1 = (uint)t; t >>= 32;
            t += (ulong)b2 + other.b2;
            uint r2 = (uint)t; t >>= 32;
            t += (ulong)b3 + other.b3;
            uint r3 = (uint)t; t >>= 32;
            t += (ulong)b4 + other.b4;
            uint r4 = (uint)t; t >>= 32;
            t += (ulong)b5 + other.b5;
            uint r5 = (uint)t; t >>= 32;
            t += (ulong)b6 + other.b6;
            uint r6 = (uint)t; t >>= 32;
            t += (ulong)b7 + other.b7;
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

            return new Scalar(r0, r1, r2, r3, r4, r5, r6, r7);
        }

        public readonly Scalar Multiply(in Scalar other)
        {
            Span<uint> val1 = new uint[8] { b0, b1, b2, b3, b4, b5, b6, b7 };
            Span<uint> val2 = stackalloc uint[16];
            Mul512(val2, this, other);
            Reduce512(val1, val2);
            return new Scalar(val1);
        }

        private static void Mul512(Span<uint> l, in Scalar a, in Scalar b)
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



        // All the following methods and operators are useful for testing and not much else
        public static bool operator ==(Scalar left, Scalar right) => left.Equals(right);
        public static bool operator !=(Scalar left, Scalar right) => !left.Equals(right);
        public bool Equals(in Scalar other) => b0 == other.b0 && b1 == other.b1 && b2 == other.b2 && b3 == other.b3 &&
                                               b4 == other.b4 && b5 == other.b5 && b6 == other.b6 && b7 == other.b7;
        public override bool Equals(object obj) => obj is Scalar other && Equals(in other);
        public override int GetHashCode() => HashCode.Combine(b0, b1, b2, b3, b4, b5, b6, b7);
    }
}
