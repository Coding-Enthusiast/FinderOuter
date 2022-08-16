// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace FinderOuter.Backend.ECC
{
    /// <summary>
    /// 256-bit unsigned integer using radix-2^52 representation (instead of 2^32)
    /// </summary>
    /// <remarks>
    /// This implements a UInt256 using 5x UInt64 parts (total of 320 bits).
    /// When normalized, each item stores 52 bits except the last that is 48 bits.
    /// </remarks>
    public readonly struct UInt256_5x52
    {
        public UInt256_5x52(uint a)
        {
            b0 = a;
            b1 = 0; b2 = 0; b3 = 0; b4 = 0;
            magnitude = (a != 0) ? 1 : 0;
            isNormalized = true;
        }

        public UInt256_5x52(uint u0, uint u1, uint u2, uint u3, uint u4, uint u5, uint u6, uint u7)
        {
            // Each part stores 52 bits except last that is 48 bits
            // 32 + 20(rem:32-20=12)
            b0 = u0 | ((ulong)(u1 & 0b00000000_00001111_11111111_11111111U) << 32);
            // 12 + 32 + 8(24)
            b1 = (u1 >> 20) | ((ulong)u2 << 12) | ((ulong)(u3 & 0b00000000_00000000_00000000_11111111U) << 44);
            // 24 + 28(4)
            b2 = (u3 >> 8) | ((ulong)(u4 & 0b00001111_11111111_11111111_11111111U) << 24);
            // 4 + 32 + 16(16)
            b3 = (u4 >> 28) | ((ulong)u5 << 4) | ((u6 & 0b00000000_00000000_11111111_11111111U) << 36);
            // 16 + 32
            b4 = (u6 >> 16) | ((ulong)u7 << 16);

            magnitude = 1;
            isNormalized = true;
        }

        public UInt256_5x52(ulong u0, ulong u1, ulong u2, ulong u3)
        {
            // Each part stores 52 bits except last that is 48 bits

            b0 = u0 & 0xFFFFFFFFFFFFF;
            b1 = u0 >> 52 | ((u1 << 12) & 0xFFFFFFFFFFFFFUL);
            b2 = u1 >> 40 | ((u2 << 24) & 0xFFFFFFFFFFFFFUL);
            b3 = u2 >> 28 | ((u3 << 36) & 0xFFFFFFFFFFFFFUL);
            b4 = u3 >> 16;

            magnitude = 1;
            isNormalized = true;
        }

        public UInt256_5x52(ulong u0, ulong u1, ulong u2, ulong u3, ulong u4, int magnitude, bool normalized)
        {
            b0 = u0; b1 = u1; b2 = u2; b3 = u3; b4 = u4;
            this.magnitude = magnitude;
            isNormalized = normalized;
        }

        public UInt256_5x52(ReadOnlySpan<byte> ba, out bool isValid)
        {
            Debug.Assert(ba.Length == 32);

            b0 = (ulong)ba[31] |
                 ((ulong)ba[30] << 8) |
                 ((ulong)ba[29] << 16) |
                 ((ulong)ba[28] << 24) |
                 ((ulong)ba[27] << 32) |
                 ((ulong)ba[26] << 40) |
                 ((ulong)(ba[25] & 0x0F) << 48);
            b1 = ((ulong)ba[25] >> 4) |
                 ((ulong)ba[24] << 4) |
                 ((ulong)ba[23] << 12) |
                 ((ulong)ba[22] << 20) |
                 ((ulong)ba[21] << 28) |
                 ((ulong)ba[20] << 36) |
                 ((ulong)ba[19] << 44);
            b2 = (ulong)ba[18] |
                 ((ulong)ba[17] << 8) |
                 ((ulong)ba[16] << 16) |
                 ((ulong)ba[15] << 24) |
                 ((ulong)ba[14] << 32) |
                 ((ulong)ba[13] << 40) |
                 ((ulong)(ba[12] & 0x0F) << 48);
            b3 = ((ulong)ba[12] >> 4) |
                 ((ulong)ba[11] << 4) |
                 ((ulong)ba[10] << 12) |
                 ((ulong)ba[9] << 20) |
                 ((ulong)ba[8] << 28) |
                 ((ulong)ba[7] << 36) |
                 ((ulong)ba[6] << 44);
            b4 = (ulong)ba[5] |
                 ((ulong)ba[4] << 8) |
                 ((ulong)ba[3] << 16) |
                 ((ulong)ba[2] << 24) |
                 ((ulong)ba[1] << 32) |
                 ((ulong)ba[0] << 40);

            isValid = !((b4 == 0x0FFFFFFFFFFFFUL) & ((b3 & b2 & b1) == 0xFFFFFFFFFFFFFUL) & (b0 >= 0xFFFFEFFFFFC2FUL));

            magnitude = 1;
            isNormalized = true;
        }

        public readonly ulong b0, b1, b2, b3, b4;
        public readonly int magnitude;
        public readonly bool isNormalized;


        private static readonly UInt256_5x52 _zero = new(0, 0, 0, 0, 0, 0, true);
        public static ref readonly UInt256_5x52 Zero => ref _zero;


        public readonly bool IsOdd => (b0 & 1) != 0;
        public bool IsZero => (b0 | b1 | b2 | b3 | b4) == 0;


        public void WriteToSpan(Span<byte> ba)
        {
            Debug.Assert(isNormalized);
            Debug.Assert(ba.Length >= 32);

            // Note: Last item is 48 bits, the rest are 52 bits
            // Read comments from bottom to make sense, array is set in reverse for optimization
            ba[31] = (byte)b0; // 8(0)
            ba[30] = (byte)(b0 >> 8); // 8(8)
            ba[29] = (byte)(b0 >> 16); // 8(16)
            ba[28] = (byte)(b0 >> 24); // 8(24)
            ba[27] = (byte)(b0 >> 32); // 8(32)
            ba[26] = (byte)(b0 >> 40); // 8(40)
            Debug.Assert(((b0 >> 48) & 0b11110000) == 0);
            ba[25] = (byte)((b1 & 0b1111) << 4 | b0 >> 48); // 4(0)+4(48)
            ba[24] = (byte)(b1 >> 4); // 8(4)
            ba[23] = (byte)(b1 >> 12); // 8(12)
            ba[22] = (byte)(b1 >> 20); // 8(20)
            ba[21] = (byte)(b1 >> 28); // 8(28)
            ba[20] = (byte)(b1 >> 36); // 8(36)
            ba[19] = (byte)(b1 >> 44); // 8(52-8=44)
            ba[18] = (byte)b2; // 8(0)
            ba[17] = (byte)(b2 >> 8); // 8(8)
            ba[16] = (byte)(b2 >> 16); // 8(16)
            ba[15] = (byte)(b2 >> 24); // 8(24)
            ba[14] = (byte)(b2 >> 32); // 8(32)
            ba[13] = (byte)(b2 >> 40); // 8(40)
            Debug.Assert(((b2 >> 48) & 0b11110000) == 0);
            ba[12] = (byte)((b3 & 0b1111) << 4 | b2 >> 48); // 4(0)+4(48)
            ba[11] = (byte)(b3 >> 4); // 8(4)
            ba[10] = (byte)(b3 >> 12); // 8(12)
            ba[9] = (byte)(b3 >> 20); // 8(20)
            ba[8] = (byte)(b3 >> 28); // 8(28)
            ba[7] = (byte)(b3 >> 36); // 8(36)
            ba[6] = (byte)(b3 >> 44); // 8(52-8=44)
            ba[5] = (byte)b4; // 8(0)
            ba[4] = (byte)(b4 >> 8); // 8(8)
            ba[3] = (byte)(b4 >> 16); // 8(16)
            ba[2] = (byte)(b4 >> 24); // 8(24)
            ba[1] = (byte)(b4 >> 32); // 8(40-8=32)
            ba[0] = (byte)(b4 >> 40); // Take 8 bits (rem=48-8=40)
        }

        public UInt256_4x64 ToUInt256_4x64()
        {
            Debug.Assert(isNormalized);

            ulong u0 = b0 | b1 << 52;
            ulong u1 = b1 >> 12 | b2 << 40;
            ulong u2 = b2 >> 24 | b3 << 28;
            ulong u3 = b3 >> 36 | b4 << 16;

            return new UInt256_4x64(u0, u1, u2, u3);
        }

        public UInt256_5x52 Normalize()
        {
            //ulong t0 = b0, t1 = b1, t2 = b2, t3 = b3, t4 = b4;

            /* Reduce t4 at the start so there will be at most a single carry from the first pass */
            ulong m;
            ulong x = b4 >> 48;
            ulong t4 = b4 & 0x0FFFFFFFFFFFFUL;

            /* The first pass ensures the magnitude is 1, ... */
            ulong t0 = b0 + (x * 0x1000003D1UL);
            ulong t1 = b1 + (t0 >> 52); t0 &= 0xFFFFFFFFFFFFFUL;
            ulong t2 = b2 + (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFUL; m = t1;
            ulong t3 = b3 + (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFUL; m &= t2;
            t4 += t3 >> 52; t3 &= 0xFFFFFFFFFFFFFUL; m &= t3;

            /* ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element) */
            Debug.Assert(t4 >> 49 == 0);

            /* At most a single final reduction is needed; check if the value is >= the field characteristic */
            ulong bb = ((t4 == 0x0FFFFFFFFFFFFUL) & (m == 0xFFFFFFFFFFFFFUL) & (t0 >= 0xFFFFEFFFFFC2FUL)) ? 1U : 0U;
            x = (t4 >> 48) | bb;

            /* Apply the final reduction (for constant-time behaviour, we do it always) */
            t0 += x * 0x1000003D1UL;
            t1 += (t0 >> 52); t0 &= 0xFFFFFFFFFFFFFUL;
            t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFUL;
            t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFUL;
            t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFUL;

            /* If t4 didn't carry to bit 48 already, then it should have after any final reduction */
            Debug.Assert(t4 >> 48 == x);

            /* Mask off the possible multiple of 2^256 from the final reduction */
            t4 &= 0x0FFFFFFFFFFFFUL;

            return new(t0, t1, t2, t3, t4, 1, true);
        }

        public UInt256_5x52 NormalizeWeak()
        {
            /* Reduce t4 at the start so there will be at most a single carry from the first pass */
            ulong x = b4 >> 48; ulong t4 = b4 & 0x0FFFFFFFFFFFFUL;

            /* The first pass ensures the magnitude is 1, ... */
            ulong t0 = b0 + (x * 0x1000003D1UL);
            ulong t1 = b1 + (t0 >> 52); t0 &= 0xFFFFFFFFFFFFFUL;
            ulong t2 = b2 + (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFUL;
            ulong t3 = b3 + (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFUL;
            t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFUL;

            /* ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element) */
            Debug.Assert(t4 >> 49 == 0);

            return new(t0, t1, t2, t3, t4, 1, true);
        }

        public UInt256_5x52 NormalizeVar()
        {
            /* Reduce t4 at the start so there will be at most a single carry from the first pass */
            ulong m;
            ulong x = b4 >> 48; ulong t4 = b4 & 0x0FFFFFFFFFFFFUL;

            /* The first pass ensures the magnitude is 1, ... */
            ulong t0 = b0 + (x * 0x1000003D1UL);
            ulong t1 = b1 + (t0 >> 52); t0 &= 0xFFFFFFFFFFFFFUL;
            ulong t2 = b2 + (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFUL; m = t1;
            ulong t3 = b3 + (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFUL; m &= t2;
            t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFUL; m &= t3;

            /* ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element) */
            Debug.Assert(t4 >> 49 == 0);

            /* At most a single final reduction is needed; check if the value is >= the field characteristic */
            ulong bb = ((t4 == 0x0FFFFFFFFFFFFUL) & (m == 0xFFFFFFFFFFFFFUL) & (t0 >= 0xFFFFEFFFFFC2FUL)) ? 1U : 0U;
            x = (t4 >> 48) | bb;

            if (x != 0)
            {
                t0 += 0x1000003D1UL;
                t1 += (t0 >> 52); t0 &= 0xFFFFFFFFFFFFFUL;
                t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFUL;
                t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFUL;
                t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFUL;

                /* If t4 didn't carry to bit 48 already, then it should have after any final reduction */
                Debug.Assert(t4 >> 48 == x);

                /* Mask off the possible multiple of 2^256 from the final reduction */
                t4 &= 0x0FFFFFFFFFFFFUL;
            }

            return new(t0, t1, t2, t3, t4, 1, true);
        }

        public bool NormalizesToZero()
        {
            /* z0 tracks a possible raw value of 0, z1 tracks a possible raw value of P */
            ulong z0, z1;

            /* Reduce t4 at the start so there will be at most a single carry from the first pass */
            ulong x = b4 >> 48; ulong t4 = b4 & 0x0FFFFFFFFFFFFUL;

            /* The first pass ensures the magnitude is 1, ... */
            ulong t0 = b0 + (x * 0x1000003D1UL);
            ulong t1 = b1 + (t0 >> 52); t0 &= 0xFFFFFFFFFFFFFUL; z0 = t0; z1 = t0 ^ 0x1000003D0UL;
            ulong t2 = b2 + (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFUL; z0 |= t1; z1 &= t1;
            ulong t3 = b3 + (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFUL; z0 |= t2; z1 &= t2;
            t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFUL; z0 |= t3; z1 &= t3;
            z0 |= t4; z1 &= t4 ^ 0xF000000000000UL;

            /* ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element) */
            Debug.Assert(t4 >> 49 == 0);

            return (z0 == 0) | (z1 == 0xFFFFFFFFFFFFFUL);
        }

        public bool NormalizeToZeroVar()
        {
            ulong t0, t1, t2, t3, t4;
            ulong z0, z1;
            ulong x;

            t0 = b0;
            t4 = b4;

            /* Reduce t4 at the start so there will be at most a single carry from the first pass */
            x = t4 >> 48;

            /* The first pass ensures the magnitude is 1, ... */
            t0 += x * 0x1000003D1UL;

            /* z0 tracks a possible raw value of 0, z1 tracks a possible raw value of P */
            z0 = t0 & 0xFFFFFFFFFFFFFUL;
            z1 = z0 ^ 0x1000003D0UL;

            /* Fast return path should catch the majority of cases */
            if ((z0 != 0UL) & (z1 != 0xFFFFFFFFFFFFFUL))
            {
                return false;
            }

            t1 = b1;
            t2 = b2;
            t3 = b3;

            t4 &= 0x0FFFFFFFFFFFFUL;

            t1 += (t0 >> 52);
            t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFUL; z0 |= t1; z1 &= t1;
            t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFUL; z0 |= t2; z1 &= t2;
            t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFUL; z0 |= t3; z1 &= t3;
            z0 |= t4; z1 &= t4 ^ 0xF000000000000UL;

            /* ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element) */
            Debug.Assert(t4 >> 49 == 0);

            return (z0 == 0) | (z1 == 0xFFFFFFFFFFFFFUL);
        }

        public UInt256_5x52 Negate(int m)
        {
            Debug.Assert(magnitude <= m);
            Debug.Assert(0xFFFFEFFFFFC2FUL * 2 * ((ulong)m + 1) >= 0xFFFFFFFFFFFFFUL * 2 * (ulong)m);
            Debug.Assert(0xFFFFFFFFFFFFFUL * 2 * ((ulong)m + 1) >= 0xFFFFFFFFFFFFFUL * 2 * (ulong)m);
            Debug.Assert(0x0FFFFFFFFFFFFUL * 2 * ((ulong)m + 1) >= 0x0FFFFFFFFFFFFUL * 2 * (ulong)m);

            ulong r0 = 0xFFFFEFFFFFC2FUL * 2 * ((ulong)m + 1) - b0;
            ulong r1 = 0xFFFFFFFFFFFFFUL * 2 * ((ulong)m + 1) - b1;
            ulong r2 = 0xFFFFFFFFFFFFFUL * 2 * ((ulong)m + 1) - b2;
            ulong r3 = 0xFFFFFFFFFFFFFUL * 2 * ((ulong)m + 1) - b3;
            ulong r4 = 0x0FFFFFFFFFFFFUL * 2 * ((ulong)m + 1) - b4;

            return new(r0, r1, r2, r3, r4, m + 1, false);
        }


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void CMov(ref UInt256_5x52 r, UInt256_5x52 a, int flag)
        {
            ulong mask0, mask1;
            mask0 = (ulong)flag + ~(ulong)0;
            mask1 = ~mask0;
            r = new UInt256_5x52(
                (r.b0 & mask0) | (a.b0 & mask1),
                (r.b1 & mask0) | (a.b1 & mask1),
                (r.b2 & mask0) | (a.b2 & mask1),
                (r.b3 & mask0) | (a.b3 & mask1),
                (r.b4 & mask0) | (a.b4 & mask1),
                a.magnitude > r.magnitude ? a.magnitude : r.magnitude,
                r.isNormalized & a.isNormalized);
        }


        public UInt256_5x52 Sqr() => Sqr(1);

        public UInt256_5x52 Sqr(int times)
        {
            Debug.Assert(magnitude <= 8);

            const ulong M = 0xFFFFFFFFFFFFFUL, R = 0x1000003D10UL;
            ulong t3, t4, tx, u0;
            UInt128 c, d;
            ulong a0 = b0, a1 = b1, a2 = b2, a3 = b3, a4 = b4;
            ulong r0 = 0, r1 = 0, r2 = 0, r3 = 0, r4 = 0;


            for (int i = 0; i < times; i++)
            {
                Debug.Assert(a0 >> 56 == 0);
                Debug.Assert(a1 >> 56 == 0);
                Debug.Assert(a2 >> 56 == 0);
                Debug.Assert(a3 >> 56 == 0);
                Debug.Assert(a4 >> 52 == 0);

                /**  [... a b c] is a shorthand for ... + a<<104 + b<<52 + c<<0 mod n.
                 *  px is a shorthand for sum(a[i]*a[x-i], i=0..x).
                 *  Note that [x 0 0 0 0 0] = [x*R].
                 */

                d = (UInt128)(a0 * 2) * a3
                   + (UInt128)(a1 * 2) * a2;
                Debug.Assert((d >> 114).IsZero);
                /* [d 0 0 0] = [p3 0 0 0] */
                c = (UInt128)a4 * a4;
                Debug.Assert((c >> 112).IsZero);
                /* [c 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
                d += (UInt128)R * (ulong)c; c >>= 64;
                Debug.Assert((d >> 115).IsZero);
                Debug.Assert((c >> 48).IsZero);
                /* [(c<<12) 0 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
                t3 = d.b0 & M; d >>= 52;
                Debug.Assert(t3 >> 52 == 0);
                Debug.Assert((d >> 63).IsZero);
                /* [(c<<12) 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */

                a4 *= 2;
                d += (UInt128)a0 * a4
                   + (UInt128)(a1 * 2) * a3
                   + (UInt128)a2 * a2;
                Debug.Assert((d >> 115).IsZero);
                /* [(c<<12) 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
                d += (UInt128)(R << 12) * (ulong)c;
                Debug.Assert((d >> 116).IsZero);
                /* [d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
                t4 = d.b0 & M; d >>= 52;
                Debug.Assert(t4 >> 52 == 0);
                Debug.Assert((d >> 64).IsZero);
                /* [d t4 t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
                tx = (t4 >> 48); t4 &= (M >> 4);
                Debug.Assert(tx >> 4 == 0);
                Debug.Assert(t4 >> 48 == 0);
                /* [d t4+(tx<<48) t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */

                c = (UInt128)a0 * a0;
                Debug.Assert((c >> 112).IsZero);
                /* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 0 p4 p3 0 0 p0] */
                d += (UInt128)a1 * a4
                   + (UInt128)(a2 * 2) * a3;
                Debug.Assert((d >> 114).IsZero);
                /* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
                u0 = d.b0 & M; d >>= 52;
                Debug.Assert(u0 >> 52 == 0);
                Debug.Assert((d >> 62).IsZero);
                /* [d u0 t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
                /* [d 0 t4+(tx<<48)+(u0<<52) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
                u0 = (u0 << 4) | tx;
                Debug.Assert(u0 >> 56 == 0);
                /* [d 0 t4+(u0<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
                c += (UInt128)u0 * (R >> 4);
                Debug.Assert((c >> 113).IsZero);
                /* [d 0 t4 t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
                r0 = c.b0 & M; c >>= 52;
                Debug.Assert(r0 >> 52 == 0);
                Debug.Assert((c >> 61).IsZero);
                /* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 0 p0] */

                a0 *= 2;
                c += (UInt128)a0 * a1;
                Debug.Assert((c >> 114).IsZero);
                /* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 p1 p0] */
                d += (UInt128)a2 * a4
                   + (UInt128)a3 * a3;
                Debug.Assert((d >> 114).IsZero);
                /* [d 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
                c += (d & M) * R; d >>= 52;
                Debug.Assert((c >> 115).IsZero);
                Debug.Assert((d >> 62).IsZero);
                /* [d 0 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
                r1 = c.b0 & M; c >>= 52;
                Debug.Assert(r1 >> 52 == 0);
                Debug.Assert((c >> 63).IsZero);
                /* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */

                c += (UInt128)a0 * a2
                   + (UInt128)a1 * a1;
                Debug.Assert((c >> 114).IsZero);
                /* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 p2 p1 p0] */
                d += (UInt128)a3 * a4;
                Debug.Assert((d >> 114).IsZero);
                /* [d 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
                c += (UInt128)R * (ulong)d; d >>= 64;
                Debug.Assert((c >> 115).IsZero);
                Debug.Assert((d >> 50).IsZero);
                /* [(d<<12) 0 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
                r2 = c.b0 & M; c >>= 52;
                Debug.Assert(r2 >> 52 == 0);
                Debug.Assert((c >> 63).IsZero);
                /* [(d<<12) 0 0 0 t4 t3+c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */

                c += (UInt128)(R << 12) * (ulong)d + t3;
                Debug.Assert((c >> 100).IsZero);
                /* [t4 c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
                r3 = c.b0 & M; c >>= 52;
                Debug.Assert(r3 >> 52 == 0);
                Debug.Assert((c >> 48).IsZero);
                /* [t4+c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
                c += t4;
                Debug.Assert((c >> 49).IsZero);
                /* [c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
                r4 = c.b0;
                Debug.Assert(r4 >> 49 == 0);
                /* [r4 r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */

                a0 = r0;
                a1 = r1;
                a2 = r2;
                a3 = r3;
                a4 = r4;
            }

            return new(r0, r1, r2, r3, r4, 1, false);
        }


        public UInt256_5x52 InverseVariable()
        {
            return Inverse();
        }

        public UInt256_5x52 Inverse()
        {
            UInt256_5x52 x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t1;
            /* The binary representation of (p - 2) has 5 blocks of 1s, with lengths in
			 *  { 1, 2, 22, 223 }. Use an addition chain to calculate 2^n - 1 for each block:
			 *  [1], [2], 3, 6, 9, 11, [22], 44, 88, 176, 220, [223]
			 */

            x2 = Sqr();
            x2 = x2 * this;

            x3 = x2.Sqr();
            x3 = x3 * this;

            x6 = x3;
            x6 = x6.Sqr(3);
            x6 = x6 * x3;

            x9 = x6;
            x9 = x9.Sqr(3);
            x9 = x9 * x3;

            x11 = x9;
            x11 = x11.Sqr(2);

            x11 = x11 * x2;

            x22 = x11;
            x22 = x22.Sqr(11);
            x22 = x22 * x11;

            x44 = x22;
            x44 = x44.Sqr(22);
            x44 = x44 * x22;

            x88 = x44;
            x88 = x88.Sqr(44);
            x88 = x88 * x44;

            x176 = x88;
            x176 = x176.Sqr(88);
            x176 = x176 * x88;

            x220 = x176;
            x220 = x220.Sqr(44);
            x220 = x220 * x44;

            x223 = x220;
            x223 = x223.Sqr(3);
            x223 = x223 * x3;

            /* The final result is then assembled using a sliding window over the blocks. */

            t1 = x223;
            t1 = t1.Sqr(23);
            t1 = t1 * x22;

            t1 = t1.Sqr(5);
            t1 = t1 * this;
            t1 = t1.Sqr(3);
            t1 = t1 * x2;
            t1 = t1.Sqr(2);
            return this * t1;
        }


        public UInt256_5x52 Multiply(uint a)
        {
            UInt256_5x52 r = new(
                b0 * a,
                b1 * a,
                b2 * a,
                b3 * a,
                b4 * a,
                magnitude * (int)a, false);
            return r;
        }

        public UInt256_5x52 Multiply(in UInt256_5x52 b)
        {
            UInt256_5x52 r = MulInner(b, 1, false);
            return r;
        }


        private UInt256_5x52 MulInner(in UInt256_5x52 b, int magnitude, bool normalized)
        {
            UInt128 c, d;
            ulong t3, t4, tx, u0;
            const ulong M = 0xFFFFFFFFFFFFFUL, R = 0x1000003D10UL;

            Debug.Assert(b0 >> 56 == 0);
            Debug.Assert(b1 >> 56 == 0);
            Debug.Assert(b2 >> 56 == 0);
            Debug.Assert(b3 >> 56 == 0);
            Debug.Assert(b4 >> 52 == 0);
            Debug.Assert(b.b0 >> 56 == 0);
            Debug.Assert(b.b1 >> 56 == 0);
            Debug.Assert(b.b2 >> 56 == 0);
            Debug.Assert(b.b3 >> 56 == 0);
            Debug.Assert(b.b4 >> 52 == 0);

            /*  [... a b c] is a shorthand for ... + a<<104 + b<<52 + c<<0 mod n.
             *  for 0 <= x <= 4, px is a shorthand for sum(a[i]*b[x-i], i=0..x).
             *  for 4 <= x <= 8, px is a shorthand for sum(a[i]*b[x-i], i=(x-4)..4)
             *  Note that [x 0 0 0 0 0] = [x*R].
             */

            d = (UInt128)b0 * b.b3
               + (UInt128)b1 * b.b2
               + (UInt128)b2 * b.b1
               + (UInt128)b3 * b.b0;
            Debug.Assert((d >> 114).IsZero);
            /* [d 0 0 0] = [p3 0 0 0] */
            c = (UInt128)b4 * b.b4;
            Debug.Assert((c >> 112).IsZero);
            /* [c 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
            d += (UInt128)R * (ulong)c; c >>= 64;
            Debug.Assert((d >> 115).IsZero);
            Debug.Assert((c >> 48).IsZero);
            /* [(c<<12) 0 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
            t3 = d.b0 & M; d >>= 52;
            Debug.Assert(t3 >> 52 == 0);
            Debug.Assert((d >> 63).IsZero);
            /* [(c<<12) 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */

            d += (UInt128)b0 * b.b4
               + (UInt128)b1 * b.b3
               + (UInt128)b2 * b.b2
               + (UInt128)b3 * b.b1
               + (UInt128)b4 * b.b0;
            Debug.Assert((d >> 115).IsZero);
            /* [(c<<12) 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
            d += (UInt128)(R << 12) * (ulong)c;
            Debug.Assert((d >> 116).IsZero);
            /* [d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
            t4 = d.b0 & M; d >>= 52;
            Debug.Assert(t4 >> 52 == 0);
            Debug.Assert((d >> 64).IsZero);
            /* [d t4 t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
            tx = (t4 >> 48); t4 &= (M >> 4);
            Debug.Assert(tx >> 4 == 0);
            Debug.Assert(t4 >> 48 == 0);
            /* [d t4+(tx<<48) t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */

            c = (UInt128)b0 * b.b0;
            Debug.Assert((c >> 112).IsZero);
            /* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 0 p4 p3 0 0 p0] */
            d += (UInt128)b1 * b.b4
               + (UInt128)b2 * b.b3
               + (UInt128)b3 * b.b2
               + (UInt128)b4 * b.b1;
            Debug.Assert((d >> 115).IsZero);
            /* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
            u0 = d.b0 & M; d >>= 52;
            Debug.Assert(u0 >> 52 == 0);
            Debug.Assert((d >> 63).IsZero);
            /* [d u0 t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
            /* [d 0 t4+(tx<<48)+(u0<<52) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
            u0 = (u0 << 4) | tx;
            Debug.Assert(u0 >> 56 == 0);
            /* [d 0 t4+(u0<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
            c += (UInt128)u0 * (R >> 4);
            Debug.Assert((c >> 115).IsZero);
            /* [d 0 t4 t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
            ulong r0 = c.b0 & M; c >>= 52;
            Debug.Assert(r0 >> 52 == 0);
            Debug.Assert((c >> 61).IsZero);
            /* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 0 p0] */

            c += (UInt128)b0 * b.b1
               + (UInt128)b1 * b.b0;
            Debug.Assert((c >> 114).IsZero);
            /* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 p1 p0] */
            d += (UInt128)b2 * b.b4
               + (UInt128)b3 * b.b3
               + (UInt128)b4 * b.b2;
            Debug.Assert((d >> 114).IsZero);
            /* [d 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
            c += (d & M) * R; d >>= 52;
            Debug.Assert((c >> 115).IsZero);
            Debug.Assert((d >> 62).IsZero);
            /* [d 0 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
            ulong r1 = c.b0 & M; c >>= 52;
            Debug.Assert(r1 >> 52 == 0);
            Debug.Assert((c >> 63).IsZero);
            /* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */

            c += (UInt128)b0 * b.b2
               + (UInt128)b1 * b.b1
               + (UInt128)b2 * b.b0;
            Debug.Assert((c >> 114).IsZero);
            /* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 p2 p1 p0] */
            d += (UInt128)b3 * b.b4
               + (UInt128)b4 * b.b3;
            Debug.Assert((d >> 114).IsZero);
            /* [d 0 0 t4 t3 c t1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
            c += (UInt128)R * (ulong)d; d >>= 64;
            Debug.Assert((c >> 115).IsZero);
            Debug.Assert((d >> 50).IsZero);
            /* [(d<<12) 0 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */

            ulong r2 = c.b0 & M; c >>= 52;
            Debug.Assert(r2 >> 52 == 0);
            Debug.Assert((c >> 63).IsZero);
            /* [(d<<12) 0 0 0 t4 t3+c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
            c += (UInt128)(R << 12) * (ulong)d + t3;
            Debug.Assert((c >> 100).IsZero);
            /* [t4 c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
            ulong r3 = c.b0 & M; c >>= 52;
            Debug.Assert(r3 >> 52 == 0);
            Debug.Assert((c >> 48).IsZero);
            /* [t4+c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
            c += t4;
            Debug.Assert((c >> 49).IsZero);
            /* [c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
            ulong r4 = c.b0;
            Debug.Assert(r4 >> 49 == 0);
            /* [r4 r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */

            return new(r0, r1, r2, r3, r4, magnitude, normalized);
        }


        public bool Sqrt(out UInt256_5x52 result)
        {
            /* Given that p is congruent to 3 mod 4, we can compute the square root of
			 *  a mod p as the (p+1)/4'th power of a.
			 *
			 *  As (p+1)/4 is an even number, it will have the same result for a and for
			 *  (-a). Only one of these two numbers actually has a square root however,
			 *  so we test at the end by squaring and comparing to the input.
			 *  Also because (p+1)/4 is an even number, the computed square root is
			 *  itself always a square (a ** ((p+1)/4) is the square of a ** ((p+1)/8)).
			 */
            UInt256_5x52 x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t1;

            /* The binary representation of (p + 1)/4 has 3 blocks of 1s, with lengths in
			 *  { 2, 22, 223 }. Use an addition chain to calculate 2^n - 1 for each block:
			 *  1, [2], 3, 6, 9, 11, [22], 44, 88, 176, 220, [223]
			 */

            x2 = Sqr();
            x2 = x2 * this;

            x3 = x2.Sqr();
            x3 = x3 * this;

            x6 = x3;
            x6 = x6.Sqr(3);
            x6 = x6 * x3;

            x9 = x6;
            x9 = x9.Sqr(3);
            x9 = x9 * x3;

            x11 = x9;
            x11 = x11.Sqr(2);
            x11 = x11 * x2;

            x22 = x11;
            x22 = x22.Sqr(11);
            x22 = x22 * x11;

            x44 = x22;
            x44 = x44.Sqr(22);
            x44 = x44 * x22;

            x88 = x44;
            x88 = x88.Sqr(44);
            x88 = x88 * x44;

            x176 = x88;
            x176 = x176.Sqr(88);
            x176 = x176 * x88;

            x220 = x176;
            x220 = x220.Sqr(44);
            x220 = x220 * x44;

            x223 = x220;
            x223 = x223.Sqr(3);
            x223 = x223 * x3;

            /* The final result is then assembled using a sliding window over the blocks. */

            t1 = x223;
            t1 = t1.Sqr(23);
            t1 = t1 * x22;
            t1 = t1.Sqr(6);
            t1 = t1 * x2;
            t1 = t1.Sqr();
            result = t1.Sqr();

            /* Check that a square root was actually calculated */

            t1 = result.Sqr();
            return t1.Equals(this);
        }


        public readonly UInt256_5x52 Add(in UInt256_5x52 a)
        {
            UInt256_5x52 r = new(
                b0 + a.b0,
                b1 + a.b1,
                b2 + a.b2,
                b3 + a.b3,
                b4 + a.b4,
                magnitude + a.magnitude,
                false);
            return r;
        }

        public static UInt256_5x52 operator +(in UInt256_5x52 a, in UInt256_5x52 b) => a.Add(b);
        public static UInt256_5x52 operator *(in UInt256_5x52 a, uint b) => a.Multiply(b);
        public static UInt256_5x52 operator *(in UInt256_5x52 a, in UInt256_5x52 b) => a.Multiply(b);


        public bool Equals(UInt256_5x52 b)
        {
            UInt256_5x52 na = Negate(1);
            na += b;
            return na.NormalizesToZero();
        }
    }
}
