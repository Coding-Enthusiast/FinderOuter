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
            Debug.Assert(ba.Length == 32);

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
    }
}
