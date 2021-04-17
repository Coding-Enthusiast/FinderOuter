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
    /// 256-bit unsigned integer using radix-2^26 representation (instead of 2^32)
    /// </summary>
    /// <remarks>
    /// This implements a UInt256 using 10x UInt32 parts (total of 320 bits).
    /// When normalized, each item stores 26 bits except the last that is 22 bits.
    /// </remarks>
    public readonly struct UInt256_10x26
    {
        public UInt256_10x26(uint a)
        {
            Debug.Assert((a & 0b11111100_00000000_00000000_00000000U) == 0);

            b0 = a;
            b1 = 0; b2 = 0; b3 = 0; b4 = 0;
            b5 = 0; b6 = 0; b7 = 0; b8 = 0; b9 = 0;
            magnitude = 1;
            isNormalized = true;
        }

        public UInt256_10x26(uint u0, uint u1, uint u2, uint u3, uint u4, uint u5, uint u6, uint u7)
        {
            // 26 bits uint_0 -> remaining=6 (=32-26)
            b0 = u0 & 0b00000011_11111111_11111111_11111111U;
            // 6 bits uint_0 + 20 bits uint_1 (total=26-bit) -> rem=12(=32-20)
            b1 = (u0 >> 26) | ((u1 & 0b00000000_00001111_11111111_11111111U) << 6);
            // 12 bits uint_1 + 14 bits uint_2 -> rem=18
            b2 = (u1 >> 20) | ((u2 & 0b00000000_00000000_00111111_11111111U) << 12);
            // 18 bits uint_2 + 8 bits uint_3 -> rem = 24
            b3 = (u2 >> 14) | ((u3 & 0b00000000_00000000_00000000_11111111U) << 18);
            // 24 bits uint_3 + 2 bits uint_4 -> rem=30
            b4 = (u3 >> 8) | ((u4 & 0b00000000_00000000_00000000_00000011U) << 24);
            // 26 bits uint_4 -> rem=4 (from remaining 30)
            b5 = (u4 >> 2) & 0b00000011_11111111_11111111_11111111U;
            // 4 bits uint_4 + 22 bits uint_5 -> rem=10
            b6 = (u4 >> 28) | ((u5 & 0b00000000_00111111_11111111_11111111U) << 4);
            // 10 bits uint_5 + 16 bits uint_6 -> rem=16
            b7 = (u5 >> 22) | ((u6 & 0b00000000_00000000_11111111_11111111U) << 10);
            // 16 bits uint_6 + 10 bits uint_7 -> rem=22
            b8 = (u6 >> 16) | ((u7 & 0b00000000_00000000_00000011_11111111U) << 16);
            // 22 bits uint_7
            b9 = u7 >> 10;

            magnitude = 1;
            isNormalized = true;
        }

        public UInt256_10x26(uint u0, uint u1, uint u2, uint u3, uint u4, uint u5, uint u6, uint u7, uint u8, uint u9,
                             int magnitude, bool normalized)
        {
            b0 = u0; b1 = u1; b2 = u2; b3 = u3; b4 = u4;
            b5 = u5; b6 = u6; b7 = u7; b8 = u8; b9 = u9;
            this.magnitude = magnitude;
            isNormalized = normalized;
        }

        public UInt256_10x26(ReadOnlySpan<uint> arr, int magnitude, bool normalized)
        {
            Debug.Assert(arr.Length == 10);

            b0 = arr[0]; b1 = arr[1]; b2 = arr[2]; b3 = arr[3]; b4 = arr[4];
            b5 = arr[5]; b6 = arr[6]; b7 = arr[7]; b8 = arr[8]; b9 = arr[9];
            this.magnitude = magnitude;
            isNormalized = normalized;
        }

        public UInt256_10x26(ReadOnlySpan<byte> ba, out bool isValid)
        {
            Debug.Assert(ba.Length == 32);

            // 8 + 8 + 8 + 2
            b0 = (uint)(ba[31] | (ba[30] << 8) | (ba[29] << 16) | ((ba[28] & 0b00000011) << 24));
            // 6 + 8 + 8 + 4
            b1 = (uint)((ba[28] >> 2) | (ba[27] << 6) | (ba[26] << 14) | ((ba[25] & 0b00001111) << 22));
            // 4 + 8 + 8 + 6
            b2 = (uint)((ba[25] >> 4) | (ba[24] << 4) | (ba[23] << 12) | ((ba[22] & 0b00111111) << 20));
            // 2 + 8 + 8 + 8
            b3 = (uint)((ba[22] >> 6) | (ba[21] << 2) | (ba[20] << 10) | (ba[19] << 18));
            // 8 + 8 + 8 + 2
            b4 = (uint)(ba[18] | (ba[17] << 8) | (ba[16] << 16) | ((ba[15] & 0b00000011) << 24));
            // 6 + 8 + 8 + 4
            b5 = (uint)((ba[15] >> 2) | (ba[14] << 6) | (ba[13] << 14) | ((ba[12] & 0b00001111) << 22));
            // 4 + 8 + 8 + 6
            b6 = (uint)((ba[12] >> 4) | (ba[11] << 4) | (ba[10] << 12) | ((ba[9] & 0b00111111) << 20));
            // 2 + 8 + 8 + 8
            b7 = (uint)((ba[9] >> 6) | (ba[8] << 2) | (ba[7] << 10) | (ba[6] << 18));
            // 8 + 8 + 8 + 2
            b8 = (uint)(ba[5] | (ba[4] << 8) | (ba[3] << 16) | ((ba[2] & 0b00000011) << 24));
            // 6 + 8 + 8 (last item is only 22 bits)
            b9 = (uint)((ba[2] >> 2) | (ba[1] << 6) | (ba[0] << 14));

            magnitude = 1;
            isNormalized = true;

            if (b9 == 0x3FFFFFUL && (b8 & b7 & b6 & b5 & b4 & b3 & b2) == 0x3FFFFFFUL &&
                (b1 + 0x40UL + ((b0 + 0x3D1UL) >> 26)) > 0x3FFFFFFUL)
            {
                isValid = false;
            }
            else
            {
                isValid = true;
            }
        }


        public readonly uint b0, b1, b2, b3, b4, b5, b6, b7, b8, b9;
        public readonly int magnitude;
        public readonly bool isNormalized;


        private static readonly UInt256_10x26 _zero = new(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, true);
        public static ref readonly UInt256_10x26 Zero => ref _zero;


        public readonly bool IsOdd => (b0 & 1) != 0;
        public bool IsZero => (b0 | b1 | b2 | b3 | b4 | b5 | b6 | b7 | b8 | b9) == 0;


        public void WriteToSpan(Span<byte> ba)
        {
            Debug.Assert(isNormalized);

            // Note: Last item is 22 bits, the rest are 26 bits
            // Read comments from bottom to make sense, array is set in reverse for optimization
            ba[31] = (byte)b0; // 8(0)
            ba[30] = (byte)(b0 >> 8); // 8(8)
            ba[29] = (byte)(b0 >> 16); // 8(16)
            Debug.Assert(((b0 >> 24) & 0b11111100) == 0);
            ba[28] = (byte)((b1 << 2) | (b0 >> 24)); // 6(0)+2(24)
            ba[27] = (byte)(b1 >> 6); // 8(6)
            ba[26] = (byte)(b1 >> 14); // 8(14)
            Debug.Assert(((b1 >> 22) & 0b11110000) == 0);
            ba[25] = (byte)((b2 << 4) | (b1 >> 22)); // 4(0)+4(22)
            ba[24] = (byte)(b2 >> 4); // 8(4)
            ba[23] = (byte)(b2 >> 12); // 8(12)
            Debug.Assert(((b2 >> 20) & 0b11000000) == 0);
            ba[22] = (byte)((b3 << 6) | (b2 >> 20)); // 2(0)+6(20)
            ba[21] = (byte)(b3 >> 2); // 8(2)
            ba[20] = (byte)(b3 >> 10); // 8(10)
            ba[19] = (byte)(b3 >> 18); // 8(18)
            ba[18] = (byte)b4; // 8(0)
            ba[17] = (byte)(b4 >> 8); // 8(8)
            ba[16] = (byte)(b4 >> 16); // 8(16)
            Debug.Assert(((b4 >> 24) & 0b11111100) == 0);
            ba[15] = (byte)((b5 << 2) | (b4 >> 24)); // 6(0)+2(24)
            ba[14] = (byte)(b5 >> 6); // 8(6)
            ba[13] = (byte)(b5 >> 14); // 8(14)
            Debug.Assert(((b5 >> 22) & 0b11110000) == 0);
            ba[12] = (byte)((b6 << 4) | (b5 >> 22)); // 4(0)+4(22)
            ba[11] = (byte)(b6 >> 4); // 8(4)
            ba[10] = (byte)(b6 >> 12); // 8(12)
            Debug.Assert(((b6 >> 20) & 0b11000000) == 0);
            ba[9] = (byte)((b7 << 6) | (b6 >> 20)); // 2(0)+6(20)
            ba[8] = (byte)(b7 >> 2); // 8(2)
            ba[7] = (byte)(b7 >> 10); // 8(10)
            ba[6] = (byte)(b7 >> 18); // 8(18)
            ba[5] = (byte)b8; // 8(0)
            ba[4] = (byte)(b8 >> 8); // 8(8)
            ba[3] = (byte)(b8 >> 16); // 8(16)
            Debug.Assert(((b8 >> 24) & 0b11111100) == 0);
            ba[2] = (byte)((b9 << 2) | (b8 >> 24)); // 6(0)+2(26-2=24)
            ba[1] = (byte)(b9 >> 6); // 8(14-8=6)
            ba[0] = (byte)(b9 >> 14); // Take 8 bits (rem=22-8=14)
        }


        public UInt256_10x26 Normalize()
        {
            /* Reduce t9 at the start so there will be at most a single carry from the first pass */
            uint x = b9 >> 22;
            uint t9 = b9 & 0b00000000_00111111_11111111_11111111U;

            /* The first pass ensures the magnitude is 1, ... */
            uint t0 = b0 + (x * 0x03D1U);
            uint t1 = b1 + (x << 6);
            t1 += t0 >> 26; t0 &= 0x03FFFFFFU;
            uint t2 = b2 + (t1 >> 26); t1 &= 0x03FFFFFFU;
            uint t3 = b3 + (t2 >> 26); t2 &= 0x03FFFFFFU; uint m = t2;
            uint t4 = b4 + (t3 >> 26); t3 &= 0x03FFFFFFU; m &= t3;
            uint t5 = b5 + (t4 >> 26); t4 &= 0x03FFFFFFU; m &= t4;
            uint t6 = b6 + (t5 >> 26); t5 &= 0x03FFFFFFU; m &= t5;
            uint t7 = b7 + (t6 >> 26); t6 &= 0x03FFFFFFU; m &= t6;
            uint t8 = b8 + (t7 >> 26); t7 &= 0x03FFFFFFU; m &= t7;
            t9 += (t8 >> 26); t8 &= 0x03FFFFFFU; m &= t8;

            /* ... except for a possible carry at bit 22 of t[9] (i.e. bit 256 of the field element) */
            Debug.Assert(t9 >> 23 == 0);

            /* At most a single final reduction is needed; check if the value is >= the field characteristic */
            x = (t9 >> 22) | ((t9 == 0x003FFFFFU ? 1u : 0) & (m == 0x03FFFFFFU ? 1u : 0)
                & ((t1 + 0x40U + ((t0 + 0x03D1U) >> 26)) > 0x03FFFFFFU ? 1u : 0));

            /* Apply the final reduction (for constant-time behaviour, we do it always) */
            t0 += x * 0x3D1U; t1 += (x << 6);
            t1 += (t0 >> 26);
            t0 &= 0x03FFFFFFU;
            t2 += (t1 >> 26);
            t1 &= 0x03FFFFFFU;
            t3 += (t2 >> 26);
            t2 &= 0x03FFFFFFU;
            t4 += (t3 >> 26);
            t3 &= 0x03FFFFFFU;
            t5 += (t4 >> 26);
            t4 &= 0x03FFFFFFU;
            t6 += (t5 >> 26);
            t5 &= 0x03FFFFFFU;
            t7 += (t6 >> 26);
            t6 &= 0x03FFFFFFU;
            t8 += (t7 >> 26);
            t7 &= 0x03FFFFFFU;
            t9 += (t8 >> 26);
            t8 &= 0x03FFFFFFU;

            /* If t[9] didn't carry to bit 22 already, then it should have after any final reduction */
            Debug.Assert(t9 >> 22 == x);

            /* Mask off the possible multiple of 2^256 from the final reduction */
            t9 &= 0x003FFFFFU;

            return new UInt256_10x26(t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, 1, true);
        }

        public UInt256_10x26 NormalizeWeak()
        {
            /* Reduce t9 at the start so there will be at most a single carry from the first pass */
            uint x = b9 >> 22;
            uint t9 = b9 & 0x003FFFFFU;

            /* The first pass ensures the magnitude is 1, ... */
            uint t0 = b0 + (x * 0x03D1U); uint t1 = b1 + (x << 6);
            t1 += (t0 >> 26); t0 &= 0x03FFFFFFU;
            uint t2 = b2 + (t1 >> 26); t1 &= 0x03FFFFFFU;
            uint t3 = b3 + (t2 >> 26); t2 &= 0x03FFFFFFU;
            uint t4 = b4 + (t3 >> 26); t3 &= 0x03FFFFFFU;
            uint t5 = b5 + (t4 >> 26); t4 &= 0x03FFFFFFU;
            uint t6 = b6 + (t5 >> 26); t5 &= 0x03FFFFFFU;
            uint t7 = b7 + (t6 >> 26); t6 &= 0x03FFFFFFU;
            uint t8 = b8 + (t7 >> 26); t7 &= 0x03FFFFFFU;
            t9 += (t8 >> 26); t8 &= 0x03FFFFFFU;

            /* ... except for a possible carry at bit 22 of t9 (i.e. bit 256 of the field element) */
            Debug.Assert(t9 >> 23 == 0);
            return new UInt256_10x26(t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, 1, isNormalized);
        }

        public UInt256_10x26 NormalizeVariable()
        {
            /* Reduce t9 at the start so there will be at most a single carry from the first pass */
            uint m;
            uint x = b9 >> 22;
            uint t9 = b9 & 0x03FFFFFU;

            /* The first pass ensures the magnitude is 1, ... */
            uint t0 = b0 + (x * 0x03D1U); uint t1 = b1 + (x << 6);
            t1 += (t0 >> 26); t0 &= 0x03FFFFFFU;
            uint t2 = b2 + (t1 >> 26); t1 &= 0x03FFFFFFU;
            uint t3 = b3 + (t2 >> 26); t2 &= 0x03FFFFFFU; m = t2;
            uint t4 = b4 + (t3 >> 26); t3 &= 0x03FFFFFFU; m &= t3;
            uint t5 = b5 + (t4 >> 26); t4 &= 0x03FFFFFFU; m &= t4;
            uint t6 = b6 + (t5 >> 26); t5 &= 0x03FFFFFFU; m &= t5;
            uint t7 = b7 + (t6 >> 26); t6 &= 0x03FFFFFFU; m &= t6;
            uint t8 = b8 + (t7 >> 26); t7 &= 0x03FFFFFFU; m &= t7;
            t9 += (t8 >> 26); t8 &= 0x03FFFFFFU; m &= t8;

            /* ... except for a possible carry at bit 22 of t9 (i.e. bit 256 of the field element) */
            Debug.Assert(t9 >> 23 == 0);

            /* At most a single final reduction is needed; check if the value is >= the field characteristic */
            x = (t9 >> 22) | ((t9 == 0x003FFFFFU ? 1U : 0) & (m == 0x03FFFFFFU ? 1U : 0)
                & ((t1 + 0x40U + ((t0 + 0x03D1U) >> 26)) > 0x03FFFFFFU ? 1U : 0));

            if (x != 0)
            {
                t0 += 0x03D1U; t1 += (x << 6);
                t1 += (t0 >> 26); t0 &= 0x3FFFFFFU;
                t2 += (t1 >> 26); t1 &= 0x03FFFFFFU;
                t3 += (t2 >> 26); t2 &= 0x03FFFFFFU;
                t4 += (t3 >> 26); t3 &= 0x03FFFFFFU;
                t5 += (t4 >> 26); t4 &= 0x03FFFFFFU;
                t6 += (t5 >> 26); t5 &= 0x03FFFFFFU;
                t7 += (t6 >> 26); t6 &= 0x03FFFFFFU;
                t8 += (t7 >> 26); t7 &= 0x03FFFFFFU;
                t9 += (t8 >> 26); t8 &= 0x03FFFFFFU;

                /* If t9 didn't carry to bit 22 already, then it should have after any final reduction */
                Debug.Assert(t9 >> 22 == x);

                /* Mask off the possible multiple of 2^256 from the final reduction */
                t9 &= 0x03FFFFFU;
            }

            return new UInt256_10x26(t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, 1, true);
        }

        public bool NormalizesToZero()
        {
            /* z0 tracks a possible raw value of 0, z1 tracks a possible raw value of P */
            uint z0, z1;

            /* Reduce t[9] at the start so there will be at most a single carry from the first pass */
            uint x = b9 >> 22; uint t9 = b9 & 0x003FFFFFU;

            /* The first pass ensures the magnitude is 1, ... */
            uint t0 = b0 + x * 0x3D1U; uint t1 = b1 + (x << 6);
            t1 += (t0 >> 26); t0 &= 0x03FFFFFFU; z0 = t0; z1 = t0 ^ 0x3D0U;
            uint t2 = b2 + (t1 >> 26); t1 &= 0x03FFFFFFU; z0 |= t1; z1 &= t1 ^ 0x40U;
            uint t3 = b3 + (t2 >> 26); t2 &= 0x03FFFFFFU; z0 |= t2; z1 &= t2;
            uint t4 = b4 + (t3 >> 26); t3 &= 0x03FFFFFFU; z0 |= t3; z1 &= t3;
            uint t5 = b5 + (t4 >> 26); t4 &= 0x03FFFFFFU; z0 |= t4; z1 &= t4;
            uint t6 = b6 + (t5 >> 26); t5 &= 0x03FFFFFFU; z0 |= t5; z1 &= t5;
            uint t7 = b7 + (t6 >> 26); t6 &= 0x03FFFFFFU; z0 |= t6; z1 &= t6;
            uint t8 = b8 + (t7 >> 26); t7 &= 0x03FFFFFFU; z0 |= t7; z1 &= t7;
            t9 += (t8 >> 26); t8 &= 0x03FFFFFFU; z0 |= t8; z1 &= t8;
            z0 |= t9; z1 &= t9 ^ 0x03C00000U;

            /* ... except for a possible carry at bit 22 of t[9] (i.e. bit 256 of the field element) */
            Debug.Assert(t9 >> 23 == 0);

            return ((z0 == 0 ? 1 : 0) | (z1 == 0x3FFFFFFU ? 1 : 0)) != 0;
        }

        public bool NormalizesToZeroVariable()
        {
            uint t0 = b0;
            uint t9 = b9;

            /* Reduce t9 at the start so there will be at most a single carry from the first pass */
            uint x = t9 >> 22;

            /* The first pass ensures the magnitude is 1, ... */
            t0 += x * 0x3D1U;

            /* z0 tracks a possible raw value of 0, z1 tracks a possible raw value of P */
            uint z0 = t0 & 0x3FFFFFFU;
            uint z1 = z0 ^ 0x3D0U;

            /* Fast return path should catch the majority of cases */
            if ((z0 != 0UL) & (z1 != 0x3FFFFFFUL))
            {
                return false;
            }


            uint t1 = b1;
            uint t2 = b2;
            uint t3 = b3;
            uint t4 = b4;
            uint t5 = b5;
            uint t6 = b6;
            uint t7 = b7;
            uint t8 = b8;

            t9 &= 0x03FFFFFU;
            t1 += (x << 6);

            t1 += (t0 >> 26);
            t2 += (t1 >> 26); t1 &= 0x3FFFFFFU; z0 |= t1; z1 &= t1 ^ 0x40U;
            t3 += (t2 >> 26); t2 &= 0x3FFFFFFU; z0 |= t2; z1 &= t2;
            t4 += (t3 >> 26); t3 &= 0x3FFFFFFU; z0 |= t3; z1 &= t3;
            t5 += (t4 >> 26); t4 &= 0x3FFFFFFU; z0 |= t4; z1 &= t4;
            t6 += (t5 >> 26); t5 &= 0x3FFFFFFU; z0 |= t5; z1 &= t5;
            t7 += (t6 >> 26); t6 &= 0x3FFFFFFU; z0 |= t6; z1 &= t6;
            t8 += (t7 >> 26); t7 &= 0x3FFFFFFU; z0 |= t7; z1 &= t7;
            t9 += (t8 >> 26); t8 &= 0x3FFFFFFU; z0 |= t8; z1 &= t8;
            z0 |= t9; z1 &= t9 ^ 0x3C00000U;

            /* ... except for a possible carry at bit 22 of t9 (i.e. bit 256 of the field element) */
            Debug.Assert(t9 >> 23 == 0);

            return (z0 == 0) | (z1 == 0x3FFFFFFUL);
        }


        public UInt256_10x26 Negate(int m)
        {
            Debug.Assert(magnitude <= m);
            return new UInt256_10x26(
                (uint)(0x03FFFC2FUL * 2 * (uint)(m + 1) - b0),
                (uint)(0x03FFFFBFUL * 2 * (uint)(m + 1) - b1),
                (uint)(0x03FFFFFFUL * 2 * (uint)(m + 1) - b2),
                (uint)(0x03FFFFFFUL * 2 * (uint)(m + 1) - b3),
                (uint)(0x03FFFFFFUL * 2 * (uint)(m + 1) - b4),
                (uint)(0x03FFFFFFUL * 2 * (uint)(m + 1) - b5),
                (uint)(0x03FFFFFFUL * 2 * (uint)(m + 1) - b6),
                (uint)(0x03FFFFFFUL * 2 * (uint)(m + 1) - b7),
                (uint)(0x03FFFFFFUL * 2 * (uint)(m + 1) - b8),
                (uint)(0x003FFFFFUL * 2 * (uint)(m + 1) - b9),
                m + 1, false);
        }


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void CMov(ref UInt256_10x26 r, UInt256_10x26 a, int flag)
        {
            uint mask0, mask1;
            mask0 = (uint)flag + ~(uint)0;
            mask1 = ~mask0;
            r = new UInt256_10x26(
                (r.b0 & mask0) | (a.b0 & mask1),
                (r.b1 & mask0) | (a.b1 & mask1),
                (r.b2 & mask0) | (a.b2 & mask1),
                (r.b3 & mask0) | (a.b3 & mask1),
                (r.b4 & mask0) | (a.b4 & mask1),
                (r.b5 & mask0) | (a.b5 & mask1),
                (r.b6 & mask0) | (a.b6 & mask1),
                (r.b7 & mask0) | (a.b7 & mask1),
                (r.b8 & mask0) | (a.b8 & mask1),
                (r.b9 & mask0) | (a.b9 & mask1),
                a.magnitude > r.magnitude ? a.magnitude : r.magnitude,
                r.isNormalized & a.isNormalized);
        }


        public UInt256_8x32 ToUInt256_8x32()
        {
            Debug.Assert(isNormalized);

            uint u0 = b0 | b1 << 26;
            uint u1 = b1 >> 6 | b2 << 20;
            uint u2 = b2 >> 12 | b3 << 14;
            uint u3 = b3 >> 18 | b4 << 8;
            uint u4 = b4 >> 24 | b5 << 2 | b6 << 28;
            uint u5 = b6 >> 4 | b7 << 22;
            uint u6 = b7 >> 10 | b8 << 16;
            uint u7 = b8 >> 16 | b9 << 10;
            return new UInt256_8x32(u0, u1, u2, u3, u4, u5, u6, u7);
        }


        public UInt256_10x26 Sqr() => Sqr(1);

        private UInt256_10x26 Sqr(int times)
        {
            Debug.Assert(magnitude <= 8);

            const uint M = 0x03FFFFFFU, R0 = 0x03D10U, R1 = 0x0400U;
            uint r0 = b0;
            uint r1 = b1;
            uint r2 = b2;
            uint r3 = b3;
            uint r4 = b4;
            uint r5 = b5;
            uint r6 = b6;
            uint r7 = b7;
            uint r8 = b8;
            uint r9 = b9;

            ulong c, d;
            ulong u0, u1, u2, u3, u4, u5, u6, u7, u8;
            uint t9, t0, t1, t2, t3, t4, t5, t6, t7;

            for (int i = 0; i < times; i++)
            {
                Debug.Assert(r0 >> 30 == 0);
                Debug.Assert(r1 >> 30 == 0);
                Debug.Assert(r2 >> 30 == 0);
                Debug.Assert(r3 >> 30 == 0);
                Debug.Assert(r4 >> 30 == 0);
                Debug.Assert(r5 >> 30 == 0);
                Debug.Assert(r6 >> 30 == 0);
                Debug.Assert(r7 >> 30 == 0);
                Debug.Assert(r8 >> 30 == 0);
                Debug.Assert(r9 >> 26 == 0);
                /* [... a b c] is a shorthand for ... + a<<52 + b<<26 + c<<0 mod n.
				 *  px is a shorthand for sum(n[i]*a[x-i], i=0..x).
				 *  Note that [x 0 0 0 0 0 0 0 0 0 0] = [x*R1 x*R0].
				 */

                d = (ulong)(r0 * 2) * r9
                  + (ulong)(r1 * 2) * r8
                  + (ulong)(r2 * 2) * r7
                  + (ulong)(r3 * 2) * r6
                  + (ulong)(r4 * 2) * r5;
                /* Debug.Assert(d, 64); */
                /* [d 0 0 0 0 0 0 0 0 0] = [p9 0 0 0 0 0 0 0 0 0] */
                t9 = (uint)(d & M); d >>= 26;
                Debug.Assert(t9 >> 26 == 0);
                Debug.Assert(d >> 38 == 0);
                /* [d t9 0 0 0 0 0 0 0 0 0] = [p9 0 0 0 0 0 0 0 0 0] */

                c = (ulong)r0 * r0;
                Debug.Assert(c >> 60 == 0);
                /* [d t9 0 0 0 0 0 0 0 0 c] = [p9 0 0 0 0 0 0 0 0 p0] */
                d += (ulong)(r1 * 2) * r9
                   + (ulong)(r2 * 2) * r8
                   + (ulong)(r3 * 2) * r7
                   + (ulong)(r4 * 2) * r6
                   + (ulong)r5 * r5;
                Debug.Assert(d >> 63 == 0);
                /* [d t9 0 0 0 0 0 0 0 0 c] = [p10 p9 0 0 0 0 0 0 0 0 p0] */
                u0 = d & M; d >>= 26; c += u0 * R0;
                Debug.Assert(u0 >> 26 == 0);
                Debug.Assert(d >> 37 == 0);
                Debug.Assert(c >> 61 == 0);
                /* [d u0 t9 0 0 0 0 0 0 0 0 c-u0*R0] = [p10 p9 0 0 0 0 0 0 0 0 p0] */
                t0 = (uint)(c & M); c >>= 26; c += u0 * R1;
                Debug.Assert(t0 >> 26 == 0);
                Debug.Assert(c >> 37 == 0);
                /* [d u0 t9 0 0 0 0 0 0 0 c-u0*R1 t0-u0*R0] = [p10 p9 0 0 0 0 0 0 0 0 p0] */
                /* [d 0 t9 0 0 0 0 0 0 0 c t0] = [p10 p9 0 0 0 0 0 0 0 0 p0] */

                c += (ulong)(r0 * 2) * r1;
                Debug.Assert(c >> 62 == 0);
                /* [d 0 t9 0 0 0 0 0 0 0 c t0] = [p10 p9 0 0 0 0 0 0 0 p1 p0] */
                d += (ulong)(r2 * 2) * r9
                   + (ulong)(r3 * 2) * r8
                   + (ulong)(r4 * 2) * r7
                   + (ulong)(r5 * 2) * r6;
                Debug.Assert(d >> 63 == 0);
                /* [d 0 t9 0 0 0 0 0 0 0 c t0] = [p11 p10 p9 0 0 0 0 0 0 0 p1 p0] */
                u1 = d & M; d >>= 26; c += u1 * R0;
                Debug.Assert(u1 >> 26 == 0);
                Debug.Assert(d >> 37 == 0);
                Debug.Assert(c >> 63 == 0);
                /* [d u1 0 t9 0 0 0 0 0 0 0 c-u1*R0 t0] = [p11 p10 p9 0 0 0 0 0 0 0 p1 p0] */
                t1 = (uint)(c & M); c >>= 26; c += u1 * R1;
                Debug.Assert(t1 >> 26 == 0);
                Debug.Assert(c >> 38 == 0);
                /* [d u1 0 t9 0 0 0 0 0 0 c-u1*R1 t1-u1*R0 t0] = [p11 p10 p9 0 0 0 0 0 0 0 p1 p0] */
                /* [d 0 0 t9 0 0 0 0 0 0 c t1 t0] = [p11 p10 p9 0 0 0 0 0 0 0 p1 p0] */

                c += (ulong)(r0 * 2) * r2
                   + (ulong)r1 * r1;
                Debug.Assert(c >> 62 == 0);
                /* [d 0 0 t9 0 0 0 0 0 0 c t1 t0] = [p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */
                d += (ulong)(r3 * 2) * r9
                   + (ulong)(r4 * 2) * r8
                   + (ulong)(r5 * 2) * r7
                   + (ulong)r6 * r6;
                Debug.Assert(d >> 63 == 0);
                /* [d 0 0 t9 0 0 0 0 0 0 c t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */
                u2 = d & M; d >>= 26; c += u2 * R0;
                Debug.Assert(u2 >> 26 == 0);
                Debug.Assert(d >> 37 == 0);
                Debug.Assert(c >> 63 == 0);
                /* [d u2 0 0 t9 0 0 0 0 0 0 c-u2*R0 t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */
                t2 = (uint)(c & M); c >>= 26; c += u2 * R1;
                Debug.Assert(t2 >> 26 == 0);
                Debug.Assert(c >> 38 == 0);
                /* [d u2 0 0 t9 0 0 0 0 0 c-u2*R1 t2-u2*R0 t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */
                /* [d 0 0 0 t9 0 0 0 0 0 c t2 t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */

                c += (ulong)(r0 * 2) * r3
                   + (ulong)(r1 * 2) * r2;
                Debug.Assert(c >> 63 == 0);
                /* [d 0 0 0 t9 0 0 0 0 0 c t2 t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 p3 p2 p1 p0] */
                d += (ulong)(r4 * 2) * r9
                   + (ulong)(r5 * 2) * r8
                   + (ulong)(r6 * 2) * r7;
                Debug.Assert(d >> 63 == 0);
                /* [d 0 0 0 t9 0 0 0 0 0 c t2 t1 t0] = [p13 p12 p11 p10 p9 0 0 0 0 0 p3 p2 p1 p0] */
                u3 = d & M; d >>= 26; c += u3 * R0;
                Debug.Assert(u3 >> 26 == 0);
                Debug.Assert(d >> 37 == 0);
                /* Debug.Assert(c, 64); */
                /* [d u3 0 0 0 t9 0 0 0 0 0 c-u3*R0 t2 t1 t0] = [p13 p12 p11 p10 p9 0 0 0 0 0 p3 p2 p1 p0] */
                t3 = (uint)(c & M); c >>= 26; c += u3 * R1;
                Debug.Assert(t3 >> 26 == 0);
                Debug.Assert(c >> 39 == 0);
                /* [d u3 0 0 0 t9 0 0 0 0 c-u3*R1 t3-u3*R0 t2 t1 t0] = [p13 p12 p11 p10 p9 0 0 0 0 0 p3 p2 p1 p0] */
                /* [d 0 0 0 0 t9 0 0 0 0 c t3 t2 t1 t0] = [p13 p12 p11 p10 p9 0 0 0 0 0 p3 p2 p1 p0] */

                c += (ulong)(r0 * 2) * r4
                   + (ulong)(r1 * 2) * r3
                   + (ulong)r2 * r2;
                Debug.Assert(c >> 63 == 0);
                /* [d 0 0 0 0 t9 0 0 0 0 c t3 t2 t1 t0] = [p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */
                d += (ulong)(r5 * 2) * r9
                   + (ulong)(r6 * 2) * r8
                   + (ulong)r7 * r7;
                Debug.Assert(d >> 62 == 0);
                /* [d 0 0 0 0 t9 0 0 0 0 c t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */
                u4 = d & M; d >>= 26; c += u4 * R0;
                Debug.Assert(u4 >> 26 == 0);
                Debug.Assert(d >> 36 == 0);
                /* Debug.Assert(c, 64); */
                /* [d u4 0 0 0 0 t9 0 0 0 0 c-u4*R0 t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */
                t4 = (uint)(c & M); c >>= 26; c += u4 * R1;
                Debug.Assert(t4 >> 26 == 0);
                Debug.Assert(c >> 39 == 0);
                /* [d u4 0 0 0 0 t9 0 0 0 c-u4*R1 t4-u4*R0 t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */
                /* [d 0 0 0 0 0 t9 0 0 0 c t4 t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */

                c += (ulong)(r0 * 2) * r5
                   + (ulong)(r1 * 2) * r4
                   + (ulong)(r2 * 2) * r3;
                Debug.Assert(c >> 63 == 0);
                /* [d 0 0 0 0 0 t9 0 0 0 c t4 t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */
                d += (ulong)(r6 * 2) * r9
                   + (ulong)(r7 * 2) * r8;
                Debug.Assert(d >> 62 == 0);
                /* [d 0 0 0 0 0 t9 0 0 0 c t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */
                u5 = d & M; d >>= 26; c += u5 * R0;
                Debug.Assert(u5 >> 26 == 0);
                Debug.Assert(d >> 36 == 0);
                /* Debug.Assert(c, 64); */
                /* [d u5 0 0 0 0 0 t9 0 0 0 c-u5*R0 t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */
                t5 = (uint)(c & M); c >>= 26; c += u5 * R1;
                Debug.Assert(t5 >> 26 == 0);
                Debug.Assert(c >> 39 == 0);
                /* [d u5 0 0 0 0 0 t9 0 0 c-u5*R1 t5-u5*R0 t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */
                /* [d 0 0 0 0 0 0 t9 0 0 c t5 t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */

                c += (ulong)(r0 * 2) * r6
                   + (ulong)(r1 * 2) * r5
                   + (ulong)(r2 * 2) * r4
                   + (ulong)r3 * r3;
                Debug.Assert(c >> 63 == 0);
                /* [d 0 0 0 0 0 0 t9 0 0 c t5 t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */
                d += (ulong)(r7 * 2) * r9
                   + (ulong)r8 * r8;
                Debug.Assert(d >> 61 == 0);
                /* [d 0 0 0 0 0 0 t9 0 0 c t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */
                u6 = d & M; d >>= 26; c += u6 * R0;
                Debug.Assert(u6 >> 26 == 0);
                Debug.Assert(d >> 35 == 0);
                /* Debug.Assert(c, 64); */
                /* [d u6 0 0 0 0 0 0 t9 0 0 c-u6*R0 t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */
                t6 = (uint)(c & M); c >>= 26; c += u6 * R1;
                Debug.Assert(t6 >> 26 == 0);
                Debug.Assert(c >> 39 == 0);
                /* [d u6 0 0 0 0 0 0 t9 0 c-u6*R1 t6-u6*R0 t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */
                /* [d 0 0 0 0 0 0 0 t9 0 c t6 t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */

                c += (ulong)(r0 * 2) * r7
                   + (ulong)(r1 * 2) * r6
                   + (ulong)(r2 * 2) * r5
                   + (ulong)(r3 * 2) * r4;
                /* Debug.Assert(c, 64); */
                Debug.Assert(c <= 0x8000007C00000007UL);
                /* [d 0 0 0 0 0 0 0 t9 0 c t6 t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 p7 p6 p5 p4 p3 p2 p1 p0] */
                d += (ulong)(r8 * 2) * r9;
                Debug.Assert(d >> 58 == 0);
                /* [d 0 0 0 0 0 0 0 t9 0 c t6 t5 t4 t3 t2 t1 t0] = [p17 p16 p15 p14 p13 p12 p11 p10 p9 0 p7 p6 p5 p4 p3 p2 p1 p0] */
                u7 = d & M; d >>= 26; c += u7 * R0;
                Debug.Assert(u7 >> 26 == 0);
                Debug.Assert(d >> 32 == 0);
                /* Debug.Assert(c, 64); */
                Debug.Assert(c <= 0x800001703FFFC2F7UL);
                /* [d u7 0 0 0 0 0 0 0 t9 0 c-u7*R0 t6 t5 t4 t3 t2 t1 t0] = [p17 p16 p15 p14 p13 p12 p11 p10 p9 0 p7 p6 p5 p4 p3 p2 p1 p0] */
                t7 = (uint)(c & M); c >>= 26; c += u7 * R1;
                Debug.Assert(t7 >> 26 == 0);
                Debug.Assert(c >> 38 == 0);
                /* [d u7 0 0 0 0 0 0 0 t9 c-u7*R1 t7-u7*R0 t6 t5 t4 t3 t2 t1 t0] = [p17 p16 p15 p14 p13 p12 p11 p10 p9 0 p7 p6 p5 p4 p3 p2 p1 p0] */
                /* [d 0 0 0 0 0 0 0 0 t9 c t7 t6 t5 t4 t3 t2 t1 t0] = [p17 p16 p15 p14 p13 p12 p11 p10 p9 0 p7 p6 p5 p4 p3 p2 p1 p0] */

                c += (ulong)(r0 * 2) * r8
                   + (ulong)(r1 * 2) * r7
                   + (ulong)(r2 * 2) * r6
                   + (ulong)(r3 * 2) * r5
                   + (ulong)r4 * r4;
                /* Debug.Assert(c, 64); */
                Debug.Assert(c <= 0x9000007B80000008UL);
                /* [d 0 0 0 0 0 0 0 0 t9 c t7 t6 t5 t4 t3 t2 t1 t0] = [p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
                d += (ulong)r9 * r9;
                Debug.Assert(d >> 57 == 0);
                /* [d 0 0 0 0 0 0 0 0 t9 c t7 t6 t5 t4 t3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
                u8 = d & M; d >>= 26; c += u8 * R0;
                Debug.Assert(u8 >> 26 == 0);
                Debug.Assert(d >> 31 == 0);
                /* Debug.Assert(c, 64); */
                Debug.Assert(c <= 0x9000016FBFFFC2F8UL);
                /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 t7 t6 t5 t4 t3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */

                r3 = t3;
                Debug.Assert(r3 >> 26 == 0);
                /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 t7 t6 t5 t4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
                r4 = t4;
                Debug.Assert(r4 >> 26 == 0);
                /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 t7 t6 t5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
                r5 = t5;
                Debug.Assert(r5 >> 26 == 0);
                /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 t7 t6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
                r6 = t6;
                Debug.Assert(r6 >> 26 == 0);
                /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 t7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
                r7 = t7;
                Debug.Assert(r7 >> 26 == 0);
                /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */

                r8 = (uint)(c & M); c >>= 26; c += u8 * R1;
                Debug.Assert(r8 >> 26 == 0);
                Debug.Assert(c >> 39 == 0);
                /* [d u8 0 0 0 0 0 0 0 0 t9+c-u8*R1 r8-u8*R0 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
                /* [d 0 0 0 0 0 0 0 0 0 t9+c r8 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
                c += d * R0 + t9;
                Debug.Assert(c >> 45 == 0);
                /* [d 0 0 0 0 0 0 0 0 0 c-d*R0 r8 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
                r9 = (uint)(c & (M >> 4)); c >>= 22; c += d * (R1 << 4);
                Debug.Assert(r9 >> 22 == 0);
                Debug.Assert(c >> 46 == 0);
                /* [d 0 0 0 0 0 0 0 0 r9+((c-d*R1<<4)<<22)-d*R0 r8 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
                /* [d 0 0 0 0 0 0 0 -d*R1 r9+(c<<22)-d*R0 r8 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
                /* [r9+(c<<22) r8 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */

                d = c * (R0 >> 4) + t0;
                Debug.Assert(d >> 56 == 0);
                /* [r9+(c<<22) r8 r7 r6 r5 r4 r3 t2 t1 d-c*R0>>4] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
                r0 = (uint)(d & M); d >>= 26;
                Debug.Assert(r0 >> 26 == 0);
                Debug.Assert(d >> 30 == 0);
                /* [r9+(c<<22) r8 r7 r6 r5 r4 r3 t2 t1+d r0-c*R0>>4] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
                d += c * (R1 >> 4) + t1;
                Debug.Assert(d >> 53 == 0);
                Debug.Assert(d <= 0x10000003FFFFBFUL);
                /* [r9+(c<<22) r8 r7 r6 r5 r4 r3 t2 d-c*R1>>4 r0-c*R0>>4] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
                /* [r9 r8 r7 r6 r5 r4 r3 t2 d r0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
                r1 = (uint)(d & M); d >>= 26;
                Debug.Assert(r1 >> 26 == 0);
                Debug.Assert(d >> 27 == 0);
                Debug.Assert(d <= 0x4000000UL);
                /* [r9 r8 r7 r6 r5 r4 r3 t2+d r1 r0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
                d += t2;
                Debug.Assert(d >> 27 == 0);
                /* [r9 r8 r7 r6 r5 r4 r3 d r1 r0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
                r2 = (uint)d;
                Debug.Assert(r2 >> 27 == 0);
                /* [r9 r8 r7 r6 r5 r4 r3 r2 r1 r0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
            }

            return new UInt256_10x26(r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, 1, false);
        }



        public UInt256_10x26 InverseVariable()
        {
            // TODO: complete these implementations
            return Inverse();
        }

        public UInt256_10x26 Inverse()
        {
            UInt256_10x26 x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t1;
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


        public UInt256_10x26 Multiply(uint a)
        {
            var r = new UInt256_10x26(
                b0 * a,
                b1 * a,
                b2 * a,
                b3 * a,
                b4 * a,
                b5 * a,
                b6 * a,
                b7 * a,
                b8 * a,
                b9 * a,
                magnitude * (int)a, false);
            return r;
        }
        public UInt256_10x26 Multiply(in UInt256_10x26 b)
        {
            var r = MulInner(b, 1, false);
            return r;
        }
        private UInt256_10x26 MulInner(in UInt256_10x26 b, int magnitude, bool normalized)
        {
            ulong u0, u1, u2, u3, u4, u5, u6, u7, u8;
            uint t9, t1, t0, t2, t3, t4, t5, t6, t7;
            const uint M = 0x03FFFFFFU, R0 = 0x03D10U, R1 = 0x0400U;

            Debug.Assert(b0 >> 30 == 0); Debug.Assert(b1 >> 30 == 0); Debug.Assert(b2 >> 30 == 0);
            Debug.Assert(b3 >> 30 == 0); Debug.Assert(b4 >> 30 == 0); Debug.Assert(b5 >> 30 == 0);
            Debug.Assert(b6 >> 30 == 0); Debug.Assert(b7 >> 30 == 0); Debug.Assert(b8 >> 30 == 0);
            Debug.Assert(b9 >> 26 == 0);
            Debug.Assert(b.b0 >> 30 == 0); Debug.Assert(b.b1 >> 30 == 0); Debug.Assert(b.b2 >> 30 == 0);
            Debug.Assert(b.b3 >> 30 == 0); Debug.Assert(b.b4 >> 30 == 0); Debug.Assert(b.b5 >> 30 == 0);
            Debug.Assert(b.b6 >> 30 == 0); Debug.Assert(b.b7 >> 30 == 0); Debug.Assert(b.b8 >> 30 == 0);
            Debug.Assert(b.b9 >> 26 == 0);

            /* [... a b c] is a shorthand for ... + a<<52 + b<<26 + c<<0 mod n.
			 *  px is a shorthand for sum(a.ni*b[x-i], i=0..x).
			 *  Note that [x 0 0 0 0 0 0 0 0 0 0] = [x*R1 x*R0].
			 */

            ulong d = (ulong)b0 * b.b9
                    + (ulong)b1 * b.b8
                    + (ulong)b2 * b.b7
                    + (ulong)b3 * b.b6
                    + (ulong)b4 * b.b5
                    + (ulong)b5 * b.b4
                    + (ulong)b6 * b.b3
                    + (ulong)b7 * b.b2
                    + (ulong)b8 * b.b1
                    + (ulong)b9 * b.b0;
            /* Debug.Assert(d, 64); */
            /* [d 0 0 0 0 0 0 0 0 0] = [p9 0 0 0 0 0 0 0 0 0] */
            t9 = (uint)(d & M); d >>= 26;
            Debug.Assert(t9 >> 26 == 0);
            Debug.Assert(d >> 38 == 0);
            /* [d t9 0 0 0 0 0 0 0 0 0] = [p9 0 0 0 0 0 0 0 0 0] */

            ulong c = (ulong)b0 * b.b0;
            Debug.Assert(c >> 60 == 0);
            /* [d t9 0 0 0 0 0 0 0 0 c] = [p9 0 0 0 0 0 0 0 0 p0] */
            d += (ulong)b1 * b.b9
               + (ulong)b2 * b.b8
               + (ulong)b3 * b.b7
               + (ulong)b4 * b.b6
               + (ulong)b5 * b.b5
               + (ulong)b6 * b.b4
               + (ulong)b7 * b.b3
               + (ulong)b8 * b.b2
               + (ulong)b9 * b.b1;
            Debug.Assert(d >> 63 == 0);
            /* [d t9 0 0 0 0 0 0 0 0 c] = [p10 p9 0 0 0 0 0 0 0 0 p0] */
            u0 = (uint)(d & M); d >>= 26; c += u0 * R0;
            Debug.Assert(u0 >> 26 == 0);
            Debug.Assert(d >> 37 == 0);
            Debug.Assert(c >> 61 == 0);
            /* [d u0 t9 0 0 0 0 0 0 0 0 c-u0*R0] = [p10 p9 0 0 0 0 0 0 0 0 p0] */
            t0 = (uint)(c & M); c >>= 26; c += u0 * R1;
            Debug.Assert(t0 >> 26 == 0);
            Debug.Assert(c >> 37 == 0);
            /* [d u0 t9 0 0 0 0 0 0 0 c-u0*R1 t0-u0*R0] = [p10 p9 0 0 0 0 0 0 0 0 p0] */
            /* [d 0 t9 0 0 0 0 0 0 0 c t0] = [p10 p9 0 0 0 0 0 0 0 0 p0] */

            c += (ulong)b0 * b.b1
               + (ulong)b1 * b.b0;
            Debug.Assert(c >> 62 == 0);
            /* [d 0 t9 0 0 0 0 0 0 0 c t0] = [p10 p9 0 0 0 0 0 0 0 p1 p0] */
            d += (ulong)b2 * b.b9
               + (ulong)b3 * b.b8
               + (ulong)b4 * b.b7
               + (ulong)b5 * b.b6
               + (ulong)b6 * b.b5
               + (ulong)b7 * b.b4
               + (ulong)b8 * b.b3
               + (ulong)b9 * b.b2;
            Debug.Assert(d >> 63 == 0);
            /* [d 0 t9 0 0 0 0 0 0 0 c t0] = [p11 p10 p9 0 0 0 0 0 0 0 p1 p0] */
            u1 = (uint)(d & M); d >>= 26; c += u1 * R0;
            Debug.Assert(u1 >> 26 == 0);
            Debug.Assert(d >> 37 == 0);
            Debug.Assert(c >> 63 == 0);
            /* [d u1 0 t9 0 0 0 0 0 0 0 c-u1*R0 t0] = [p11 p10 p9 0 0 0 0 0 0 0 p1 p0] */
            t1 = (uint)(c & M); c >>= 26; c += u1 * R1;
            Debug.Assert(t1 >> 26 == 0);
            Debug.Assert(c >> 38 == 0);
            /* [d u1 0 t9 0 0 0 0 0 0 c-u1*R1 t1-u1*R0 t0] = [p11 p10 p9 0 0 0 0 0 0 0 p1 p0] */
            /* [d 0 0 t9 0 0 0 0 0 0 c t1 t0] = [p11 p10 p9 0 0 0 0 0 0 0 p1 p0] */

            c += (ulong)b0 * b.b2
               + (ulong)b1 * b.b1
               + (ulong)b2 * b.b0;
            Debug.Assert(c >> 62 == 0);
            /* [d 0 0 t9 0 0 0 0 0 0 c t1 t0] = [p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */
            d += (ulong)b3 * b.b9
               + (ulong)b4 * b.b8
               + (ulong)b5 * b.b7
               + (ulong)b6 * b.b6
               + (ulong)b7 * b.b5
               + (ulong)b8 * b.b4
               + (ulong)b9 * b.b3;
            Debug.Assert(d >> 63 == 0);
            /* [d 0 0 t9 0 0 0 0 0 0 c t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */
            u2 = (uint)(d & M); d >>= 26; c += u2 * R0;
            Debug.Assert(u2 >> 26 == 0);
            Debug.Assert(d >> 37 == 0);
            Debug.Assert(c >> 63 == 0);
            /* [d u2 0 0 t9 0 0 0 0 0 0 c-u2*R0 t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */
            t2 = (uint)(c & M); c >>= 26; c += u2 * R1;
            Debug.Assert(t2 >> 26 == 0);
            Debug.Assert(c >> 38 == 0);
            /* [d u2 0 0 t9 0 0 0 0 0 c-u2*R1 t2-u2*R0 t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */
            /* [d 0 0 0 t9 0 0 0 0 0 c t2 t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 0 p2 p1 p0] */

            c += (ulong)b0 * b.b3
               + (ulong)b1 * b.b2
               + (ulong)b2 * b.b1
               + (ulong)b3 * b.b0;
            Debug.Assert(c >> 63 == 0);
            /* [d 0 0 0 t9 0 0 0 0 0 c t2 t1 t0] = [p12 p11 p10 p9 0 0 0 0 0 p3 p2 p1 p0] */
            d += (ulong)b4 * b.b9
               + (ulong)b5 * b.b8
               + (ulong)b6 * b.b7
               + (ulong)b7 * b.b6
               + (ulong)b8 * b.b5
               + (ulong)b9 * b.b4;
            Debug.Assert(d >> 63 == 0);
            /* [d 0 0 0 t9 0 0 0 0 0 c t2 t1 t0] = [p13 p12 p11 p10 p9 0 0 0 0 0 p3 p2 p1 p0] */
            u3 = (uint)(d & M); d >>= 26; c += u3 * R0;
            Debug.Assert(u3 >> 26 == 0);
            Debug.Assert(d >> 37 == 0);
            /* Debug.Assert(c>> 64); */
            /* [d u3 0 0 0 t9 0 0 0 0 0 c-u3*R0 t2 t1 t0] = [p13 p12 p11 p10 p9 0 0 0 0 0 p3 p2 p1 p0] */
            t3 = (uint)(c & M); c >>= 26; c += u3 * R1;
            Debug.Assert(t3 >> 26 == 0);
            Debug.Assert(c >> 39 == 0);
            /* [d u3 0 0 0 t9 0 0 0 0 c-u3*R1 t3-u3*R0 t2 t1 t0] = [p13 p12 p11 p10 p9 0 0 0 0 0 p3 p2 p1 p0] */
            /* [d 0 0 0 0 t9 0 0 0 0 c t3 t2 t1 t0] = [p13 p12 p11 p10 p9 0 0 0 0 0 p3 p2 p1 p0] */

            c += (ulong)b0 * b.b4
               + (ulong)b1 * b.b3
               + (ulong)b2 * b.b2
               + (ulong)b3 * b.b1
               + (ulong)b4 * b.b0;
            Debug.Assert(c >> 63 == 0);
            /* [d 0 0 0 0 t9 0 0 0 0 c t3 t2 t1 t0] = [p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */
            d += (ulong)b5 * b.b9
               + (ulong)b6 * b.b8
               + (ulong)b7 * b.b7
               + (ulong)b8 * b.b6
               + (ulong)b9 * b.b5;
            Debug.Assert(d >> 62 == 0);
            /* [d 0 0 0 0 t9 0 0 0 0 c t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */
            u4 = (uint)(d & M); d >>= 26; c += u4 * R0;
            Debug.Assert(u4 >> 26 == 0);
            Debug.Assert(d >> 36 == 0);
            /* Debug.Assert(c>> 64); */
            /* [d u4 0 0 0 0 t9 0 0 0 0 c-u4*R0 t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */
            t4 = (uint)(c & M); c >>= 26; c += u4 * R1;
            Debug.Assert(t4 >> 26 == 0);
            Debug.Assert(c >> 39 == 0);
            /* [d u4 0 0 0 0 t9 0 0 0 c-u4*R1 t4-u4*R0 t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */
            /* [d 0 0 0 0 0 t9 0 0 0 c t4 t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 0 p4 p3 p2 p1 p0] */

            c += (ulong)b0 * b.b5
               + (ulong)b1 * b.b4
               + (ulong)b2 * b.b3
               + (ulong)b3 * b.b2
               + (ulong)b4 * b.b1
               + (ulong)b5 * b.b0;
            Debug.Assert(c >> 63 == 0);
            /* [d 0 0 0 0 0 t9 0 0 0 c t4 t3 t2 t1 t0] = [p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */
            d += (ulong)b6 * b.b9
               + (ulong)b7 * b.b8
               + (ulong)b8 * b.b7
               + (ulong)b9 * b.b6;
            Debug.Assert(d >> 62 == 0);
            /* [d 0 0 0 0 0 t9 0 0 0 c t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */
            u5 = (uint)(d & M); d >>= 26; c += u5 * R0;
            Debug.Assert(u5 >> 26 == 0);
            Debug.Assert(d >> 36 == 0);
            /* Debug.Assert(c>> 64); */
            /* [d u5 0 0 0 0 0 t9 0 0 0 c-u5*R0 t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */
            t5 = (uint)(c & M); c >>= 26; c += u5 * R1;
            Debug.Assert(t5 >> 26 == 0);
            Debug.Assert(c >> 39 == 0);
            /* [d u5 0 0 0 0 0 t9 0 0 c-u5*R1 t5-u5*R0 t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */
            /* [d 0 0 0 0 0 0 t9 0 0 c t5 t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 0 p5 p4 p3 p2 p1 p0] */

            c += (ulong)b0 * b.b6
               + (ulong)b1 * b.b5
               + (ulong)b2 * b.b4
               + (ulong)b3 * b.b3
               + (ulong)b4 * b.b2
               + (ulong)b5 * b.b1
               + (ulong)b6 * b.b0;
            Debug.Assert(c >> 63 == 0);
            /* [d 0 0 0 0 0 0 t9 0 0 c t5 t4 t3 t2 t1 t0] = [p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */
            d += (ulong)b7 * b.b9
               + (ulong)b8 * b.b8
               + (ulong)b9 * b.b7;
            Debug.Assert(d >> 61 == 0);
            /* [d 0 0 0 0 0 0 t9 0 0 c t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */
            u6 = (uint)(d & M); d >>= 26; c += u6 * R0;
            Debug.Assert(u6 >> 26 == 0);
            Debug.Assert(d >> 35 == 0);
            /* Debug.Assert(c>> 64); */
            /* [d u6 0 0 0 0 0 0 t9 0 0 c-u6*R0 t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */
            t6 = (uint)(c & M); c >>= 26; c += u6 * R1;
            Debug.Assert(t6 >> 26 == 0);
            Debug.Assert(c >> 39 == 0);
            /* [d u6 0 0 0 0 0 0 t9 0 c-u6*R1 t6-u6*R0 t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */
            /* [d 0 0 0 0 0 0 0 t9 0 c t6 t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 0 p6 p5 p4 p3 p2 p1 p0] */

            c += (ulong)b0 * b.b7
               + (ulong)b1 * b.b6
               + (ulong)b2 * b.b5
               + (ulong)b3 * b.b4
               + (ulong)b4 * b.b3
               + (ulong)b5 * b.b2
               + (ulong)b6 * b.b1
               + (ulong)b7 * b.b0;
            /* Debug.Assert(c>> 64); */
            Debug.Assert(c <= 0x8000007C00000007UL);
            /* [d 0 0 0 0 0 0 0 t9 0 c t6 t5 t4 t3 t2 t1 t0] = [p16 p15 p14 p13 p12 p11 p10 p9 0 p7 p6 p5 p4 p3 p2 p1 p0] */
            d += (ulong)b8 * b.b9
               + (ulong)b9 * b.b8;
            Debug.Assert(d >> 58 == 0);
            /* [d 0 0 0 0 0 0 0 t9 0 c t6 t5 t4 t3 t2 t1 t0] = [p17 p16 p15 p14 p13 p12 p11 p10 p9 0 p7 p6 p5 p4 p3 p2 p1 p0] */
            u7 = (uint)(d & M); d >>= 26; c += u7 * R0;
            Debug.Assert(u7 >> 26 == 0);
            Debug.Assert(d >> 32 == 0);
            /* Debug.Assert(c>> 64); */
            Debug.Assert(c <= 0x800001703FFFC2F7UL);
            /* [d u7 0 0 0 0 0 0 0 t9 0 c-u7*R0 t6 t5 t4 t3 t2 t1 t0] = [p17 p16 p15 p14 p13 p12 p11 p10 p9 0 p7 p6 p5 p4 p3 p2 p1 p0] */
            t7 = (uint)(c & M); c >>= 26; c += u7 * R1;
            Debug.Assert(t7 >> 26 == 0);
            Debug.Assert(c >> 38 == 0);
            /* [d u7 0 0 0 0 0 0 0 t9 c-u7*R1 t7-u7*R0 t6 t5 t4 t3 t2 t1 t0] = [p17 p16 p15 p14 p13 p12 p11 p10 p9 0 p7 p6 p5 p4 p3 p2 p1 p0] */
            /* [d 0 0 0 0 0 0 0 0 t9 c t7 t6 t5 t4 t3 t2 t1 t0] = [p17 p16 p15 p14 p13 p12 p11 p10 p9 0 p7 p6 p5 p4 p3 p2 p1 p0] */

            c += (ulong)b0 * b.b8
               + (ulong)b1 * b.b7
               + (ulong)b2 * b.b6
               + (ulong)b3 * b.b5
               + (ulong)b4 * b.b4
               + (ulong)b5 * b.b3
               + (ulong)b6 * b.b2
               + (ulong)b7 * b.b1
               + (ulong)b8 * b.b0;
            /* Debug.Assert(c>> 64); */
            Debug.Assert(c <= 0x9000007B80000008UL);
            /* [d 0 0 0 0 0 0 0 0 t9 c t7 t6 t5 t4 t3 t2 t1 t0] = [p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
            d += (ulong)b9 * b.b9;
            Debug.Assert(d >> 57 == 0);
            /* [d 0 0 0 0 0 0 0 0 t9 c t7 t6 t5 t4 t3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
            u8 = (uint)(d & M); d >>= 26; c += u8 * R0;
            Debug.Assert(u8 >> 26 == 0);
            Debug.Assert(d >> 31 == 0);
            /* Debug.Assert(c>> 64); */
            Debug.Assert(c <= 0x9000016FBFFFC2F8UL);
            /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 t7 t6 t5 t4 t3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */

            uint r3 = t3;
            Debug.Assert(r3 >> 26 == 0);
            /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 t7 t6 t5 t4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
            uint r4 = t4;
            Debug.Assert(r4 >> 26 == 0);
            /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 t7 t6 t5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
            uint r5 = t5;
            Debug.Assert(r5 >> 26 == 0);
            /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 t7 t6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
            uint r6 = t6;
            Debug.Assert(r6 >> 26 == 0);
            /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 t7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
            uint r7 = t7;
            Debug.Assert(r7 >> 26 == 0);
            /* [d u8 0 0 0 0 0 0 0 0 t9 c-u8*R0 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */

            uint r8 = (uint)(c & M); c >>= 26; c += u8 * R1;
            Debug.Assert(r8 >> 26 == 0);
            Debug.Assert(c >> 39 == 0);
            /* [d u8 0 0 0 0 0 0 0 0 t9+c-u8*R1 r8-u8*R0 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
            /* [d 0 0 0 0 0 0 0 0 0 t9+c r8 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
            c += d * R0 + t9;
            Debug.Assert(c >> 45 == 0);
            /* [d 0 0 0 0 0 0 0 0 0 c-d*R0 r8 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
            uint r9 = (uint)(c & (M >> 4)); c >>= 22; c += d * (R1 << 4);
            Debug.Assert(r9 >> 22 == 0);
            Debug.Assert(c >> 46 == 0);
            /* [d 0 0 0 0 0 0 0 0 r9+((c-d*R1<<4)<<22)-d*R0 r8 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
            /* [d 0 0 0 0 0 0 0 -d*R1 r9+(c<<22)-d*R0 r8 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
            /* [r9+(c<<22) r8 r7 r6 r5 r4 r3 t2 t1 t0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */

            d = c * (R0 >> 4) + t0;
            Debug.Assert(d >> 56 == 0);
            /* [r9+(c<<22) r8 r7 r6 r5 r4 r3 t2 t1 d-c*R0>>4] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
            uint r0 = (uint)(d & M); d >>= 26;
            Debug.Assert(r0 >> 26 == 0);
            Debug.Assert(d >> 30 == 0);
            /* [r9+(c<<22) r8 r7 r6 r5 r4 r3 t2 t1+d r0-c*R0>>4] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
            d += c * (R1 >> 4) + t1;
            Debug.Assert(d >> 53 == 0);
            Debug.Assert(d <= 0x10000003FFFFBFUL);
            /* [r9+(c<<22) r8 r7 r6 r5 r4 r3 t2 d-c*R1>>4 r0-c*R0>>4] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
            /* [r9 r8 r7 r6 r5 r4 r3 t2 d r0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
            uint r1 = (uint)(d & M); d >>= 26;
            Debug.Assert(r1 >> 26 == 0);
            Debug.Assert(d >> 27 == 0);
            Debug.Assert(d <= 0x4000000UL);
            /* [r9 r8 r7 r6 r5 r4 r3 t2+d r1 r0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
            d += t2;
            Debug.Assert(d >> 27 == 0);
            /* [r9 r8 r7 r6 r5 r4 r3 d r1 r0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
            uint r2 = (uint)d;
            Debug.Assert(r2 >> 27 == 0);
            /* [r9 r8 r7 r6 r5 r4 r3 r2 r1 r0] = [p18 p17 p16 p15 p14 p13 p12 p11 p10 p9 p8 p7 p6 p5 p4 p3 p2 p1 p0] */
            return new UInt256_10x26(r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, magnitude, normalized);
        }


        public bool Sqrt(out UInt256_10x26 result)
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
            UInt256_10x26 x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t1;

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


        public readonly UInt256_10x26 Add(in UInt256_10x26 a)
        {
            var r = new UInt256_10x26(
                b0 + a.b0,
                b1 + a.b1,
                b2 + a.b2,
                b3 + a.b3,
                b4 + a.b4,
                b5 + a.b5,
                b6 + a.b6,
                b7 + a.b7,
                b8 + a.b8,
                b9 + a.b9,
                magnitude + a.magnitude,
                false);
            return r;
        }


        public static UInt256_10x26 operator +(in UInt256_10x26 a, in UInt256_10x26 b) => a.Add(b);
        public static UInt256_10x26 operator *(in UInt256_10x26 a, uint b) => a.Multiply(b);
        public static UInt256_10x26 operator *(in UInt256_10x26 a, in UInt256_10x26 b) => a.Multiply(b);


        public bool Equals(UInt256_10x26 b)
        {
            var na = Negate(1);
            na += b;
            return na.NormalizesToZero();
        }
    }
}
