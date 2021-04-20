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

        public Scalar(Span<byte> data, out int overflow)
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

        internal readonly uint GetBits(int offset, int count)
        {
            Debug.Assert(offset >= 0);
            Debug.Assert(count >= 0);
            Debug.Assert((offset + count - 1) >> 5 == offset >> 5);
            return (uint)((GetChunk(offset >> 5) >> (offset & 0x1F)) & ((1 << count) - 1));
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



        // All the following methods and operators are useful for testing and not much else
        public static bool operator ==(Scalar left, Scalar right) => left.Equals(right);
        public static bool operator !=(Scalar left, Scalar right) => !left.Equals(right);
        public bool Equals(in Scalar other) => b0 == other.b0 && b1 == other.b1 && b2 == other.b2 && b3 == other.b3 &&
                                               b4 == other.b4 && b5 == other.b5 && b6 == other.b6 && b7 == other.b7;
        public override bool Equals(object obj) => obj is Scalar other && Equals(in other);
        public override int GetHashCode() => HashCode.Combine(b0, b1, b2, b3, b4, b5, b6, b7);
    }
}
