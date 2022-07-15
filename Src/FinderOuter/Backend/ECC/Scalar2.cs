// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace FinderOuter.Backend.ECC
{
    public readonly struct Scalar2
    {
        public Scalar2(ulong u0, ulong u1, ulong u2, ulong u3)
        {
            b0 = u0; b1 = u1; b2 = u2; b3 = u3;
        }

        /// <param name="hPt"><see cref="Cryptography.Hashing.Sha256Fo.hashState"/> pointer</param>
        public unsafe Scalar2(uint* hPt, out int overflow)
        {
            b3 = hPt[0] | (ulong)hPt[1] << 32;
            b2 = hPt[2] | (ulong)hPt[3] << 32;
            b1 = hPt[4] | (ulong)hPt[5] << 32;
            b0 = hPt[6] | (ulong)hPt[7] << 32;

            overflow = GetOverflow();
        }

        /// <param name="hPt"><see cref="Cryptography.Hashing.Sha512Fo.hashState"/> pointer</param>
        public unsafe Scalar2(ulong* hPt, out int overflow)
        {
            b3 = hPt[0];
            b2 = hPt[1];
            b1 = hPt[2];
            b0 = hPt[3];

            overflow = GetOverflow();
        }

        public unsafe Scalar2(byte* pt, out int overflow)
        {
            b0 = pt[31] | (ulong)pt[30] << 8 | (ulong)pt[29] << 16 | (ulong)pt[28] << 24 |
                 (ulong)pt[27] << 32 | (ulong)pt[26] << 40 | (ulong)pt[25] << 48 | (ulong)pt[24] << 56;
            b1 = pt[23] | (ulong)pt[22] << 8 | (ulong)pt[21] << 16 | (ulong)pt[20] << 24 |
                 (ulong)pt[19] << 32 | (ulong)pt[18] << 40 | (ulong)pt[17] << 48 | (ulong)pt[16] << 56;
            b2 = pt[15] | (ulong)pt[14] << 8 | (ulong)pt[13] << 16 | (ulong)pt[12] << 24 |
                 (ulong)pt[11] << 32 | (ulong)pt[10] << 40 | (ulong)pt[9] << 48 | (ulong)pt[8] << 56;
            b3 = pt[7] | (ulong)pt[6] << 8 | (ulong)pt[5] << 16 | (ulong)pt[4] << 24 |
                 (ulong)pt[3] << 32 | (ulong)pt[2] << 40 | (ulong)pt[1] << 48 | (ulong)pt[0] << 56;

            overflow = GetOverflow();

            Debug.Assert(overflow == 0 || overflow == 1);

            UInt128 t = (UInt128)b0 + (UInt128)overflow * NC0;
            b0 = t.b0; t = new(t.b1, 0); // t >>= 64;
            t += (UInt128)b1 + (UInt128)overflow * NC1;
            b1 = t.b0; t = new(t.b1, 0); // t >>= 64;
            t += (UInt128)b2 + (UInt128)overflow * NC2;
            b2 = t.b0; t = new(t.b1, 0); // t >>= 64;
            t += b3;
            b3 = t.b0;

            Debug.Assert((overflow == 1 && t.b1 == 1) || (overflow == 0 && t.b1 == 0));
            Debug.Assert(GetOverflow() == 0);
        }

        public Scalar2(ReadOnlySpan<byte> data, out int overflow)
        {
            if (data.Length != 32)
                throw new ArgumentOutOfRangeException(nameof(data));

            b0 = data[31] | (ulong)data[30] << 8 | (ulong)data[29] << 16 | (ulong)data[28] << 24 |
                 (ulong)data[27] << 32 | (ulong)data[26] << 40 | (ulong)data[25] << 48 | (ulong)data[24] << 56;
            b1 = data[23] | (ulong)data[22] << 8 | (ulong)data[21] << 16 | (ulong)data[20] << 24 |
                 (ulong)data[19] << 32 | (ulong)data[18] << 40 | (ulong)data[17] << 48 | (ulong)data[16] << 56;
            b2 = data[15] | (ulong)data[14] << 8 | (ulong)data[13] << 16 | (ulong)data[12] << 24 |
                 (ulong)data[11] << 32 | (ulong)data[10] << 40 | (ulong)data[9] << 48 | (ulong)data[8] << 56;
            b3 = data[7] | (ulong)data[6] << 8 | (ulong)data[5] << 16 | (ulong)data[4] << 24 |
                 (ulong)data[3] << 32 | (ulong)data[2] << 40 | (ulong)data[1] << 48 | (ulong)data[0] << 56;

            overflow = GetOverflow();

            Debug.Assert(overflow == 0 || overflow == 1);

            UInt128 t = (UInt128)b0 + (UInt128)overflow * NC0;
            b0 = t.b0; t = new(t.b1, 0); // t >>= 64;
            t += (UInt128)b1 + (UInt128)overflow * NC1;
            b1 = t.b0; t = new(t.b1, 0); // t >>= 64;
            t += (UInt128)b2 + (UInt128)overflow * NC2;
            b2 = t.b0; t = new(t.b1, 0); // t >>= 64;
            t += b3;
            b3 = t.b0;

            Debug.Assert((overflow == 1 && t.b1 == 1) || (overflow == 0 && t.b1 == 0));
            Debug.Assert(GetOverflow() == 0);
        }

        public Scalar2(Span<ulong> d)
        {
            b0 = d[0];
            b1 = d[1];
            b2 = d[2];
            b3 = d[3];

            Debug.Assert(GetOverflow() == 0);
        }


        internal readonly ulong b0, b1, b2, b3;

        // Secp256k1 curve order
        public const ulong N0 = 0xBFD25E8CD0364141U;
        public const ulong N1 = 0xBAAEDCE6AF48A03BU;
        public const ulong N2 = 0xFFFFFFFFFFFFFFFEU;
        public const ulong N3 = 0xFFFFFFFFFFFFFFFFU;

        // 2^256 - N
        // Since overflow will be less than 2N the result of X % N is X - N
        // X - N ≡ Z (mod N) => X + (2^256 - N) ≡ Z + 2^256 (mod N)
        // 250 ≡ 9 (mod 241) => 250 - 241 ≡ 250 + 256 - 241 ≡ 265 ≡ 265 - 256 ≡ 9 (mod 241)
        //                   => 265=0x0109 256=0x0100 => 265-256: get rid of highest bit => 0x0109≡0x09
        public const ulong NC0 = ~N0 + 1;
        public const ulong NC1 = ~N1;
        public const ulong NC2 = 1;

        // N/2
        public const ulong NH0 = 0xDFE92F46681B20A0U;
        public const ulong NH1 = 0x5D576E7357A4501DU;
        public const ulong NH2 = 0xFFFFFFFFFFFFFFFFU;
        public const ulong NH3 = 0x7FFFFFFFFFFFFFFFU;

        public bool IsZero => (b0 | b1 | b2 | b3) == 0;

        private int GetOverflow()
        {
            int yes = 0;
            int no = 0;
            no |= (b3 < N3 ? 1 : 0);
            no |= (b2 < N2 ? 1 : 0);
            yes |= (b2 > N2 ? 1 : 0) & ~no;
            no |= (b1 < N1 ? 1 : 0);
            yes |= (b1 > N1 ? 1 : 0) & ~no;
            yes |= (b0 >= N0 ? 1 : 0) & ~no;
            return yes;
        }

        internal readonly ulong GetBits(int offset, int count)
        {
            Debug.Assert(offset >= 0);
            Debug.Assert(count >= 0);
            Debug.Assert((offset + count - 1) >> 6 == offset >> 6);
            return (GetChunk(offset >> 6) >> (offset & 0x3F)) & ((1UL << count) - 1);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private ulong GetChunk(int index)
        {
            Debug.Assert(index >= 0 && index <= 3);
#pragma warning disable CS8509 // The switch expression does not handle all possible values of its input type (it is not exhaustive).
            return index switch
#pragma warning restore CS8509
            {
                0 => b0,
                1 => b1,
                2 => b2,
                3 => b3,
            };
        }



        // All the following methods and operators are useful for testing and not much else
        public static bool operator ==(Scalar2 left, Scalar2 right) => left.Equals(right);
        public static bool operator !=(Scalar2 left, Scalar2 right) => !left.Equals(right);
        public bool Equals(in Scalar2 other) => b0 == other.b0 && b1 == other.b1 && b2 == other.b2 && b3 == other.b3;
        public override bool Equals(object obj) => obj is Scalar2 other && Equals(in other);
        public override int GetHashCode() => HashCode.Combine(b0, b1, b2, b3);
    }
}
