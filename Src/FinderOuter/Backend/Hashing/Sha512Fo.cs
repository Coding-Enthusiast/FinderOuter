// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System;
using System.Runtime.CompilerServices;

namespace FinderOuter.Backend.Hashing
{
    /// <summary>
    /// Implementation of 512-bit Secure Hash Algorithm (SHA) based on RFC-6234
    /// <para/> https://tools.ietf.org/html/rfc6234
    /// </summary>
    public static class Sha512Fo
    {
        /// <summary>
        /// Size of the hash result in bytes (=64 bytes).
        /// </summary>
        public const int HashByteSize = 64;

        /// <summary>
        /// Size of the blocks used in each round (=128 bytes).
        /// </summary>
        public const int BlockByteSize = 128;

        public const int HashStateSize = 8;
        public const int WorkingVectorSize = 80;
        /// <summary>
        /// Size of UInt32[] buffer = 88
        /// </summary>
        public const int UBufferSize = HashStateSize + WorkingVectorSize;

        private static readonly ulong[] Ks =
        {
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
            0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
            0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
            0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
            0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
            0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
            0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
            0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
            0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
        };


        public static unsafe byte[] ComputeHash(Span<byte> data)
        {
            ulong* pt = stackalloc ulong[UBufferSize];
            Init(pt);
            fixed (byte* dPt = data)
            {
                CompressData(dPt, data.Length, data.Length, pt, pt + HashStateSize);
            }
            return GetBytes(pt);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static unsafe void Init(ulong* hPt)
        {
            hPt[0] = 0x6a09e667f3bcc908;
            hPt[1] = 0xbb67ae8584caa73b;
            hPt[2] = 0x3c6ef372fe94f82b;
            hPt[3] = 0xa54ff53a5f1d36f1;
            hPt[4] = 0x510e527fade682d1;
            hPt[5] = 0x9b05688c2b3e6c1f;
            hPt[6] = 0x1f83d9abfb41bd6b;
            hPt[7] = 0x5be0cd19137e2179;
        }

        /// <summary>
        /// Sets initial HashState values to the result of computing SHA512("Bitcoin seed" ^ 0x36) used in
        /// HMACSHA512 in BIP-32 constructor while instantiating from an etnropy source
        /// </summary>
        /// <param name="hPt"></param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static unsafe void Init_InnerPad_Bitcoinseed(ulong* hPt)
        {
            hPt[0] = 0x2e2af459060c1873UL;
            hPt[1] = 0x7894b868dc88433aUL;
            hPt[2] = 0xdd1a797ef1a1933aUL;
            hPt[3] = 0xe6486d04fcb412a7UL;
            hPt[4] = 0xfbcc67b9a396caa0UL;
            hPt[5] = 0xa2970b146f49b65eUL;
            hPt[6] = 0xfdf1daabc66f6248UL;
            hPt[7] = 0x2ff99c812ada6dc3UL;
        }

        /// <summary>
        /// Sets initial HashState values to the result of computing SHA512("Bitcoin seed" ^ 0x5c) used in
        /// HMACSHA512 in BIP-32 constructor while instantiating from an etnropy source
        /// </summary>
        /// <param name="hPt"></param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static unsafe void Init_OuterPad_Bitcoinseed(ulong* hPt)
        {
            hPt[0] = 0xbbd27bac212e9dbdUL;
            hPt[1] = 0xdd0bc55e7e4037c1UL;
            hPt[2] = 0xdfdd3d6890bd6424UL;
            hPt[3] = 0x2902de663032b34cUL;
            hPt[4] = 0xa30f8aa6f67899fcUL;
            hPt[5] = 0x69a566c30f88378fUL;
            hPt[6] = 0x0500247985ecb694UL;
            hPt[7] = 0xf6d70307c6b2d337UL;
        }


        /// <summary>
        /// Sets initial HashState values to the result of computing SHA512("Seed version" ^ 0x36) used in
        /// HMACSHA512 in Electrum mnemonic checksum verification.
        /// </summary>
        /// <param name="hPt"></param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static unsafe void Init_InnerPad_SeedVersion(ulong* hPt)
        {
            hPt[0] = 0x1197a4930cdcdf99UL;
            hPt[1] = 0x546bbb7463b748ecUL;
            hPt[2] = 0x54b710c32be37324UL;
            hPt[3] = 0xb1c66f4992fba20bUL;
            hPt[4] = 0x2636810bfe5bb0acUL;
            hPt[5] = 0xa303a6e0e2f532b7UL;
            hPt[6] = 0x6f8de49628412246UL;
            hPt[7] = 0x12a1440d199e4378UL;
        }

        /// <summary>
        /// Sets initial HashState values to the result of computing SHA512("Seed version" ^ 0x5c) used in
        /// HMACSHA512 in Electrum mnemonic checksum verification.
        /// </summary>
        /// <param name="hPt"></param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static unsafe void Init_OuterPad_SeedVersion(ulong* hPt)
        {
            hPt[0] = 0x81dbfcd8ccef4fd9UL;
            hPt[1] = 0xe6d72480c338f2f2UL;
            hPt[2] = 0x83986704cc866344UL;
            hPt[3] = 0x3c6605131ca79477UL;
            hPt[4] = 0xb9dceafa29032584UL;
            hPt[5] = 0xded96c7785b367d5UL;
            hPt[6] = 0x393a2aff50ec45ebUL;
            hPt[7] = 0x2e7b225f70227970UL;
        }


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static unsafe byte[] GetBytes(ulong* hPt)
        {
            return new byte[HashByteSize]
            {
                (byte)(hPt[0] >> 56), (byte)(hPt[0] >> 48), (byte)(hPt[0] >> 40), (byte)(hPt[0] >> 32),
                (byte)(hPt[0] >> 24), (byte)(hPt[0] >> 16), (byte)(hPt[0] >> 8), (byte)hPt[0],

                (byte)(hPt[1] >> 56), (byte)(hPt[1] >> 48), (byte)(hPt[1] >> 40), (byte)(hPt[1] >> 32),
                (byte)(hPt[1] >> 24), (byte)(hPt[1] >> 16), (byte)(hPt[1] >> 8), (byte)hPt[1],

                (byte)(hPt[2] >> 56), (byte)(hPt[2] >> 48), (byte)(hPt[2] >> 40), (byte)(hPt[2] >> 32),
                (byte)(hPt[2] >> 24), (byte)(hPt[2] >> 16), (byte)(hPt[2] >> 8), (byte)hPt[2],

                (byte)(hPt[3] >> 56), (byte)(hPt[3] >> 48), (byte)(hPt[3] >> 40), (byte)(hPt[3] >> 32),
                (byte)(hPt[3] >> 24), (byte)(hPt[3] >> 16), (byte)(hPt[3] >> 8), (byte)hPt[3],

                (byte)(hPt[4] >> 56), (byte)(hPt[4] >> 48), (byte)(hPt[4] >> 40), (byte)(hPt[4] >> 32),
                (byte)(hPt[4] >> 24), (byte)(hPt[4] >> 16), (byte)(hPt[4] >> 8), (byte)hPt[4],

                (byte)(hPt[5] >> 56), (byte)(hPt[5] >> 48), (byte)(hPt[5] >> 40), (byte)(hPt[5] >> 32),
                (byte)(hPt[5] >> 24), (byte)(hPt[5] >> 16), (byte)(hPt[5] >> 8), (byte)hPt[5],

                (byte)(hPt[6] >> 56), (byte)(hPt[6] >> 48), (byte)(hPt[6] >> 40), (byte)(hPt[6] >> 32),
                (byte)(hPt[6] >> 24), (byte)(hPt[6] >> 16), (byte)(hPt[6] >> 8), (byte)hPt[6],

                (byte)(hPt[7] >> 56), (byte)(hPt[7] >> 48), (byte)(hPt[7] >> 40), (byte)(hPt[7] >> 32),
                (byte)(hPt[7] >> 24), (byte)(hPt[7] >> 16), (byte)(hPt[7] >> 8), (byte)hPt[7]
            };
        }

        /// <summary>
        /// Returns first half of the hash result (used in BIP-32)
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <returns></returns>
        public static unsafe byte[] GetFirst32Bytes(ulong* hPt)
        {
            return new byte[32]
            {
                (byte)(hPt[0] >> 56), (byte)(hPt[0] >> 48), (byte)(hPt[0] >> 40), (byte)(hPt[0] >> 32),
                (byte)(hPt[0] >> 24), (byte)(hPt[0] >> 16), (byte)(hPt[0] >> 8), (byte)hPt[0],

                (byte)(hPt[1] >> 56), (byte)(hPt[1] >> 48), (byte)(hPt[1] >> 40), (byte)(hPt[1] >> 32),
                (byte)(hPt[1] >> 24), (byte)(hPt[1] >> 16), (byte)(hPt[1] >> 8), (byte)hPt[1],

                (byte)(hPt[2] >> 56), (byte)(hPt[2] >> 48), (byte)(hPt[2] >> 40), (byte)(hPt[2] >> 32),
                (byte)(hPt[2] >> 24), (byte)(hPt[2] >> 16), (byte)(hPt[2] >> 8), (byte)hPt[2],

                (byte)(hPt[3] >> 56), (byte)(hPt[3] >> 48), (byte)(hPt[3] >> 40), (byte)(hPt[3] >> 32),
                (byte)(hPt[3] >> 24), (byte)(hPt[3] >> 16), (byte)(hPt[3] >> 8), (byte)hPt[3],
            };
        }

        /// <summary>
        /// Returns second half of the hash result (used in BIP-32)
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <returns></returns>
        public static unsafe byte[] GetSecond32Bytes(ulong* hPt)
        {
            return new byte[32]
            {
                (byte)(hPt[4] >> 56), (byte)(hPt[4] >> 48), (byte)(hPt[4] >> 40), (byte)(hPt[4] >> 32),
                (byte)(hPt[4] >> 24), (byte)(hPt[4] >> 16), (byte)(hPt[4] >> 8), (byte)hPt[4],

                (byte)(hPt[5] >> 56), (byte)(hPt[5] >> 48), (byte)(hPt[5] >> 40), (byte)(hPt[5] >> 32),
                (byte)(hPt[5] >> 24), (byte)(hPt[5] >> 16), (byte)(hPt[5] >> 8), (byte)hPt[5],

                (byte)(hPt[6] >> 56), (byte)(hPt[6] >> 48), (byte)(hPt[6] >> 40), (byte)(hPt[6] >> 32),
                (byte)(hPt[6] >> 24), (byte)(hPt[6] >> 16), (byte)(hPt[6] >> 8), (byte)hPt[6],

                (byte)(hPt[7] >> 56), (byte)(hPt[7] >> 48), (byte)(hPt[7] >> 40), (byte)(hPt[7] >> 32),
                (byte)(hPt[7] >> 24), (byte)(hPt[7] >> 16), (byte)(hPt[7] >> 8), (byte)hPt[7],
            };
        }


        public static unsafe void CompressData(byte* dPt, int dataLen, int totalLen, ulong* hPt, ulong* wPt)
        {
            Span<byte> finalBlock = new byte[128];

            fixed (byte* fPt = &finalBlock[0])
            {
                int dIndex = 0;
                while (dataLen >= BlockByteSize)
                {
                    for (int i = 0; i < 16; i++, dIndex += 8)
                    {
                        wPt[i] =
                                ((ulong)dPt[dIndex] << 56) |
                                ((ulong)dPt[dIndex + 1] << 48) |
                                ((ulong)dPt[dIndex + 2] << 40) |
                                ((ulong)dPt[dIndex + 3] << 32) |
                                ((ulong)dPt[dIndex + 4] << 24) |
                                ((ulong)dPt[dIndex + 5] << 16) |
                                ((ulong)dPt[dIndex + 6] << 8) |
                                dPt[dIndex + 7];
                    }

                    SetW(wPt);
                    CompressBlockWithWSet(hPt, wPt);

                    dataLen -= BlockByteSize;
                }

                // Copy the reamaining bytes into a blockSize length buffer so that we can loop through it easily:
                Buffer.MemoryCopy(dPt + dIndex, fPt, finalBlock.Length, dataLen);

                // Append 1 bit followed by zeros. Since we only work with bytes, this is 1 whole byte
                fPt[dataLen] = 0b1000_0000;

                if (dataLen >= 112) // blockSize - pad2.Len = 128 - 16
                {
                    // This means we have an additional block to compress, which we do it here:

                    for (int i = 0, j = 0; i < 16; i++, j += 8)
                    {
                        wPt[i] =
                            ((ulong)fPt[j] << 56) |
                            ((ulong)fPt[j + 1] << 48) |
                            ((ulong)fPt[j + 2] << 40) |
                            ((ulong)fPt[j + 3] << 32) |
                            ((ulong)fPt[j + 4] << 24) |
                            ((ulong)fPt[j + 5] << 16) |
                            ((ulong)fPt[j + 6] << 8) |
                            fPt[j + 7];
                    }

                    SetW(wPt);
                    CompressBlockWithWSet(hPt, wPt);

                    finalBlock.Clear();
                }

                // Add length in bits as the last 16 bytes of final block in big-endian order
                // See MessageLengthTest in SHA256 Test project to understand what the following shifts are
                fPt[127] = (byte)(totalLen << 3);
                fPt[126] = (byte)(totalLen >> 5);
                fPt[125] = (byte)(totalLen >> 13);
                fPt[124] = (byte)(totalLen >> 21);
                fPt[123] = (byte)(totalLen >> 29);
                // The remainig 11 bytes are always zero
                // The remaining 112 bytes are already set

                for (int i = 0, j = 0; i < 16; i++, j += 8)
                {
                    wPt[i] =
                            ((ulong)fPt[j] << 56) |
                            ((ulong)fPt[j + 1] << 48) |
                            ((ulong)fPt[j + 2] << 40) |
                            ((ulong)fPt[j + 3] << 32) |
                            ((ulong)fPt[j + 4] << 24) |
                            ((ulong)fPt[j + 5] << 16) |
                            ((ulong)fPt[j + 6] << 8) |
                            fPt[j + 7];
                }

                SetW(wPt);
                CompressBlockWithWSet(hPt, wPt);
            }
        }


        /// <summary>
        /// Compresses a single block (useful for data length smaller than 112 that only need 1 SHA512 block)
        /// </summary>
        public static unsafe void CompressSingleBlock(byte* dPt, ulong* hPt, ulong* wPt)
        {
            for (int i = 0, j = 0; i < 16; i++, j += 8)
            {
                wPt[i] = ((ulong)dPt[j] << 56) | ((ulong)dPt[j + 1] << 48) | ((ulong)dPt[j + 2] << 40) | ((ulong)dPt[j + 3] << 32) |
                         ((ulong)dPt[j + 4] << 24) | ((ulong)dPt[j + 5] << 16) | ((ulong)dPt[j + 6] << 8) | dPt[j + 7];
            }

            SetW(wPt);
            CompressBlockWithWSet(hPt, wPt);
        }

        /// <summary>
        /// Computes _single_ SHA512 hash for the second block of
        /// (data.Length == 165) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public static unsafe void Compress165SecondBlock(ulong* hPt, ulong* wPt)
        {
            // w4 = extra value | 0b00000000_00000000_00000000_00000000_00000000_10000000_00000000_00000000UL 
            // w5 to w14 = 0
            // w15 = 1320
            wPt[16] = SSIG0(wPt[1]) + wPt[0];
            wPt[17] = 46443371157268820 + SSIG0(wPt[2]) + wPt[1];
            wPt[18] = SSIG1(wPt[16]) + SSIG0(wPt[3]) + wPt[2];
            wPt[19] = SSIG1(wPt[17]) + SSIG0(wPt[4]) + wPt[3];
            wPt[20] = SSIG1(wPt[18]) + wPt[4];
            wPt[21] = SSIG1(wPt[19]);
            wPt[22] = SSIG1(wPt[20]) + 1320;
            wPt[23] = SSIG1(wPt[21]) + wPt[16];
            wPt[24] = SSIG1(wPt[22]) + wPt[17];
            wPt[25] = SSIG1(wPt[23]) + wPt[18];
            wPt[26] = SSIG1(wPt[24]) + wPt[19];
            wPt[27] = SSIG1(wPt[25]) + wPt[20];
            wPt[28] = SSIG1(wPt[26]) + wPt[21];
            wPt[29] = SSIG1(wPt[27]) + wPt[22];
            wPt[30] = SSIG1(wPt[28]) + wPt[23] + 2882303761517118107;
            wPt[31] = SSIG1(wPt[29]) + wPt[24] + SSIG0(wPt[16]) + 1320;
            wPt[32] = SSIG1(wPt[30]) + wPt[25] + SSIG0(wPt[17]) + wPt[16];
            wPt[33] = SSIG1(wPt[31]) + wPt[26] + SSIG0(wPt[18]) + wPt[17];
            wPt[34] = SSIG1(wPt[32]) + wPt[27] + SSIG0(wPt[19]) + wPt[18];
            wPt[35] = SSIG1(wPt[33]) + wPt[28] + SSIG0(wPt[20]) + wPt[19];
            wPt[36] = SSIG1(wPt[34]) + wPt[29] + SSIG0(wPt[21]) + wPt[20];
            wPt[37] = SSIG1(wPt[35]) + wPt[30] + SSIG0(wPt[22]) + wPt[21];
            wPt[38] = SSIG1(wPt[36]) + wPt[31] + SSIG0(wPt[23]) + wPt[22];
            wPt[39] = SSIG1(wPt[37]) + wPt[32] + SSIG0(wPt[24]) + wPt[23];
            wPt[40] = SSIG1(wPt[38]) + wPt[33] + SSIG0(wPt[25]) + wPt[24];
            wPt[41] = SSIG1(wPt[39]) + wPt[34] + SSIG0(wPt[26]) + wPt[25];
            wPt[42] = SSIG1(wPt[40]) + wPt[35] + SSIG0(wPt[27]) + wPt[26];
            wPt[43] = SSIG1(wPt[41]) + wPt[36] + SSIG0(wPt[28]) + wPt[27];
            wPt[44] = SSIG1(wPt[42]) + wPt[37] + SSIG0(wPt[29]) + wPt[28];
            wPt[45] = SSIG1(wPt[43]) + wPt[38] + SSIG0(wPt[30]) + wPt[29];
            wPt[46] = SSIG1(wPt[44]) + wPt[39] + SSIG0(wPt[31]) + wPt[30];
            wPt[47] = SSIG1(wPt[45]) + wPt[40] + SSIG0(wPt[32]) + wPt[31];
            wPt[48] = SSIG1(wPt[46]) + wPt[41] + SSIG0(wPt[33]) + wPt[32];
            wPt[49] = SSIG1(wPt[47]) + wPt[42] + SSIG0(wPt[34]) + wPt[33];
            wPt[50] = SSIG1(wPt[48]) + wPt[43] + SSIG0(wPt[35]) + wPt[34];
            wPt[51] = SSIG1(wPt[49]) + wPt[44] + SSIG0(wPt[36]) + wPt[35];
            wPt[52] = SSIG1(wPt[50]) + wPt[45] + SSIG0(wPt[37]) + wPt[36];
            wPt[53] = SSIG1(wPt[51]) + wPt[46] + SSIG0(wPt[38]) + wPt[37];
            wPt[54] = SSIG1(wPt[52]) + wPt[47] + SSIG0(wPt[39]) + wPt[38];
            wPt[55] = SSIG1(wPt[53]) + wPt[48] + SSIG0(wPt[40]) + wPt[39];
            wPt[56] = SSIG1(wPt[54]) + wPt[49] + SSIG0(wPt[41]) + wPt[40];
            wPt[57] = SSIG1(wPt[55]) + wPt[50] + SSIG0(wPt[42]) + wPt[41];
            wPt[58] = SSIG1(wPt[56]) + wPt[51] + SSIG0(wPt[43]) + wPt[42];
            wPt[59] = SSIG1(wPt[57]) + wPt[52] + SSIG0(wPt[44]) + wPt[43];
            wPt[60] = SSIG1(wPt[58]) + wPt[53] + SSIG0(wPt[45]) + wPt[44];
            wPt[61] = SSIG1(wPt[59]) + wPt[54] + SSIG0(wPt[46]) + wPt[45];
            wPt[62] = SSIG1(wPt[60]) + wPt[55] + SSIG0(wPt[47]) + wPt[46];
            wPt[63] = SSIG1(wPt[61]) + wPt[56] + SSIG0(wPt[48]) + wPt[47];
            wPt[64] = SSIG1(wPt[62]) + wPt[57] + SSIG0(wPt[49]) + wPt[48];
            wPt[65] = SSIG1(wPt[63]) + wPt[58] + SSIG0(wPt[50]) + wPt[49];
            wPt[66] = SSIG1(wPt[64]) + wPt[59] + SSIG0(wPt[51]) + wPt[50];
            wPt[67] = SSIG1(wPt[65]) + wPt[60] + SSIG0(wPt[52]) + wPt[51];
            wPt[68] = SSIG1(wPt[66]) + wPt[61] + SSIG0(wPt[53]) + wPt[52];
            wPt[69] = SSIG1(wPt[67]) + wPt[62] + SSIG0(wPt[54]) + wPt[53];
            wPt[70] = SSIG1(wPt[68]) + wPt[63] + SSIG0(wPt[55]) + wPt[54];
            wPt[71] = SSIG1(wPt[69]) + wPt[64] + SSIG0(wPt[56]) + wPt[55];
            wPt[72] = SSIG1(wPt[70]) + wPt[65] + SSIG0(wPt[57]) + wPt[56];
            wPt[73] = SSIG1(wPt[71]) + wPt[66] + SSIG0(wPt[58]) + wPt[57];
            wPt[74] = SSIG1(wPt[72]) + wPt[67] + SSIG0(wPt[59]) + wPt[58];
            wPt[75] = SSIG1(wPt[73]) + wPt[68] + SSIG0(wPt[60]) + wPt[59];
            wPt[76] = SSIG1(wPt[74]) + wPt[69] + SSIG0(wPt[61]) + wPt[60];
            wPt[77] = SSIG1(wPt[75]) + wPt[70] + SSIG0(wPt[62]) + wPt[61];
            wPt[78] = SSIG1(wPt[76]) + wPt[71] + SSIG0(wPt[63]) + wPt[62];
            wPt[79] = SSIG1(wPt[77]) + wPt[72] + SSIG0(wPt[64]) + wPt[63];

            CompressBlockWithWSet(hPt, wPt);
        }

        /// <summary>
        /// Computes _single_ SHA512 hash for the second block of
        /// (data.Length == 192) and (wPt[0] to wPt[15] is set) and (Init() is called)
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public static unsafe void Compress192SecondBlock(ulong* hPt, ulong* wPt)
        {
            // w8 = 0b10000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000UL 
            // w9 to w14 = 0
            // w15 = 1536
            wPt[16] = SSIG0(wPt[1]) + wPt[0];
            wPt[17] = 54043195528458264 + SSIG0(wPt[2]) + wPt[1];
            wPt[18] = SSIG1(wPt[16]) + SSIG0(wPt[3]) + wPt[2];
            wPt[19] = SSIG1(wPt[17]) + SSIG0(wPt[4]) + wPt[3];
            wPt[20] = SSIG1(wPt[18]) + SSIG0(wPt[5]) + wPt[4];
            wPt[21] = SSIG1(wPt[19]) + SSIG0(wPt[6]) + wPt[5];
            wPt[22] = SSIG1(wPt[20]) + 1536 + SSIG0(wPt[7]) + wPt[6];
            wPt[23] = SSIG1(wPt[21]) + wPt[16] + 4719772409484279808 + wPt[7];
            wPt[24] = SSIG1(wPt[22]) + wPt[17] + 9223372036854775808;
            wPt[25] = SSIG1(wPt[23]) + wPt[18];
            wPt[26] = SSIG1(wPt[24]) + wPt[19];
            wPt[27] = SSIG1(wPt[25]) + wPt[20];
            wPt[28] = SSIG1(wPt[26]) + wPt[21];
            wPt[29] = SSIG1(wPt[27]) + wPt[22];
            wPt[30] = SSIG1(wPt[28]) + wPt[23] + 778;
            wPt[31] = SSIG1(wPt[29]) + wPt[24] + SSIG0(wPt[16]) + 1536;
            wPt[32] = SSIG1(wPt[30]) + wPt[25] + SSIG0(wPt[17]) + wPt[16];
            wPt[33] = SSIG1(wPt[31]) + wPt[26] + SSIG0(wPt[18]) + wPt[17];
            wPt[34] = SSIG1(wPt[32]) + wPt[27] + SSIG0(wPt[19]) + wPt[18];
            wPt[35] = SSIG1(wPt[33]) + wPt[28] + SSIG0(wPt[20]) + wPt[19];
            wPt[36] = SSIG1(wPt[34]) + wPt[29] + SSIG0(wPt[21]) + wPt[20];
            wPt[37] = SSIG1(wPt[35]) + wPt[30] + SSIG0(wPt[22]) + wPt[21];
            wPt[38] = SSIG1(wPt[36]) + wPt[31] + SSIG0(wPt[23]) + wPt[22];
            wPt[39] = SSIG1(wPt[37]) + wPt[32] + SSIG0(wPt[24]) + wPt[23];
            wPt[40] = SSIG1(wPt[38]) + wPt[33] + SSIG0(wPt[25]) + wPt[24];
            wPt[41] = SSIG1(wPt[39]) + wPt[34] + SSIG0(wPt[26]) + wPt[25];
            wPt[42] = SSIG1(wPt[40]) + wPt[35] + SSIG0(wPt[27]) + wPt[26];
            wPt[43] = SSIG1(wPt[41]) + wPt[36] + SSIG0(wPt[28]) + wPt[27];
            wPt[44] = SSIG1(wPt[42]) + wPt[37] + SSIG0(wPt[29]) + wPt[28];
            wPt[45] = SSIG1(wPt[43]) + wPt[38] + SSIG0(wPt[30]) + wPt[29];
            wPt[46] = SSIG1(wPt[44]) + wPt[39] + SSIG0(wPt[31]) + wPt[30];
            wPt[47] = SSIG1(wPt[45]) + wPt[40] + SSIG0(wPt[32]) + wPt[31];
            wPt[48] = SSIG1(wPt[46]) + wPt[41] + SSIG0(wPt[33]) + wPt[32];
            wPt[49] = SSIG1(wPt[47]) + wPt[42] + SSIG0(wPt[34]) + wPt[33];
            wPt[50] = SSIG1(wPt[48]) + wPt[43] + SSIG0(wPt[35]) + wPt[34];
            wPt[51] = SSIG1(wPt[49]) + wPt[44] + SSIG0(wPt[36]) + wPt[35];
            wPt[52] = SSIG1(wPt[50]) + wPt[45] + SSIG0(wPt[37]) + wPt[36];
            wPt[53] = SSIG1(wPt[51]) + wPt[46] + SSIG0(wPt[38]) + wPt[37];
            wPt[54] = SSIG1(wPt[52]) + wPt[47] + SSIG0(wPt[39]) + wPt[38];
            wPt[55] = SSIG1(wPt[53]) + wPt[48] + SSIG0(wPt[40]) + wPt[39];
            wPt[56] = SSIG1(wPt[54]) + wPt[49] + SSIG0(wPt[41]) + wPt[40];
            wPt[57] = SSIG1(wPt[55]) + wPt[50] + SSIG0(wPt[42]) + wPt[41];
            wPt[58] = SSIG1(wPt[56]) + wPt[51] + SSIG0(wPt[43]) + wPt[42];
            wPt[59] = SSIG1(wPt[57]) + wPt[52] + SSIG0(wPt[44]) + wPt[43];
            wPt[60] = SSIG1(wPt[58]) + wPt[53] + SSIG0(wPt[45]) + wPt[44];
            wPt[61] = SSIG1(wPt[59]) + wPt[54] + SSIG0(wPt[46]) + wPt[45];
            wPt[62] = SSIG1(wPt[60]) + wPt[55] + SSIG0(wPt[47]) + wPt[46];
            wPt[63] = SSIG1(wPt[61]) + wPt[56] + SSIG0(wPt[48]) + wPt[47];
            wPt[64] = SSIG1(wPt[62]) + wPt[57] + SSIG0(wPt[49]) + wPt[48];
            wPt[65] = SSIG1(wPt[63]) + wPt[58] + SSIG0(wPt[50]) + wPt[49];
            wPt[66] = SSIG1(wPt[64]) + wPt[59] + SSIG0(wPt[51]) + wPt[50];
            wPt[67] = SSIG1(wPt[65]) + wPt[60] + SSIG0(wPt[52]) + wPt[51];
            wPt[68] = SSIG1(wPt[66]) + wPt[61] + SSIG0(wPt[53]) + wPt[52];
            wPt[69] = SSIG1(wPt[67]) + wPt[62] + SSIG0(wPt[54]) + wPt[53];
            wPt[70] = SSIG1(wPt[68]) + wPt[63] + SSIG0(wPt[55]) + wPt[54];
            wPt[71] = SSIG1(wPt[69]) + wPt[64] + SSIG0(wPt[56]) + wPt[55];
            wPt[72] = SSIG1(wPt[70]) + wPt[65] + SSIG0(wPt[57]) + wPt[56];
            wPt[73] = SSIG1(wPt[71]) + wPt[66] + SSIG0(wPt[58]) + wPt[57];
            wPt[74] = SSIG1(wPt[72]) + wPt[67] + SSIG0(wPt[59]) + wPt[58];
            wPt[75] = SSIG1(wPt[73]) + wPt[68] + SSIG0(wPt[60]) + wPt[59];
            wPt[76] = SSIG1(wPt[74]) + wPt[69] + SSIG0(wPt[61]) + wPt[60];
            wPt[77] = SSIG1(wPt[75]) + wPt[70] + SSIG0(wPt[62]) + wPt[61];
            wPt[78] = SSIG1(wPt[76]) + wPt[71] + SSIG0(wPt[63]) + wPt[62];
            wPt[79] = SSIG1(wPt[77]) + wPt[72] + SSIG0(wPt[64]) + wPt[63];

            CompressBlockWithWSet(hPt, wPt);
        }


        /// <summary>
        /// Compresses the given block for HMAC functions with 2 first items set to 0x36 ^ UTF8("Bitcoin seed") and
        /// the rest to 0x36 values as defined by HMAC-SHA algorithm.
        /// <para/>This method will set all items from 0 to 80 in w
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public static unsafe void CompressHmacBlock_0x36_Bitcoinseed(ulong* hPt, ulong* wPt)
        {
            // w1 & w2 => 0x3636363636363636UL ^ "Bitcoin seed"
            // w3 to w15 = 0x3636363636363636UL
            wPt[0] = 0x745f4255595f5816UL;
            wPt[1] = 0x4553535236363636UL;
            wPt[2] = 0x3636363636363636UL;
            wPt[3] = 0x3636363636363636UL;
            wPt[4] = 0x3636363636363636UL;
            wPt[5] = 0x3636363636363636UL;
            wPt[6] = 0x3636363636363636UL;
            wPt[7] = 0x3636363636363636UL;
            wPt[8] = 0x3636363636363636UL;
            wPt[9] = 0x3636363636363636UL;
            wPt[10] = 0x3636363636363636UL;
            wPt[11] = 0x3636363636363636UL;
            wPt[12] = 0x3636363636363636UL;
            wPt[13] = 0x3636363636363636UL;
            wPt[14] = 0x3636363636363636UL;
            wPt[15] = 0x3636363636363636UL;
            wPt[16] = 0x36ab84982c867f3cUL;
            wPt[17] = 0x207a7a795d5d5d5cUL;
            wPt[18] = 0x140eb9b421c0933aUL;
            wPt[19] = 0x42a76bd9ee7e61ecUL;
            wPt[20] = 0x4bf06373b762cd51UL;
            wPt[21] = 0x71b9f8e2a6df78d7UL;
            wPt[22] = 0xa0b4a11c27534500UL;
            wPt[23] = 0xfd36cad1277ae636UL;
            wPt[24] = 0xf379c064b2f9b6ceUL;
            wPt[25] = 0x2e0a83303f490971UL;
            wPt[26] = 0x54f91d9ca300a056UL;
            wPt[27] = 0x0129f13799adad0dUL;
            wPt[28] = 0x87c33266679184a1UL;
            wPt[29] = 0xc116a6f0cbf7ea60UL;
            wPt[30] = 0x6d40f14b62510d99UL;
            wPt[31] = 0x47bbaa9befb537f4UL;
            wPt[32] = 0xfb155fb0b24116adUL;
            wPt[33] = 0x3fec19a934241c65UL;
            wPt[34] = 0xdc601ed653b39a18UL;
            wPt[35] = 0x3aa29a2f2c3dfe68UL;
            wPt[36] = 0x0f87ae22bee86a6bUL;
            wPt[37] = 0x9ae9d3e0cf0bbefeUL;
            wPt[38] = 0xa35a984d805a1e51UL;
            wPt[39] = 0x51f080098f858f8dUL;
            wPt[40] = 0x7570d4919edb5dd5UL;
            wPt[41] = 0xc61e9061d17550f8UL;
            wPt[42] = 0xdf1d03c50dee6f36UL;
            wPt[43] = 0x0e0f5d4cd0d9f100UL;
            wPt[44] = 0x5ae8209f86819264UL;
            wPt[45] = 0xe1ebcfc71705f46aUL;
            wPt[46] = 0x7aacba2a9bc64783UL;
            wPt[47] = 0xc1089ca0f512349cUL;
            wPt[48] = 0xd86935fac81d4038UL;
            wPt[49] = 0xe4312c0ace1197d3UL;
            wPt[50] = 0xc7bd36e9996d7213UL;
            wPt[51] = 0x9341f31269ac3f59UL;
            wPt[52] = 0x35048ccee896390cUL;
            wPt[53] = 0xb688ded0bc24ee8fUL;
            wPt[54] = 0xf93f79584148e9daUL;
            wPt[55] = 0xc4ced4698d7f8314UL;
            wPt[56] = 0xcb0bd41d3c1f928eUL;
            wPt[57] = 0xbbd26eb64c089f3aUL;
            wPt[58] = 0x22980cf223478ee1UL;
            wPt[59] = 0x5c4a7dbd11dd87b8UL;
            wPt[60] = 0x12deff15d891a276UL;
            wPt[61] = 0x6ddac191bfbb3134UL;
            wPt[62] = 0xe035279310e9e4d5UL;
            wPt[63] = 0xeab87c927f9da196UL;
            wPt[64] = 0xf323be22fc7fbbe4UL;
            wPt[65] = 0xdabb6d63a1f76b15UL;
            wPt[66] = 0x22cad1cdcd8063ffUL;
            wPt[67] = 0xf8d17c1a564179d8UL;
            wPt[68] = 0x132185dbd9342c7aUL;
            wPt[69] = 0x28a6bdc48a480323UL;
            wPt[70] = 0x77f219e0d38d94c6UL;
            wPt[71] = 0xe8be9ac6db1cd144UL;
            wPt[72] = 0x18c44d093705ddf0UL;
            wPt[73] = 0x2b47a03a3221351dUL;
            wPt[74] = 0x302ae3c9deb98c24UL;
            wPt[75] = 0x6af7da5e4af98288UL;
            wPt[76] = 0xedf400295ec6b828UL;
            wPt[77] = 0x704ba8d9a63ac957UL;
            wPt[78] = 0x666a861b48a11cc1UL;
            wPt[79] = 0x7ab80bd5f234721dUL;

            CompressBlockWithWSet(hPt, wPt);
        }


        /// <summary>
        /// Compresses the given block for HMAC functions with 2 first items set to 0x5c ^ UTF8("Bitcoin seed") and
        /// the rest to 0x5c values as defined by HMAC-SHA algorithm.
        /// <para/>This method will set all items from 0 to 80 in w
        /// </summary>
        /// <param name="hPt">HashState pointer</param>
        /// <param name="wPt">Working vector pointer</param>
        public static unsafe void CompressHmacBlock_0x5c_Bitcoinseed(ulong* hPt, ulong* wPt)
        {
            // w1 & w2 => 0x5c5c5c5c5c5c5c5cUL ^ "Bitcoin seed"
            // w3 to w15 = 0x5c5c5c5c5c5c5c5cUL
            wPt[0] = 0x1e35283f3335327cUL;
            wPt[1] = 0x2f3939385c5c5c5cUL;
            wPt[2] = 0x5c5c5c5c5c5c5c5cUL;
            wPt[3] = 0x5c5c5c5c5c5c5c5cUL;
            wPt[4] = 0x5c5c5c5c5c5c5c5cUL;
            wPt[5] = 0x5c5c5c5c5c5c5c5cUL;
            wPt[6] = 0x5c5c5c5c5c5c5c5cUL;
            wPt[7] = 0x5c5c5c5c5c5c5c5cUL;
            wPt[8] = 0x5c5c5c5c5c5c5c5cUL;
            wPt[9] = 0x5c5c5c5c5c5c5c5cUL;
            wPt[10] = 0x5c5c5c5c5c5c5c5cUL;
            wPt[11] = 0x5c5c5c5c5c5c5c5cUL;
            wPt[12] = 0x5c5c5c5c5c5c5c5cUL;
            wPt[13] = 0x5c5c5c5c5c5c5c5cUL;
            wPt[14] = 0x5c5c5c5c5c5c5c5cUL;
            wPt[15] = 0x5c5c5c5c5c5c5c5cUL;
            wPt[16] = 0x2e97748b0e7471baUL;
            wPt[17] = 0x667878779b9b9b9aUL;
            wPt[18] = 0x25ba3fdc348ec15bUL;
            wPt[19] = 0x6cacf215913fc550UL;
            wPt[20] = 0x20eff62d16e33acfUL;
            wPt[21] = 0xc802b274c57beb33UL;
            wPt[22] = 0x8c296e31810b7bd0UL;
            wPt[23] = 0x3c127c21e41fc77dUL;
            wPt[24] = 0x41a16550a65c860aUL;
            wPt[25] = 0x0d6d768144a060f8UL;
            wPt[26] = 0xd8a10061153e42f7UL;
            wPt[27] = 0x57581dd1cccc10ccUL;
            wPt[28] = 0xa55e55b8fa4dde6bUL;
            wPt[29] = 0x94d4996acb1c32aeUL;
            wPt[30] = 0x9ee443840677ca10UL;
            wPt[31] = 0x6dd8112e7dc24392UL;
            wPt[32] = 0xf1b73eb2544d4375UL;
            wPt[33] = 0x2fd2ef1384b5aca4UL;
            wPt[34] = 0x0a0781298474d939UL;
            wPt[35] = 0x3cdec9b5be361ee8UL;
            wPt[36] = 0x5751248d57841143UL;
            wPt[37] = 0x243ff3b45c78eea3UL;
            wPt[38] = 0x174a92073ce0b408UL;
            wPt[39] = 0x949712c7a7f1ceadUL;
            wPt[40] = 0x1c9e19d7f666c897UL;
            wPt[41] = 0xd0edd3bfb5fee495UL;
            wPt[42] = 0x3a660630977cdf8cUL;
            wPt[43] = 0xbfa99b30c3cf84e9UL;
            wPt[44] = 0xf79da95ceb1727feUL;
            wPt[45] = 0x1a1f809885436533UL;
            wPt[46] = 0x33a299a1990ffdd4UL;
            wPt[47] = 0xd3718aa72920b74cUL;
            wPt[48] = 0xd89ed4491e531328UL;
            wPt[49] = 0xb47ec6d9b9df5bc6UL;
            wPt[50] = 0x65cce5e45686aa39UL;
            wPt[51] = 0x672cef97564e5fd9UL;
            wPt[52] = 0x9d9b8f018974368bUL;
            wPt[53] = 0x4e8007ecff9795ccUL;
            wPt[54] = 0xba2db2863d76b601UL;
            wPt[55] = 0x0e244c7a992e20aeUL;
            wPt[56] = 0x5269d61b0f78433fUL;
            wPt[57] = 0x7d4795d7d128684bUL;
            wPt[58] = 0x73082aca4bab6b77UL;
            wPt[59] = 0xc8dc7bc902b77feaUL;
            wPt[60] = 0xf9232ab04709f463UL;
            wPt[61] = 0x4c10d555afaf0d1fUL;
            wPt[62] = 0x5b05e3f54c2ee530UL;
            wPt[63] = 0xeb172a94be10d867UL;
            wPt[64] = 0xf9af4d8dadda8315UL;
            wPt[65] = 0xf2e90eed546fbdbbUL;
            wPt[66] = 0x37e6d3171deeee47UL;
            wPt[67] = 0x07f032659b6bd4feUL;
            wPt[68] = 0x3761cd5ded50e03fUL;
            wPt[69] = 0xcc602e922c42f7a4UL;
            wPt[70] = 0xf619333ae35df071UL;
            wPt[71] = 0xdd5a5927212b408dUL;
            wPt[72] = 0x4796ab36cbd4f5bcUL;
            wPt[73] = 0x04f59200491aebe1UL;
            wPt[74] = 0xad4c42811261ce38UL;
            wPt[75] = 0x199ca023df097ddaUL;
            wPt[76] = 0xd06fe5c2bb8c3850UL;
            wPt[77] = 0x42d2391d3003b00dUL;
            wPt[78] = 0xd34b74e17a5c282eUL;
            wPt[79] = 0x7d2655337dff24dcUL;

            CompressBlockWithWSet(hPt, wPt);
        }



        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static unsafe void SetW(ulong* wPt, int start = 16)
        {
            for (int i = start; i < WorkingVectorSize; i++)
            {
                wPt[i] = SSIG1(wPt[i - 2]) + wPt[i - 7] + SSIG0(wPt[i - 15]) + wPt[i - 16];
            }
        }

        public static unsafe void CompressBlockWithWSet(ulong* hPt, ulong* wPt)
        {
            ulong a = hPt[0];
            ulong b = hPt[1];
            ulong c = hPt[2];
            ulong d = hPt[3];
            ulong e = hPt[4];
            ulong f = hPt[5];
            ulong g = hPt[6];
            ulong h = hPt[7];

            ulong temp, aa, bb, cc, dd, ee, ff, hh, gg;

            fixed (ulong* kPt = &Ks[0])
            {
                for (int j = 0; j < 80;)
                {
                    temp = h + BSIG1(e) + CH(e, f, g) + kPt[j] + wPt[j];
                    ee = d + temp;
                    aa = temp + BSIG0(a) + MAJ(a, b, c);
                    j++;

                    temp = g + BSIG1(ee) + CH(ee, e, f) + kPt[j] + wPt[j];
                    ff = c + temp;
                    bb = temp + BSIG0(aa) + MAJ(aa, a, b);
                    j++;

                    temp = f + BSIG1(ff) + CH(ff, ee, e) + kPt[j] + wPt[j];
                    gg = b + temp;
                    cc = temp + BSIG0(bb) + MAJ(bb, aa, a);
                    j++;

                    temp = e + BSIG1(gg) + CH(gg, ff, ee) + kPt[j] + wPt[j];
                    hh = a + temp;
                    dd = temp + BSIG0(cc) + MAJ(cc, bb, aa);
                    j++;

                    temp = ee + BSIG1(hh) + CH(hh, gg, ff) + kPt[j] + wPt[j];
                    h = aa + temp;
                    d = temp + BSIG0(dd) + MAJ(dd, cc, bb);
                    j++;

                    temp = ff + BSIG1(h) + CH(h, hh, gg) + kPt[j] + wPt[j];
                    g = bb + temp;
                    c = temp + BSIG0(d) + MAJ(d, dd, cc);
                    j++;

                    temp = gg + BSIG1(g) + CH(g, h, hh) + kPt[j] + wPt[j];
                    f = cc + temp;
                    b = temp + BSIG0(c) + MAJ(c, d, dd);
                    j++;

                    temp = hh + BSIG1(f) + CH(f, g, h) + kPt[j] + wPt[j];
                    e = dd + temp;
                    a = temp + BSIG0(b) + MAJ(b, c, d);
                    j++;
                }
            }

            hPt[0] += a;
            hPt[1] += b;
            hPt[2] += c;
            hPt[3] += d;
            hPt[4] += e;
            hPt[5] += f;
            hPt[6] += g;
            hPt[7] += h;
        }


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong CH(ulong x, ulong y, ulong z) => z ^ (x & (y ^ z));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong MAJ(ulong x, ulong y, ulong z) => (x & y) | (z & (x | y));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong BSIG0(ulong x) => (x >> 28 | x << 36) ^ (x >> 34 | x << 30) ^ (x >> 39 | x << 25);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong BSIG1(ulong x) => (x >> 14 | x << 50) ^ (x >> 18 | x << 46) ^ (x >> 41 | x << 23);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ulong SSIG0(ulong x) => (x >> 1 | x << 63) ^ (x >> 8 | x << 56) ^ (x >> 7);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ulong SSIG1(ulong x) => (x >> 19 | x << 45) ^ (x >> 61 | x << 3) ^ (x >> 6);
    }
}
