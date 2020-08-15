// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using Autarkysoft.Bitcoin.Cryptography.Asymmetric.EllipticCurve;
using Autarkysoft.Bitcoin.ImprovementProposals;
using FinderOuter.Backend;
using FinderOuter.Backend.Cryptography.Hashing;
using FinderOuter.Models;
using FinderOuter.Services.Comparers;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Text;
using System.Threading.Tasks;

namespace FinderOuter.Services
{
    public enum MnemonicTypes
    {
        BIP39,
        Electrum,
    }

    public class MnemonicSevice
    {
        public MnemonicSevice(IReport rep)
        {
            report = rep;
            inputService = new InputService();
            calc = new EllipticCurveCalculator();
        }


        private readonly IReport report;
        private readonly InputService inputService;
        private readonly EllipticCurveCalculator calc;

        private Dictionary<uint, byte[]> wordBytes = new Dictionary<uint, byte[]>(2048);
        public const byte SpaceByte = 32;

        private readonly int[] allowedWordLengths = { 12, 15, 18, 21, 24 };
        private uint[] wordIndexes;
        private int[] missingIndexes;
        private string[] allWords;
        private byte[] pbkdf2Salt;
        private byte[] mnBytes;
        private BIP0032Path path;
        private ICompareService comparer;

        private readonly BigInteger order = new SecP256k1().N;
        private const ulong N0 = 0xBFD25E8C_D0364141;
        private const ulong N1 = 0xBAAEDCE6_AF48A03B;
        private const ulong N2 = 0xFFFFFFFF_FFFFFFFE;
        private const ulong N3 = 0xFFFFFFFF_FFFFFFFF;

        private int missCount;
        private string[] words;


        public unsafe bool SetBip32(Sha512Fo sha, byte* mnPt, int mnLen, ulong* iPt, ulong* oPt)
        {
            // The process is: PBKDF2(password=UTF8(mnemonic), salt=UTF8("mnemonic+passphrase") -> BIP32 seed
            //                 BIP32 -> HMACSHA(data=seed, key=MasterKeyHashKey) -> HMACSHA(data=key|index, key=ChainCode)
            // All HMACSHAs are using 512 variant

            // *** PBKDF2 ***
            // dkLen/HmacLen=1 => only 1 block => no loop needed
            // Salt is the "mnemonic+passPhrase" + blockNumber(=1) => fixed and set during precomputing
            ulong[] resultOfF = new ulong[8];
            ulong[] uTemp = new ulong[80];

            ulong[] iPadHashStateTemp = new ulong[8];
            ulong[] oPadHashStateTemp = new ulong[8];

            ulong parkey0, parkey1, parkey2, parkey3, carry;

            fixed (byte* dPt = &pbkdf2Salt[0])
            fixed (ulong* hPt = &sha.hashState[0], wPt = &sha.w[0], seedPt = &resultOfF[0], uPt = &uTemp[0],
                          ihPt = &iPadHashStateTemp[0], ohPt = &oPadHashStateTemp[0])
            {
                // Setting values in uTemp that never change
                uPt[8] = 0b10000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000UL;
                uPt[9] = 0;
                uPt[10] = 0;
                uPt[11] = 0;
                uPt[12] = 0;
                uPt[13] = 0;
                uPt[14] = 0;
                uPt[15] = 1536;


                // Set HMAC key ie. set pads (used as working vectors)
                if (mnLen > Sha512Fo.BlockByteSize)
                {
                    // Key bytes must be hashed first
                    sha.Init(hPt);
                    sha.CompressData(mnPt, mnLen, mnLen, hPt, wPt);
                    // Set pads to be used as working vectors
                    iPt[0] = 0x3636363636363636U ^ hPt[0];
                    iPt[1] = 0x3636363636363636U ^ hPt[1];
                    iPt[2] = 0x3636363636363636U ^ hPt[2];
                    iPt[3] = 0x3636363636363636U ^ hPt[3];
                    iPt[4] = 0x3636363636363636U ^ hPt[4];
                    iPt[5] = 0x3636363636363636U ^ hPt[5];
                    iPt[6] = 0x3636363636363636U ^ hPt[6];
                    iPt[7] = 0x3636363636363636U ^ hPt[7];
                    iPt[8] = 0x3636363636363636U;
                    iPt[9] = 0x3636363636363636U;
                    iPt[10] = 0x3636363636363636U;
                    iPt[11] = 0x3636363636363636U;
                    iPt[12] = 0x3636363636363636U;
                    iPt[13] = 0x3636363636363636U;
                    iPt[14] = 0x3636363636363636U;
                    iPt[15] = 0x3636363636363636U;

                    oPt[0] = 0x5c5c5c5c5c5c5c5cU ^ hPt[0];
                    oPt[1] = 0x5c5c5c5c5c5c5c5cU ^ hPt[1];
                    oPt[2] = 0x5c5c5c5c5c5c5c5cU ^ hPt[2];
                    oPt[3] = 0x5c5c5c5c5c5c5c5cU ^ hPt[3];
                    oPt[4] = 0x5c5c5c5c5c5c5c5cU ^ hPt[4];
                    oPt[5] = 0x5c5c5c5c5c5c5c5cU ^ hPt[5];
                    oPt[6] = 0x5c5c5c5c5c5c5c5cU ^ hPt[6];
                    oPt[7] = 0x5c5c5c5c5c5c5c5cU ^ hPt[7];
                    oPt[8] = 0x5c5c5c5c5c5c5c5cU;
                    oPt[9] = 0x5c5c5c5c5c5c5c5cU;
                    oPt[10] = 0x5c5c5c5c5c5c5c5cU;
                    oPt[11] = 0x5c5c5c5c5c5c5c5cU;
                    oPt[12] = 0x5c5c5c5c5c5c5c5cU;
                    oPt[13] = 0x5c5c5c5c5c5c5c5cU;
                    oPt[14] = 0x5c5c5c5c5c5c5c5cU;
                    oPt[15] = 0x5c5c5c5c5c5c5c5cU;
                }
                else
                {
                    byte[] temp = new byte[Sha512Fo.BlockByteSize];
                    fixed (byte* tPt = &temp[0])
                    {
                        Buffer.MemoryCopy(mnPt, tPt, Sha512Fo.BlockByteSize, mnLen);
                        for (int i = 0, j = 0; i < 16; i++, j += 8)
                        {
                            ulong val =
                                ((ulong)tPt[j] << 56) |
                                ((ulong)tPt[j + 1] << 48) |
                                ((ulong)tPt[j + 2] << 40) |
                                ((ulong)tPt[j + 3] << 32) |
                                ((ulong)tPt[j + 4] << 24) |
                                ((ulong)tPt[j + 5] << 16) |
                                ((ulong)tPt[j + 6] << 8) |
                                tPt[j + 7];

                            iPt[i] = 0x3636363636363636U ^ val;
                            oPt[i] = 0x5c5c5c5c5c5c5c5cU ^ val;
                        }
                    }
                }

                // F()
                // compute u1 = hmac.ComputeHash(data=pbkdf2Salt);

                // Final result is SHA512(outer_pad | SHA512(inner_pad | data)) where data is pbkdf2Salt
                // 1. Compute SHA512(inner_pad | data)
                sha.Init(hPt);
                sha.CompressBlock(hPt, iPt);
                // Make a copy of hashState of inner-pad to be used in the loop below (explaination in the loop)
                *(Block64*)ihPt = *(Block64*)hPt;
                // Data length is unknown and an initial block of 128 bytes was already compressed
                sha.CompressData(dPt, pbkdf2Salt.Length, pbkdf2Salt.Length + 128, hPt, wPt);
                // 2. Compute SHA512(outer_pad | hash)
                *(Block64*)wPt = *(Block64*)hPt;
                wPt[8] = 0b10000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000UL;
                wPt[9] = 0;
                wPt[10] = 0;
                wPt[11] = 0;
                wPt[12] = 0;
                wPt[13] = 0;
                wPt[14] = 0;
                wPt[15] = 1536; // oPad.Length(=128) + hashState.Lengh(=64) = 192 byte *8 = 1,536 bit

                sha.Init(hPt);
                sha.CompressBlock(hPt, oPt);
                // Make a copy of hashState of outer-pad to be used in the loop below (explaination in the loop)
                *(Block64*)ohPt = *(Block64*)hPt;
                sha.Compress192SecondBlock(hPt, wPt);

                // Copy u1 to result of F() to be XOR'ed with each result on iterations, and result of F() is the seed
                *(Block64*)seedPt = *(Block64*)hPt;

                // Compute u2 to u(c-1) where c is iteration and each u is the HMAC of previous u
                for (int j = 1; j < 2048; j++)
                {
                    // Each u is calculated by computing HMAC(previous_u) where previous_u is 64 bytes hPt
                    // Start by making a copy of hPt so Init() can be called
                    *(Block64*)uPt = *(Block64*)hPt;

                    // Final result is SHA512(outer_pad | SHA512(inner_pad | 64_byte_data))
                    // 1. Compute SHA512(inner_pad | 64_byte_data)
                    // 2. Compute SHA512(outer_pad | hash)
                    //    Since pads don't change and each step is Init() then Compress(pad) the hashState is always the same
                    //    after these 2 steps and is already computed and stored in temp arrays above
                    //    by doing this 2*2047=4094 SHA512 block compressions are skipped

                    // Replace: sha.Init(hPt); sha.CompressBlockWithWSet(hPt, iPt); with line below:
                    *(Block64*)hPt = *(Block64*)ihPt;
                    sha.Compress192SecondBlock(hPt, uPt);

                    // 2. Compute SHA512(outer_pad | hash)
                    *(Block64*)wPt = *(Block64*)hPt;
                    // The rest of wPt is set above and is unchanged

                    // Replace: sha.Init(hPt); sha.CompressBlock(hPt, oPt); with line below:
                    *(Block64*)hPt = *(Block64*)ohPt;
                    sha.Compress192SecondBlock(hPt, wPt);

                    // result of F() is XOR sum of all u arrays
                    if (Avx2.IsSupported) // AVX512 :(
                    {
                        Vector256<ulong> part1 = Avx2.Xor(Avx2.LoadVector256(seedPt), Avx2.LoadVector256(hPt));
                        Vector256<ulong> part2 = Avx2.Xor(Avx2.LoadVector256(seedPt + 4), Avx2.LoadVector256(hPt + 4));

                        Avx2.Store(seedPt, part1);
                        Avx2.Store(seedPt + 4, part2);
                    }
                    else
                    {
                        seedPt[0] ^= hPt[0];
                        seedPt[1] ^= hPt[1];
                        seedPt[2] ^= hPt[2];
                        seedPt[3] ^= hPt[3];
                        seedPt[4] ^= hPt[4];
                        seedPt[5] ^= hPt[5];
                        seedPt[6] ^= hPt[6];
                        seedPt[7] ^= hPt[7];
                    }
                }


                // *** BIP32 ***
                // Set from entropy/seed by computing HMAC(data=seed, key="Bitcoin seed")

                // Final result is SHA512(outer_pad | SHA512(inner_pad | data)) where data is 64-byte seed
                // 1. Compute SHA512(inner_pad | data)
                sha.Init_InnerPad_Bitcoinseed(hPt);
                *(Block64*)wPt = *(Block64*)seedPt;
                // from wPt[8] to wPt[15] didn't change
                sha.Compress192SecondBlock(hPt, wPt);

                // 2. Compute SHA512(outer_pad | hash)
                *(Block64*)wPt = *(Block64*)hPt; // ** Copy hashState before changing it **
                // from wPt[8] to wPt[15] didn't change
                sha.Init_OuterPad_Bitcoinseed(hPt);
                sha.Compress192SecondBlock(hPt, wPt);
                // Master key is set. PrivateKey= first 32-bytes of hPt and ChainCode is second 32-bytes

                // Each child is derived by computing HMAC(data=(hardened? 0|prvKey : pubkey) | index, key=ChainCode)
                // ChainCode is the second 32-byte half of the hash. Set pad items that never change here:
                iPt[4] = 0x3636363636363636U;
                iPt[5] = 0x3636363636363636U;
                iPt[6] = 0x3636363636363636U;
                iPt[7] = 0x3636363636363636U;
                iPt[8] = 0x3636363636363636U;
                iPt[9] = 0x3636363636363636U;
                iPt[10] = 0x3636363636363636U;
                iPt[11] = 0x3636363636363636U;
                iPt[12] = 0x3636363636363636U;
                iPt[13] = 0x3636363636363636U;
                iPt[14] = 0x3636363636363636U;
                iPt[15] = 0x3636363636363636U;

                oPt[4] = 0x5c5c5c5c5c5c5c5cU;
                oPt[5] = 0x5c5c5c5c5c5c5c5cU;
                oPt[6] = 0x5c5c5c5c5c5c5c5cU;
                oPt[7] = 0x5c5c5c5c5c5c5c5cU;
                oPt[8] = 0x5c5c5c5c5c5c5c5cU;
                oPt[9] = 0x5c5c5c5c5c5c5c5cU;
                oPt[10] = 0x5c5c5c5c5c5c5c5cU;
                oPt[11] = 0x5c5c5c5c5c5c5c5cU;
                oPt[12] = 0x5c5c5c5c5c5c5c5cU;
                oPt[13] = 0x5c5c5c5c5c5c5c5cU;
                oPt[14] = 0x5c5c5c5c5c5c5c5cU;
                oPt[15] = 0x5c5c5c5c5c5c5c5cU;

                uPt[5] = 0;
                uPt[6] = 0;
                uPt[7] = 0;
                uPt[8] = 0;
                uPt[9] = 0;
                uPt[10] = 0;
                uPt[11] = 0;
                uPt[12] = 0;
                uPt[13] = 0;
                uPt[14] = 0;
                uPt[15] = 1320; // (1+32+4 + 128)*8

                BigInteger kParent = new BigInteger(sha.GetFirst32Bytes(hPt), true, true);
                if (kParent == 0 || kParent >= order)
                {
                    return false;
                }
                parkey0 = hPt[3];
                parkey1 = hPt[2];
                parkey2 = hPt[1];
                parkey3 = hPt[0];

                foreach (var index in path.Indexes)
                {
                    if ((index & 0x80000000) != 0) // IsHardened
                    {
                        // First _byte_ is zero
                        // private-key is the first 32 bytes (4 items) of hPt (total 33 bytes)
                        // 4 bytes index + SHA padding are also added
                        uPt[0] = parkey3 >> 8;
                        uPt[1] = parkey3 << 56 | parkey2 >> 8;
                        uPt[2] = parkey2 << 56 | parkey1 >> 8;
                        uPt[3] = parkey1 << 56 | parkey0 >> 8;
                        uPt[4] = parkey0 << 56 |
                                 (ulong)index << 24 |
                                 0b00000000_00000000_00000000_00000000_00000000_10000000_00000000_00000000UL;
                    }
                    else
                    {
                        var point = calc.MultiplyByG(kParent);
                        byte[] xBytes = point.X.ToByteArray(true, true).PadLeft(32);
                        fixed (byte* pubXPt = &xBytes[0])
                        {
                            uPt[0] = (point.Y.IsEven ? 0x0200000000000000UL : 0x0300000000000000UL) |
                                     (ulong)pubXPt[0] << 48 |
                                     (ulong)pubXPt[1] << 40 |
                                     (ulong)pubXPt[2] << 32 |
                                     (ulong)pubXPt[3] << 24 |
                                     (ulong)pubXPt[4] << 16 |
                                     (ulong)pubXPt[5] << 8 |
                                            pubXPt[6];
                            uPt[1] = (ulong)pubXPt[7] << 56 |
                                     (ulong)pubXPt[8] << 48 |
                                     (ulong)pubXPt[9] << 40 |
                                     (ulong)pubXPt[10] << 32 |
                                     (ulong)pubXPt[11] << 24 |
                                     (ulong)pubXPt[12] << 16 |
                                     (ulong)pubXPt[13] << 8 |
                                            pubXPt[14];
                            uPt[2] = (ulong)pubXPt[15] << 56 |
                                     (ulong)pubXPt[16] << 48 |
                                     (ulong)pubXPt[17] << 40 |
                                     (ulong)pubXPt[18] << 32 |
                                     (ulong)pubXPt[19] << 24 |
                                     (ulong)pubXPt[20] << 16 |
                                     (ulong)pubXPt[21] << 8 |
                                            pubXPt[22];
                            uPt[3] = (ulong)pubXPt[23] << 56 |
                                     (ulong)pubXPt[24] << 48 |
                                     (ulong)pubXPt[25] << 40 |
                                     (ulong)pubXPt[26] << 32 |
                                     (ulong)pubXPt[27] << 24 |
                                     (ulong)pubXPt[28] << 16 |
                                     (ulong)pubXPt[29] << 8 |
                                            pubXPt[30];
                            uPt[4] = (ulong)pubXPt[31] << 56 |
                                     (ulong)index << 24 |
                                     0b00000000_00000000_00000000_00000000_00000000_10000000_00000000_00000000UL;
                        }
                    }


                    // Final result is SHA512(outer_pad | SHA512(inner_pad | 37_byte_data))
                    // 1. Compute SHA512(inner_pad | 37_byte_data)
                    // Set pads to be used as working vectors (key is ChainCode that is the second 32 bytes of SHA512
                    iPt[0] = 0x3636363636363636U ^ hPt[4];
                    iPt[1] = 0x3636363636363636U ^ hPt[5];
                    iPt[2] = 0x3636363636363636U ^ hPt[6];
                    iPt[3] = 0x3636363636363636U ^ hPt[7];

                    oPt[0] = 0x5c5c5c5c5c5c5c5cU ^ hPt[4];
                    oPt[1] = 0x5c5c5c5c5c5c5c5cU ^ hPt[5];
                    oPt[2] = 0x5c5c5c5c5c5c5c5cU ^ hPt[6];
                    oPt[3] = 0x5c5c5c5c5c5c5c5cU ^ hPt[7];

                    sha.Init(hPt);
                    sha.CompressBlock(hPt, iPt);
                    sha.Compress165SecondBlock(hPt, uPt);

                    // 2. Compute SHA512(outer_pad | hash)
                    *(Block64*)wPt = *(Block64*)hPt;

                    // from wPt[8] to wPt[15] didn't change
                    sha.Init(hPt);
                    sha.CompressBlock(hPt, oPt);
                    sha.Compress192SecondBlock(hPt, wPt);

                    // New private key is (parentPrvKey + int(hPt)) % order
                    // TODO: this is a bottleneck and needs to be replaced by a ModularUInt256 instance
                    kParent = (kParent + new BigInteger(sha.GetFirst32Bytes(hPt), true, true)) % order;

                    ulong toAdd = hPt[3];
                    parkey0 += toAdd;
                    if (parkey0 < toAdd) parkey1++;

                    toAdd = hPt[2];
                    parkey1 += toAdd;
                    if (parkey1 < toAdd) parkey2++;

                    toAdd = hPt[1];
                    parkey2 += toAdd;
                    if (parkey2 < toAdd) parkey3++;

                    toAdd = hPt[0];
                    parkey3 += toAdd;
                    if (parkey3 < toAdd) carry = 1;
                    else carry = 0;

                    bool bigger = false;
                    if (carry == 1)
                    {
                        bigger = true;
                    }
                    else if (parkey3 == N3)
                    {
                        if (parkey2 > N2)
                        {
                            bigger = true;
                        }
                        else if (parkey2 == N2)
                        {
                            if (parkey1 > N1)
                            {
                                bigger = true;
                            }
                            else if (parkey1 == N1)
                            {
                                if (parkey0 >= N0)
                                {
                                    bigger = true;
                                }
                            }
                        }
                    }

                    if (bigger)
                    {
                        if (parkey0 < N0) parkey1--;
                        parkey0 -= N0;

                        if (parkey1 < N1) parkey2--;
                        parkey1 -= N1;

                        if (parkey2 < N2) parkey3--;
                        parkey2 -= N2;

                        parkey3 -= N3;
                    }
                }

                // Child extended key (private key + chianCode) should be set by adding the index to the end of the Path
                // and have been computed already
                hPt[0] = parkey3;
                hPt[1] = parkey2;
                hPt[2] = parkey1;
                hPt[3] = parkey0;

                return comparer.Compare(sha.GetFirst32Bytes(hPt));
            }
        }


        private bool SetResult(int mnLen)
        {
            report.AddMessageSafe($"Found a key: {Encoding.UTF8.GetString(mnBytes.SubArray(0, mnLen))}");
            return true;
        }


        private unsafe bool Loop24()
        {
            using Sha512Fo sha512 = new Sha512Fo();
            ulong[] ipad = new ulong[80];
            ulong[] opad = new ulong[80];

            using Sha256Fo sha256 = new Sha256Fo();
            var cartesian = CartesianProduct.Create(Enumerable.Repeat(Enumerable.Range(0, 2048), missCount));

            fixed (ulong* iPt = ipad, oPt = opad)
            fixed (uint* wPt = &sha256.w[0], hPt = &sha256.hashState[0], wrd = &wordIndexes[0])
            fixed (int* mi = &missingIndexes[0])
            fixed (byte* mnPt = &mnBytes[0])
            {
                wPt[8] = 0b10000000_00000000_00000000_00000000U;
                wPt[15] = 256;

                foreach (var item in cartesian)
                {
                    int j = 0;
                    foreach (var k in item)
                    {
                        wrd[mi[j]] = (uint)k;
                        j++;
                    }
                    // 0000_0000 0000_0000 0000_0111 1111_1111 -> 1111_1111 1110_0000 0000_0000 0000_0000
                    // 0000_0000 0000_0000 0000_0222 2222_2222 -> 0000_0000 0002_2222 2222_2200 0000_0000
                    // 0000_0000 0000_0000 0000_0333 3333_3333 -> 0000_0000 0000_0000 0000_0033 3333_3333 -> 3
                    //                                            1111_1111 1112_2222 2222_2233 3333_3333
                    wPt[0] = wrd[0] << 21 | wrd[1] << 10 | wrd[2] >> 1;

                    // 0000_0000 0000_0000 0000_0000 0000_0003 -> 3000_0000 0000_0000 0000_0000 0000_0000
                    // 0000_0000 0000_0000 0000_0444 4444_4444 -> 0444_4444 4444_0000 0000_0000 0000_0000
                    // 0000_0000 0000_0000 0000_0555 5555_5555 -> 0000_0000 0000_5555 5555_5550 0000_0000
                    // 0000_0000 0000_0000 0000_0666 6666_6666 -> 0000_0000 0000_0000 0000_0006 6666_6666 -> 66
                    //                                            3444_4444 4444_5555 5555_5556 6666_6666
                    wPt[1] = wrd[2] << 31 | wrd[3] << 20 | wrd[4] << 9 | wrd[5] >> 2;

                    // 0000_0000 0000_0000 0000_0000 0000_0066 -> 6600_0000 0000_0000 0000_0000 0000_0000
                    // 0000_0000 0000_0000 0000_0777 7777_7777 -> 0077_7777 7777_7000 0000_0000 0000_0000
                    // 0000_0000 0000_0000 0000_0888 8888_8888 -> 0000_0000 0000_0888 8888_8888 0000_0000
                    // 0000_0000 0000_0000 0000_0999 9999_9999 -> 0000_0000 0000_0000 0000_0000 9999_9999 -> 999
                    //                                            6677_7777 7777_7888 8888_8888 9999_9999
                    wPt[2] = wrd[5] << 30 | wrd[6] << 19 | wrd[7] << 8 | wrd[8] >> 3;

                    // 0000_0000 0000_0000 0000_0000 0000_0999 -> 9990_0000 0000_0000 0000_0000 0000_0000
                    // 0000_0000 0000_0000 0000_0AAA AAAA_AAAA -> 000A_AAAA AAAA_AA00 0000_0000 0000_0000
                    // 0000_0000 0000_0000 0000_0BBB BBBB_BBBB -> 0000_0000 0000_00BB BBBB_BBBB B000_0000
                    // 0000_0000 0000_0000 0000_0CCC CCCC_CCCC -> 0000_0000 0000_0000 0000_0000 0CCC_CCCC -> CCCC
                    //                                            999A_AAAA AAAA_AABB BBBB_BBBB BCCC_CCCC
                    wPt[3] = wrd[8] << 29 | wrd[9] << 18 | wrd[10] << 7 | wrd[11] >> 4;

                    // 0000_0000 0000_0000 0000_0000 0000_CCCC -> CCCC_0000 0000_0000 0000_0000 0000_0000
                    // 0000_0000 0000_0000 0000_0DDD DDDD_DDDD -> 0000_DDDD DDDD_DDD0 0000_0000 0000_0000
                    // 0000_0000 0000_0000 0000_0EEE EEEE_EEEE -> 0000_0000 0000_000E EEEE_EEEE EE00_0000
                    // 0000_0000 0000_0000 0000_0FFF FFFF_FFFF -> 0000_0000 0000_0000 0000_0000 00FF_FFFF -> FFFF_F
                    //                                            CCCC_DDDD DDDD_DDDE EEEE_EEEE EEFF_FFFF
                    wPt[4] = wrd[11] << 28 | wrd[12] << 17 | wrd[13] << 6 | wrd[14] >> 5;

                    // 0000_0000 0000_0000 0000_0000 000F_FFFF -> FFFF_F000 0000_0000 0000_0000 0000_0000
                    // 0000_0000 0000_0000 0000_0GGG GGGG_GGGG -> 0000_0GGG GGGG_GGGG 0000_0000 0000_0000
                    // 0000_0000 0000_0000 0000_0HHH HHHH_HHHH -> 0000_0000 0000_0000 HHHH_HHHH HHH0_0000
                    // 0000_0000 0000_0000 0000_0III IIII_IIII -> 0000_0000 0000_0000 0000_0000 000I_IIII -> IIII_II
                    //                                         -> FFFF_FGGG GGGG_GGGG HHHH_HHHH HHHI_IIII
                    wPt[5] = wrd[14] << 27 | wrd[15] << 16 | wrd[16] << 5 | wrd[17] >> 6;

                    // 0000_0000 0000_0000 0000_0000 00II_IIII -> IIII_II00 0000_0000 0000_0000 0000_0000
                    // 0000_0000 0000_0000 0000_0JJJ JJJJ_JJJJ -> 0000_00JJ JJJJ_JJJJ J000_0000 0000_0000
                    // 0000_0000 0000_0000 0000_0KKK KKKK_KKKK -> 0000_0000 0000_0000 0KKK_KKKK KKKK_0000
                    // 0000_0000 0000_0000 0000_0LLL LLLL_LLLL -> 0000_0000 0000_0000 0000_0000 0000_LLLL -> LLLL_LLL
                    //                                         -> IIII_IIJJ JJJJ_JJJJ JKKK_KKKK KKKK_LLLL
                    wPt[6] = wrd[17] << 26 | wrd[18] << 15 | wrd[19] << 4 | wrd[20] >> 7;

                    // 0000_0000 0000_0000 0000_0000 0LLL_LLLL -> LLLL_LLL0 0000_0000 0000_0000 0000_0000
                    // 0000_0000 0000_0000 0000_0MMM MMMM_MMMM -> 0000_000M MMMM_MMMM MM00_0000 0000_0000
                    // 0000_0000 0000_0000 0000_0NNN NNNN_NNNN -> 0000_0000 0000_0000 00NN_NNNN NNNN_N000
                    // 0000_0000 0000_0000 0000_0OOO OOOO_OOOO -> 0000_0000 0000_0000 0000_0000 0000_0OOO -> OOOO_OOOO
                    //                                         -> LLLL_LLLM MMMM_MMMM MMNN_NNNN NNNN_NOOO
                    wPt[7] = wrd[20] << 25 | wrd[21] << 14 | wrd[22] << 3 | wrd[23] >> 8;

                    sha256.Init(hPt);
                    sha256.Compress32(hPt, wPt);

                    if ((byte)wrd[23] == hPt[0] >> 24)
                    {
                        int mnLen = 0;
                        for (int i = 0; i < 24; i++)
                        {
                            foreach (byte b in wordBytes[wrd[i]])
                            {
                                mnPt[mnLen++] = b;
                            }
                            mnPt[mnLen++] = SpaceByte;
                        }

                        if (SetBip32(sha512, mnPt, --mnLen, iPt, oPt))
                        {
                            return SetResult(mnLen);
                        }
                    }
                }
            }

            return false;
        }

        private unsafe bool Loop21()
        {
            using Sha512Fo sha512 = new Sha512Fo();
            ulong[] ipad = new ulong[80];
            ulong[] opad = new ulong[80];

            using Sha256Fo sha256 = new Sha256Fo();
            var cartesian = CartesianProduct.Create(Enumerable.Repeat(Enumerable.Range(0, 2048), missCount));

            fixed (ulong* iPt = ipad, oPt = opad)
            fixed (uint* wPt = &sha256.w[0], hPt = &sha256.hashState[0], wrd = &wordIndexes[0])
            fixed (int* mi = &missingIndexes[0])
            fixed (byte* mnPt = &mnBytes[0])
            {
                wPt[7] = 0b10000000_00000000_00000000_00000000U;
                wPt[15] = 224;

                foreach (var item in cartesian)
                {
                    int j = 0;
                    foreach (var k in item)
                    {
                        wrd[mi[j]] = (uint)k;
                        j++;
                    }

                    wPt[0] = wrd[0] << 21 | wrd[1] << 10 | wrd[2] >> 1;
                    wPt[1] = wrd[2] << 31 | wrd[3] << 20 | wrd[4] << 9 | wrd[5] >> 2;
                    wPt[2] = wrd[5] << 30 | wrd[6] << 19 | wrd[7] << 8 | wrd[8] >> 3;
                    wPt[3] = wrd[8] << 29 | wrd[9] << 18 | wrd[10] << 7 | wrd[11] >> 4;
                    wPt[4] = wrd[11] << 28 | wrd[12] << 17 | wrd[13] << 6 | wrd[14] >> 5;
                    wPt[5] = wrd[14] << 27 | wrd[15] << 16 | wrd[16] << 5 | wrd[17] >> 6;
                    wPt[6] = wrd[17] << 26 | wrd[18] << 15 | wrd[19] << 4 | wrd[20] >> 7;

                    sha256.Init(hPt);
                    sha256.Compress28(hPt, wPt);

                    if ((wrd[20] & 0b111_1111) == hPt[0] >> 25)
                    {
                        int mnLen = 0;
                        for (int i = 0; i < 21; i++)
                        {
                            foreach (byte b in wordBytes[wrd[i]])
                            {
                                mnPt[mnLen++] = b;
                            }
                            mnPt[mnLen++] = SpaceByte;
                        }

                        if (SetBip32(sha512, mnPt, --mnLen, iPt, oPt))
                        {
                            return SetResult(mnLen);
                        }
                    }
                }
            }

            return false;
        }

        private unsafe bool Loop18()
        {
            using Sha512Fo sha512 = new Sha512Fo();
            ulong[] ipad = new ulong[80];
            ulong[] opad = new ulong[80];

            using Sha256Fo sha256 = new Sha256Fo();
            var cartesian = CartesianProduct.Create(Enumerable.Repeat(Enumerable.Range(0, 2048), missCount));

            fixed (ulong* iPt = ipad, oPt = opad)
            fixed (uint* wPt = &sha256.w[0], hPt = &sha256.hashState[0], wrd = &wordIndexes[0])
            fixed (int* mi = &missingIndexes[0])
            fixed (byte* mnPt = &mnBytes[0])
            {
                wPt[6] = 0b10000000_00000000_00000000_00000000U;
                wPt[15] = 192;

                foreach (var item in cartesian)
                {
                    int j = 0;
                    foreach (var k in item)
                    {
                        wrd[mi[j]] = (uint)k;
                        j++;
                    }

                    wPt[0] = wrd[0] << 21 | wrd[1] << 10 | wrd[2] >> 1;
                    wPt[1] = wrd[2] << 31 | wrd[3] << 20 | wrd[4] << 9 | wrd[5] >> 2;
                    wPt[2] = wrd[5] << 30 | wrd[6] << 19 | wrd[7] << 8 | wrd[8] >> 3;
                    wPt[3] = wrd[8] << 29 | wrd[9] << 18 | wrd[10] << 7 | wrd[11] >> 4;
                    wPt[4] = wrd[11] << 28 | wrd[12] << 17 | wrd[13] << 6 | wrd[14] >> 5;
                    wPt[5] = wrd[14] << 27 | wrd[15] << 16 | wrd[16] << 5 | wrd[17] >> 6;

                    sha256.Init(hPt);
                    sha256.Compress24(hPt, wPt);

                    if ((wrd[17] & 0b11_1111) == hPt[0] >> 26)
                    {
                        int mnLen = 0;
                        for (int i = 0; i < 18; i++)
                        {
                            foreach (byte b in wordBytes[wrd[i]])
                            {
                                mnPt[mnLen++] = b;
                            }
                            mnPt[mnLen++] = SpaceByte;
                        }

                        if (SetBip32(sha512, mnPt, --mnLen, iPt, oPt))
                        {
                            return SetResult(mnLen);
                        }
                    }
                }
            }

            return false;
        }

        private unsafe void Loop15()
        {
            using Sha512Fo sha512 = new Sha512Fo();
            ulong[] ipad = new ulong[80];
            ulong[] opad = new ulong[80];

            using Sha256Fo sha256 = new Sha256Fo();
            var cartesian = CartesianProduct.Create(Enumerable.Repeat(Enumerable.Range(0, 2048), missCount));

            fixed (ulong* iPt = ipad, oPt = opad)
            fixed (uint* wPt = &sha256.w[0], hPt = &sha256.hashState[0], wrd = &wordIndexes[0])
            fixed (int* mi = &missingIndexes[0])
            fixed (byte* mnPt = &mnBytes[0])
            {
                wPt[5] = 0b10000000_00000000_00000000_00000000U;
                wPt[15] = 160;

                foreach (var item in cartesian)
                {
                    int j = 0;
                    foreach (var k in item)
                    {
                        wrd[mi[j]] = (uint)k;
                        j++;
                    }

                    wPt[0] = wrd[0] << 21 | wrd[1] << 10 | wrd[2] >> 1;
                    wPt[1] = wrd[2] << 31 | wrd[3] << 20 | wrd[4] << 9 | wrd[5] >> 2;
                    wPt[2] = wrd[5] << 30 | wrd[6] << 19 | wrd[7] << 8 | wrd[8] >> 3;
                    wPt[3] = wrd[8] << 29 | wrd[9] << 18 | wrd[10] << 7 | wrd[11] >> 4;
                    wPt[4] = wrd[11] << 28 | wrd[12] << 17 | wrd[13] << 6 | wrd[14] >> 5;

                    sha256.Init(hPt);
                    sha256.Compress20(hPt, wPt);

                    if ((wrd[14] & 0b1_1111) == hPt[0] >> 27)
                    {
                        int mnLen = 0;
                        for (int i = 0; i < 15; i++)
                        {
                            foreach (byte b in wordBytes[wrd[i]])
                            {
                                mnPt[mnLen++] = b;
                            }
                            mnPt[mnLen++] = SpaceByte;
                        }

                        if (SetBip32(sha512, mnPt, --mnLen, iPt, oPt))
                        {
                            SetResultParallel(mnPt, mnLen);
                        }
                    }
                }
            }
        }


        private unsafe void Loop12(int firstItem, int firstIndex, ParallelLoopState loopState)
        {
            var cartesian = CartesianProduct.Create(Enumerable.Repeat(Enumerable.Range(0, 2048), missCount - 1));
            using Sha512Fo sha512 = new Sha512Fo();
            ulong[] ipad = new ulong[80];
            ulong[] opad = new ulong[80];

            using Sha256Fo sha256 = new Sha256Fo();
            byte[] localMnBytes = new byte[mnBytes.Length];

            fixed (ulong* iPt = ipad, oPt = opad)
            fixed (uint* wPt = &sha256.w[0], hPt = &sha256.hashState[0], wrd = &wordIndexes[0])
            fixed (int* mi = &missingIndexes[1])
            fixed (byte* mnPt = &localMnBytes[0])
            {
                wPt[4] = 0b10000000_00000000_00000000_00000000U;
                wPt[15] = 128;

                wrd[firstIndex] = (uint)firstItem;

                foreach (var item in cartesian)
                {
                    if (loopState.IsStopped)
                    {
                        return;
                    }

                    int j = 0;
                    foreach (var k in item)
                    {
                        wrd[mi[j]] = (uint)k;
                        j++;
                    }

                    wPt[0] = wrd[0] << 21 | wrd[1] << 10 | wrd[2] >> 1;
                    wPt[1] = wrd[2] << 31 | wrd[3] << 20 | wrd[4] << 9 | wrd[5] >> 2;
                    wPt[2] = wrd[5] << 30 | wrd[6] << 19 | wrd[7] << 8 | wrd[8] >> 3;
                    wPt[3] = wrd[8] << 29 | wrd[9] << 18 | wrd[10] << 7 | wrd[11] >> 4;

                    sha256.Init(hPt);
                    sha256.Compress16(hPt, wPt);

                    if ((wrd[11] & 0b1111) == hPt[0] >> 28)
                    {
                        int mnLen = 0;
                        for (int i = 0; i < 12; i++)
                        {
                            foreach (byte b in wordBytes[wrd[i]])
                            {
                                mnPt[mnLen++] = b;
                            }
                            mnPt[mnLen++] = SpaceByte;
                        }

                        if (SetBip32(sha512, mnPt, --mnLen, iPt, oPt))
                        {
                            SetResultParallel(mnPt, mnLen);
                            loopState.Stop();
                            break;
                        }
                    }
                }
            }

            report.IncrementProgress();
        }

        private unsafe void SetResultParallel(byte* mnPt, int mnLen)
        {
            report.AddMessageSafe($"Found a key: {Encoding.UTF8.GetString(mnPt, mnLen)}");
            report.FoundAnyResult = true;
        }

        private unsafe void Loop12()
        {
            if (missCount > 1)
            {
                report.AddMessageSafe("Running in parallel.");
                report.SetProgressStep(2048);
                int firstIndex = missingIndexes[0];
                var cartesian = CartesianProduct.Create(Enumerable.Repeat(Enumerable.Range(0, 2048), missCount - 1));
                Parallel.For(0, 2048, (firstItem, state) => Loop12(firstItem, firstIndex, state));
            }
            else
            {
                // We can't call the same parallel method due to usage of LoopState so we at least optimize this by
                // avoiding the inner loop over the IEnumerable
                using Sha512Fo sha512 = new Sha512Fo();
                ulong[] ipad = new ulong[80];
                ulong[] opad = new ulong[80];

                using Sha256Fo sha256 = new Sha256Fo();

                int misIndex = missingIndexes[0];

                fixed (ulong* iPt = ipad, oPt = opad)
                fixed (uint* wPt = &sha256.w[0], hPt = &sha256.hashState[0], wrd = &wordIndexes[0])
                fixed (byte* mnPt = &mnBytes[0])
                {
                    wPt[4] = 0b10000000_00000000_00000000_00000000U;
                    wPt[15] = 128;

                    for (uint item = 0; item < 2048; item++)
                    {
                        wrd[misIndex] = item;

                        wPt[0] = wrd[0] << 21 | wrd[1] << 10 | wrd[2] >> 1;
                        wPt[1] = wrd[2] << 31 | wrd[3] << 20 | wrd[4] << 9 | wrd[5] >> 2;
                        wPt[2] = wrd[5] << 30 | wrd[6] << 19 | wrd[7] << 8 | wrd[8] >> 3;
                        wPt[3] = wrd[8] << 29 | wrd[9] << 18 | wrd[10] << 7 | wrd[11] >> 4;

                        sha256.Init(hPt);
                        sha256.Compress16(hPt, wPt);

                        if ((wrd[11] & 0b1111) == hPt[0] >> 28)
                        {
                            int mnLen = 0;
                            for (int i = 0; i < 12; i++)
                            {
                                foreach (byte b in wordBytes[wrd[i]])
                                {
                                    mnPt[mnLen++] = b;
                                }
                                mnPt[mnLen++] = SpaceByte;
                            }

                            if (SetBip32(sha512, mnPt, --mnLen, iPt, oPt))
                            {
                                SetResultParallel(mnPt, mnLen);
                                break;
                            }
                        }
                    }
                }
            }
        }



        private BigInteger GetTotalCount(int missCount) => BigInteger.Pow(2048, missCount);

        private bool TrySetEntropy(string mnemonic, MnemonicTypes mnType)
        {
            if (string.IsNullOrWhiteSpace(mnemonic))
            {
                return report.Fail("Mnemonic can not be null or empty.");
            }

            return report.Fail("Not yet implemented.");
        }


        public bool TrySetWordList(BIP0039.WordLists wl, out string[] allWords, out int maxWordLen)
        {
            try
            {
                allWords = BIP0039.GetAllWords(wl);
                maxWordLen = allWords.Max(w => Encoding.UTF8.GetBytes(w).Length);
                return true;
            }
            catch (Exception)
            {
                allWords = null;
                maxWordLen = 0;
                return false;
            }
        }

        /// <summary>
        /// Returns a buffer to hold byte array representation of the mnemonic with maximum possible length.
        /// Number of words * maximum word byte length + number of spaces in between
        /// </summary>
        /// <param name="seedLen"></param>
        /// <param name="maxWordLen"></param>
        /// <returns></returns>
        public byte[] GetSeedByte(int seedLen, int maxWordLen) => new byte[(seedLen * maxWordLen) + (seedLen - 1)];


        public bool TrySplitMnemonic(string mnemonic, char missingChar)
        {
            if (string.IsNullOrWhiteSpace(mnemonic))
            {
                return report.Fail("Mnemonic can not be null or empty.");
            }
            else
            {
                words = mnemonic.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (!allowedWordLengths.Contains(words.Length))
                {
                    return report.Fail("Invalid mnemonic length.");
                }

                string miss = new string(new char[] { missingChar });
                if (words.Any(s => s != miss && !allWords.Contains(s)))
                {
                    words = null;
                    return report.Fail("Given mnemonic contains invalid words.");
                }
                missCount = words.Count(s => s == miss);
                wordIndexes = new uint[words.Length];
                missingIndexes = new int[missCount];
                for (int i = 0, j = 0; i < words.Length; i++)
                {
                    if (words[i] != miss)
                    {
                        wordIndexes[i] = (uint)Array.IndexOf(allWords, words[i]);
                    }
                    else
                    {
                        missingIndexes[j] = i;
                        j++;
                    }
                }

                return true;
            }
        }

        public void SetPbkdf2Salt(string pass)
        {
            byte[] salt = Encoding.UTF8.GetBytes($"mnemonic{pass?.Normalize(NormalizationForm.FormKD)}");
            pbkdf2Salt = new byte[salt.Length + 4];
            Buffer.BlockCopy(salt, 0, pbkdf2Salt, 0, salt.Length);
            pbkdf2Salt[^1] = 1;
        }


        public async Task<bool> FindMissing(string mnemonic, char missChar, string pass, string extra, InputType extraType,
                                            string path, uint index, MnemonicTypes mnType, BIP0039.WordLists wl)
        {
            report.Init();

            // TODO: implement Electrum seeds too
            if (mnType != MnemonicTypes.BIP39)
                return report.Fail("Only BIP-39 seeds are supported for now.");

            if (!TrySetWordList(wl, out allWords, out int maxWordLen))
                return report.Fail($"Could not find {wl} word list among resources.");
            if (!inputService.IsMissingCharValid(missChar))
                return report.Fail("Missing character is not accepted.");
            if (!TrySplitMnemonic(mnemonic, missChar))
                return false;

            mnBytes = GetSeedByte(words.Length, maxWordLen);

            wordBytes = new Dictionary<uint, byte[]>(2048);
            for (uint i = 0; i < allWords.Length; i++)
            {
                wordBytes.Add(i, Encoding.UTF8.GetBytes(allWords[i]));
            }

            SetPbkdf2Salt(pass);
            try
            {
                this.path = new BIP0032Path(path);
                this.path.Add(index);
            }
            catch (Exception ex)
            {
                return report.Fail($"Invalid path ({ex.Message}).");
            }

            if (!inputService.TryGetCompareService(extraType, extra, out comparer))
            {
                return report.Fail("Invalid extra input or input type.");
            }

            report.AddMessageSafe($"There are {words.Length} words in the given mnemonic with {missCount} missing.");
            report.AddMessageSafe($"A total of {GetTotalCount(missCount):n0} mnemonics should be checked.");

            Stopwatch watch = Stopwatch.StartNew();

            await Task.Run(() =>
            {
                switch (words.Length)
                {
                    case 12:
                        Loop12();
                        break;
                    case 15:
                        Loop15();
                        break;
                    case 18:
                        Loop18();
                        break;
                    case 21:
                        Loop21();
                        break;
                    case 24:
                        Loop24();
                        break;
                }
                //words.Length switch
                //{
                //    //24 => Loop24(),
                //    //21 => Loop21(),
                //    //18 => Loop18(),
                //    //15 => Loop15(),
                //    _ => Loop12(),
                //};
            });

            watch.Stop();

            report.AddMessageSafe($"Elapsed time: {watch.Elapsed}");
            report.SetKeyPerSecSafe(GetTotalCount(missCount), watch.Elapsed.TotalSeconds);

            return report.Finalize();
        }


        public async Task<bool> FindPath(string mnemonic, string extra, MnemonicTypes mnType, BIP0039.WordLists wl, string passPhrase)
        {
            report.Init();

            if (!TrySetEntropy(mnemonic, mnType) && !TrySetWordList(wl, out allWords, out int maxWordLen))
            {
                return false;
            }
            if (string.IsNullOrWhiteSpace(extra))
            {
                return report.Fail("Additioan info can not be null or empty.");
            }
            else
            {

            }

            return report.Fail("Not yet implemented");
        }
    }
}
