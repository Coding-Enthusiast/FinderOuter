// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

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
    public enum WordLists
    {
        English,
        ChineseSimplified,
        ChineseTraditional,
        French,
        Italian,
        Japanese,
        Korean,
        Spanish
    }
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
        }


        HmacSha512 hmac = new HmacSha512();
        EllipticCurveCalculator calc = new EllipticCurveCalculator();
        private readonly IReport report;
        private readonly InputService inputService;
        private readonly int[] allowedWordLengths = { 12, 15, 18, 21, 24 };
        private uint[] wordIndexes;
        private int[] missingIndexes;
        private string[] allWords;
        private byte[] pbkdf2Salt;
        private BIP0032Path path;
        private ICompareService comparer;
        private readonly BigInteger order = new SecP256k1().N;
        private const ulong N0 = 0xBFD25E8C_D0364141;
        private const ulong N1 = 0xBAAEDCE6_AF48A03B;
        private const ulong N2 = 0xFFFFFFFF_FFFFFFFE;
        private const ulong N3 = 0xFFFFFFFF_FFFFFFFF;

        private int missCount;
        private string[] words;

        // Biggest word has 8 chars, biggest mnemonic has 24 words + 23 spaces
        // TODO: replace StringBuilder with a byte[] for an even faster result
        private const int SbCap = (8 * 24) + 23;


        public enum InputType
        {
            Address
        }

        readonly List<IEnumerable<int>> Final = new List<IEnumerable<int>>();
        private void SetResult(IEnumerable<int> item)
        {
            Final.Add(item);
        }

        private bool SetResult(byte[] mnBa)
        {
            report.AddMessageSafe($"Found a key: {Encoding.UTF8.GetString(mnBa)}");
            return true;
        }


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
                    BigInteger childInt = new BigInteger(sha.GetFirst32Bytes(hPt), true, true);

                    BigInteger child = kParent + childInt;
                    BigInteger reducedChild = child % order;
                    kParent = reducedChild;

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

        private unsafe void SetBip32(byte[] mnemonic)
        {
            // This is PBKDF2 and since there is only 1 block (dkLen/HmacLen=1) there is no loop here
            // and the salt is the "mnemonic+passPhrase" + blockNumber so it is fixed and has to be pre-computed.

            hmac.Key = mnemonic;

            // F()
            byte[] seed = new byte[hmac.OutputSize];
            // compute u1
            byte[] u1 = hmac.ComputeHash(pbkdf2Salt);

            Buffer.BlockCopy(u1, 0, seed, 0, u1.Length);

            // compute u2 to u(c-1) where c is iteration and each u is the hmac of previous u
            for (int j = 1; j < 2048; j++)
            {
                u1 = hmac.ComputeHash(u1);

                // result of F() is XOR sum of all u arrays
                int len = u1.Length;
                fixed (byte* first = seed, second = u1)
                {
                    if (Avx2.IsSupported)
                    {
                        var part1 = Avx2.Xor(Avx2.LoadVector256(first), Avx2.LoadVector256(second));
                        var part2 = Avx2.Xor(Avx2.LoadVector256(first + 32), Avx2.LoadVector256(second + 32));

                        Avx2.Store(first, part1);
                        Avx2.Store(first + 32, part2);
                    }
                    else
                    {
                        *(ulong*)first ^= *(ulong*)second;
                        *(ulong*)(first + 8) ^= *(ulong*)(second + 8);
                        *(ulong*)(first + 16) ^= *(ulong*)(second + 16);
                        *(ulong*)(first + 24) ^= *(ulong*)(second + 24);
                        *(ulong*)(first + 32) ^= *(ulong*)(second + 32);
                        *(ulong*)(first + 40) ^= *(ulong*)(second + 40);
                        *(ulong*)(first + 48) ^= *(ulong*)(second + 48);
                        *(ulong*)(first + 56) ^= *(ulong*)(second + 56);
                    }
                }
            }


            using BIP0032 bip = new BIP0032(seed);
            if (comparer.Compare(bip.GetPrivateKeys(path, 1, 0)[0].ToBytes()))
            {
                report.AddMessageSafe("Found a key.");
            }
        }


        private unsafe bool Loop24()
        {
            using Sha256Fo sha = new Sha256Fo();

            var cartesian = CartesianProduct.Create(Enumerable.Repeat(Enumerable.Range(0, 2048), missCount));

            fixed (uint* wPt = &sha.w[0], hPt = &sha.hashState[0], wrd = &wordIndexes[0])
            fixed (int* mi = &missingIndexes[0])
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

                    sha.Init(hPt);
                    sha.Compress32(hPt, wPt);

                    if ((byte)wrd[23] == hPt[0] >> 24)
                    {
                        StringBuilder sb = new StringBuilder(SbCap);
                        for (int i = 0; i < 24; i++)
                        {
                            sb.Append($"{allWords[wrd[i]]} ");
                        }
                        // no space at the end.
                        sb.Length--;

                        SetBip32(Encoding.UTF8.GetBytes(sb.ToString()));
                    }
                }
            }

            return Final.Count != 0;
        }

        private unsafe bool Loop21()
        {
            using Sha256Fo sha = new Sha256Fo();
            var cartesian = CartesianProduct.Create(Enumerable.Repeat(Enumerable.Range(0, 2048), missCount));

            fixed (uint* wPt = &sha.w[0], hPt = &sha.hashState[0], wrd = &wordIndexes[0])
            fixed (int* mi = &missingIndexes[0])
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

                    sha.Init(hPt);
                    sha.Compress28(hPt, wPt);

                    if ((wrd[20] & 0b111_1111) == hPt[0] >> 25)
                    {
                        StringBuilder sb = new StringBuilder(SbCap);
                        for (int i = 0; i < 21; i++)
                        {
                            sb.Append($"{allWords[wrd[i]]} ");
                        }
                        sb.Length--;

                        SetBip32(Encoding.UTF8.GetBytes(sb.ToString()));
                    }
                }
            }

            return Final.Count != 0;
        }

        private unsafe bool Loop18()
        {
            using Sha256Fo sha = new Sha256Fo();
            var cartesian = CartesianProduct.Create(Enumerable.Repeat(Enumerable.Range(0, 2048), missCount));

            fixed (uint* wPt = &sha.w[0], hPt = &sha.hashState[0], wrd = &wordIndexes[0])
            fixed (int* mi = &missingIndexes[0])
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

                    sha.Init(hPt);
                    sha.Compress24(hPt, wPt);

                    if ((wrd[17] & 0b11_1111) == hPt[0] >> 26)
                    {
                        StringBuilder sb = new StringBuilder(SbCap);
                        for (int i = 0; i < 18; i++)
                        {
                            sb.Append($"{allWords[wrd[i]]} ");
                        }
                        sb.Length--;

                        SetBip32(Encoding.UTF8.GetBytes(sb.ToString()));
                    }
                }
            }

            return Final.Count != 0;
        }

        private unsafe bool Loop15()
        {
            using Sha256Fo sha = new Sha256Fo();
            var cartesian = CartesianProduct.Create(Enumerable.Repeat(Enumerable.Range(0, 2048), missCount));

            fixed (uint* wPt = &sha.w[0], hPt = &sha.hashState[0], wrd = &wordIndexes[0])
            fixed (int* mi = &missingIndexes[0])
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

                    sha.Init(hPt);
                    sha.Compress20(hPt, wPt);

                    if ((wrd[14] & 0b1_1111) == hPt[0] >> 27)
                    {
                        StringBuilder sb = new StringBuilder(SbCap);
                        for (int i = 0; i < 15; i++)
                        {
                            sb.Append($"{allWords[wrd[i]]} ");
                        }
                        sb.Length--;

                        SetBip32(Encoding.UTF8.GetBytes(sb.ToString()));
                    }
                }
            }

            return Final.Count != 0;
        }

        private unsafe bool Loop12()
        {
            using Sha512Fo sha512 = new Sha512Fo();
            ulong[] ipad = new ulong[80];
            ulong[] opad = new ulong[80];

            using Sha256Fo sha256 = new Sha256Fo();
            var cartesian = CartesianProduct.Create(Enumerable.Repeat(Enumerable.Range(0, 2048), missCount));

            fixed (ulong* iPt = ipad, oPt = opad)
            fixed (uint* wPt = &sha256.w[0], hPt = &sha256.hashState[0], wrd = &wordIndexes[0])
            fixed (int* mi = &missingIndexes[0])
            {
                wPt[4] = 0b10000000_00000000_00000000_00000000U;
                wPt[15] = 128;

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

                    sha256.Init(hPt);
                    sha256.Compress16(hPt, wPt);

                    if ((wrd[11] & 0b1111) == hPt[0] >> 28)
                    {
                        StringBuilder sb = new StringBuilder(SbCap);
                        for (int i = 0; i < 12; i++)
                        {
                            sb.Append($"{allWords[wrd[i]]} ");
                        }
                        sb.Length--;

                        byte[] tempBaaaa = Encoding.UTF8.GetBytes(sb.ToString());

                        fixed (byte* mnPt = tempBaaaa)
                        {
                            if (SetBip32(sha512, mnPt, tempBaaaa.Length, iPt, oPt))
                            {
                                return SetResult(tempBaaaa);
                            }
                        }
                    }
                }
            }

            return false;
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


        public bool TrySetWordList(BIP0039.WordLists wl)
        {
            try
            {
                allWords = BIP0039.GetAllWords(wl);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

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

            if (!TrySetWordList(wl))
                return report.Fail($"Could not find {wl} word list among resources.");
            if (!inputService.IsMissingCharValid(missChar))
                return report.Fail("Missing character is not accepted.");
            if (!TrySplitMnemonic(mnemonic, missChar))
                return false;

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

            switch (extraType)
            {
                case InputType.Address:
                    comparer = new PrvToAddrCompComparer();
                    break;
                default:
                    return report.Fail("Input type is not defined.");
            }

            if (!comparer.Init(extra))
            {
                return report.Fail("Invalid extra data was provided.");
            }

            report.AddMessageSafe($"There are {words.Length} words in the given mnemonic with {missCount} missing.");
            report.AddMessageSafe($"A total of {GetTotalCount(missCount):n0} mnemonics should be checked.");

            Stopwatch watch = Stopwatch.StartNew();

            bool success = await Task.Run(() =>
            {
                return words.Length switch
                {
                    24 => Loop24(),
                    21 => Loop21(),
                    18 => Loop18(),
                    15 => Loop15(),
                    _ => Loop12(),
                };
            });

            watch.Stop();

            report.AddMessageSafe($"Elapsed time: {watch.Elapsed}");
            report.SetKeyPerSecSafe(GetTotalCount(missCount), watch.Elapsed.TotalSeconds);

            return report.Finalize(success);
        }


        public async Task<bool> FindPath(string mnemonic, string extra, MnemonicTypes mnType, BIP0039.WordLists wl, string passPhrase)
        {
            report.Init();

            if (!TrySetEntropy(mnemonic, mnType) && !TrySetWordList(wl))
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
