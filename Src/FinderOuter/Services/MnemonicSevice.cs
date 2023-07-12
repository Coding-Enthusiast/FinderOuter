// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using Autarkysoft.Bitcoin.Cryptography.EllipticCurve;
using Autarkysoft.Bitcoin.ImprovementProposals;
using FinderOuter.Backend.Hashing;
using FinderOuter.Models;
using FinderOuter.Services.Comparers;
using FinderOuter.Services.SearchSpaces;
using System;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Text;
using System.Threading.Tasks;

namespace FinderOuter.Services
{
    public class MnemonicSevice
    {
        public MnemonicSevice(IReport rep)
        {
            report = rep;
        }


        private readonly IReport report;

        private readonly byte[][] allWordsBytes = new byte[2048][];
        public const byte SpaceByte = 32;

        // TODO: this could be converted to SHA512 working vector and then leave the compression 
        //       to SetBip32() after setting HMAC key
        private byte[] pbkdf2Salt;
        private BIP0032Path path;
        private ICompareService comparer;
        private int maxMnBufferLen;
        private MnemonicSearchSpace searchSpace;


        public unsafe bool SetBip32(byte* mnPt, int mnLen, ulong* bigBuffer, ICompareService comparer)
        {
            // The process is: PBKDF2(password=UTF8(mnemonic), salt=UTF8("mnemonic+passphrase") -> BIP32 seed
            //                 BIP32 -> HMACSHA(data=seed, key=MasterKeyHashKey) -> HMACSHA(data=key|index, key=ChainCode)
            // All HMACSHAs are using 512 variant

            // *** PBKDF2 ***
            // dkLen/HmacLen=1 => only 1 block => no loop needed
            // Salt is the "mnemonic+passPhrase" + blockNumber(=1) => fixed and set during precomputing

            ulong* hPt = bigBuffer;
            ulong* wPt = hPt + Sha512Fo.HashStateSize;
            ulong* uPt = wPt + Sha512Fo.WorkingVectorSize;
            ulong* iPt = uPt + 80;
            ulong* oPt = iPt + 80;

            ulong* seedPt = oPt + 80;
            ulong* ihPt = seedPt + 8;
            ulong* ohPt = ihPt + 8;

            fixed (byte* dPt = &pbkdf2Salt[0])
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
                    Sha512Fo.Init(hPt);
                    Sha512Fo.CompressData(mnPt, mnLen, mnLen, hPt, wPt);
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
                Sha512Fo.Init(hPt);
                Sha512Fo.SetW(iPt);
                Sha512Fo.CompressBlockWithWSet(hPt, iPt);
                // Make a copy of hashState of inner-pad to be used in the loop below (explaination in the loop)
                *(Block64*)ihPt = *(Block64*)hPt;
                // Data length is unknown and an initial block of 128 bytes was already compressed
                Sha512Fo.CompressData(dPt, pbkdf2Salt.Length, pbkdf2Salt.Length + 128, hPt, wPt);
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

                Sha512Fo.Init(hPt);
                Sha512Fo.SetW(oPt);
                Sha512Fo.CompressBlockWithWSet(hPt, oPt);
                // Make a copy of hashState of outer-pad to be used in the loop below (explaination in the loop)
                *(Block64*)ohPt = *(Block64*)hPt;
                Sha512Fo.Compress192SecondBlock(hPt, wPt);

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
                    Sha512Fo.Compress192SecondBlock(hPt, uPt);

                    // 2. Compute SHA512(outer_pad | hash)
                    *(Block64*)wPt = *(Block64*)hPt;
                    // The rest of wPt is set above and is unchanged

                    // Replace: sha.Init(hPt); sha.CompressBlock(hPt, oPt); with line below:
                    *(Block64*)hPt = *(Block64*)ohPt;
                    Sha512Fo.Compress192SecondBlock(hPt, wPt);

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
                Sha512Fo.Init_InnerPad_Bitcoinseed(hPt);
                *(Block64*)wPt = *(Block64*)seedPt;
                // from wPt[8] to wPt[15] didn't change
                Sha512Fo.Compress192SecondBlock(hPt, wPt);

                // 2. Compute SHA512(outer_pad | hash)
                *(Block64*)wPt = *(Block64*)hPt; // ** Copy hashState before changing it **
                // from wPt[8] to wPt[15] didn't change
                Sha512Fo.Init_OuterPad_Bitcoinseed(hPt);
                Sha512Fo.Compress192SecondBlock(hPt, wPt);
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

                Scalar8x32 sclrParent = new(hPt, out bool overflow);
                if (overflow)
                {
                    return false;
                }

                foreach (uint index in path.Indexes)
                {
                    if ((index & 0x80000000) != 0) // IsHardened
                    {
                        // First _byte_ is zero
                        // private-key is the first 32 bytes (4 items) of hPt (total 33 bytes)
                        // 4 bytes index + SHA padding are also added
                        uPt[0] = (ulong)sclrParent.b7 << 24 | (ulong)sclrParent.b6 >> 8;
                        uPt[1] = (ulong)sclrParent.b6 << 56 | (ulong)sclrParent.b5 << 24 | (ulong)sclrParent.b4 >> 8;
                        uPt[2] = (ulong)sclrParent.b4 << 56 | (ulong)sclrParent.b3 << 24 | (ulong)sclrParent.b2 >> 8;
                        uPt[3] = (ulong)sclrParent.b2 << 56 | (ulong)sclrParent.b1 << 24 | (ulong)sclrParent.b0 >> 8;
                        uPt[4] = (ulong)sclrParent.b0 << 56 |
                                 (ulong)index << 24 |
                                 0b00000000_00000000_00000000_00000000_00000000_10000000_00000000_00000000UL;
                    }
                    else
                    {
                        Span<byte> pubkeyBytes = comparer.Calc.GetPubkey(sclrParent, true);
                        fixed (byte* pubXPt = &pubkeyBytes[0])
                        {
                            uPt[0] = (ulong)pubXPt[0] << 56 |
                                     (ulong)pubXPt[1] << 48 |
                                     (ulong)pubXPt[2] << 40 |
                                     (ulong)pubXPt[3] << 32 |
                                     (ulong)pubXPt[4] << 24 |
                                     (ulong)pubXPt[5] << 16 |
                                     (ulong)pubXPt[6] << 8 |
                                            pubXPt[7];
                            uPt[1] = (ulong)pubXPt[8] << 56 |
                                     (ulong)pubXPt[9] << 48 |
                                     (ulong)pubXPt[10] << 40 |
                                     (ulong)pubXPt[11] << 32 |
                                     (ulong)pubXPt[12] << 24 |
                                     (ulong)pubXPt[13] << 16 |
                                     (ulong)pubXPt[14] << 8 |
                                            pubXPt[15];
                            uPt[2] = (ulong)pubXPt[16] << 56 |
                                     (ulong)pubXPt[17] << 48 |
                                     (ulong)pubXPt[18] << 40 |
                                     (ulong)pubXPt[19] << 32 |
                                     (ulong)pubXPt[20] << 24 |
                                     (ulong)pubXPt[21] << 16 |
                                     (ulong)pubXPt[22] << 8 |
                                            pubXPt[23];
                            uPt[3] = (ulong)pubXPt[24] << 56 |
                                     (ulong)pubXPt[25] << 48 |
                                     (ulong)pubXPt[26] << 40 |
                                     (ulong)pubXPt[27] << 32 |
                                     (ulong)pubXPt[28] << 24 |
                                     (ulong)pubXPt[29] << 16 |
                                     (ulong)pubXPt[30] << 8 |
                                            pubXPt[31];
                            uPt[4] = (ulong)pubXPt[32] << 56 |
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

                    Sha512Fo.Init(hPt);
                    Sha512Fo.SetW(iPt);
                    Sha512Fo.CompressBlockWithWSet(hPt, iPt);
                    Sha512Fo.Compress165SecondBlock(hPt, uPt);

                    // 2. Compute SHA512(outer_pad | hash)
                    *(Block64*)wPt = *(Block64*)hPt;

                    // from wPt[8] to wPt[15] didn't change
                    Sha512Fo.Init(hPt);
                    Sha512Fo.SetW(oPt);
                    Sha512Fo.CompressBlockWithWSet(hPt, oPt);
                    Sha512Fo.Compress192SecondBlock(hPt, wPt);

                    // New private key is (parentPrvKey + int(hPt)) % order
                    // TODO: this is a bottleneck and needs to be replaced by a ModularUInt256 instance
                    sclrParent = sclrParent.Add(new Scalar8x32(hPt, out _), out _);
                }

                // Child extended key (private key + chianCode) should be set by adding the index to the end of the Path
                // and have been computed already
                hPt[0] = (ulong)sclrParent.b7 << 32 | sclrParent.b6;
                hPt[1] = (ulong)sclrParent.b5 << 32 | sclrParent.b4;
                hPt[2] = (ulong)sclrParent.b3 << 32 | sclrParent.b2;
                hPt[3] = (ulong)sclrParent.b1 << 32 | sclrParent.b0;

                return comparer.Compare(hPt);
            }
        }

        private unsafe void SetResultParallel(byte* mnPt, int mnLen)
        {
            report.AddMessageSafe($"Found the right words:{Environment.NewLine}{Encoding.UTF8.GetString(mnPt, mnLen)}");
            report.FoundAnyResult = true;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe bool MoveNext(Permutation* items, int len)
        {
            for (int i = len - 1; i >= 0; i--)
            {
                if (items[i].Increment())
                {
                    return true;
                }
            }

            return false;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe bool MoveNext(uint* items, int len)
        {
            for (int i = len - 1; i >= 0; --i)
            {
                items[i] += 1;

                if (items[i] == 2048)
                {
                    items[i] = 0;
                }
                else
                {
                    return true;
                }
            }

            return false;
        }


        private unsafe void Loop24(int firstItem, int firstIndex, ParallelLoopState loopState)
        {
            ICompareService localComp = comparer.Clone();

            byte[] mnBuffer = new byte[maxMnBufferLen];

            byte[][] localCopy = new byte[allWordsBytes.Length][];
            Array.Copy(allWordsBytes, localCopy, allWordsBytes.Length);

            uint[] localWIndex = new uint[searchSpace.wordIndexes.Length];
            Array.Copy(searchSpace.wordIndexes, localWIndex, searchSpace.wordIndexes.Length);

            ulong* bigBuffer = stackalloc ulong[Sha512Fo.UBufferSize + 80 + 80 + 80 + 8 + 8 + 8];
            uint* pt = stackalloc uint[Sha256Fo.UBufferSize];
            Permutation[] permutations = new Permutation[searchSpace.MissCount - 1];

            fixed (Permutation* itemsPt = &permutations[0])
            fixed (uint* wrd = &localWIndex[0])
            fixed (int* mi = &searchSpace.MissingIndexes[1])
            fixed (byte* mnPt = &mnBuffer[0])
            fixed (uint* valPt = &searchSpace.AllPermutationValues[0])
            {
                uint* tempPt = valPt;
                for (int i = 0; i < permutations.Length; i++)
                {
                    tempPt += searchSpace.PermutationCounts[i];
                    itemsPt[i] = new(searchSpace.PermutationCounts[i + 1], tempPt);
                }

                pt[16] = 0b10000000_00000000_00000000_00000000U;
                pt[23] = 256;
                wrd[firstIndex] = valPt[firstItem];

                do
                {
                    if (loopState.IsStopped)
                    {
                        return;
                    }

                    int j = 0;
                    foreach (Permutation item in permutations)
                    {
                        wrd[mi[j]] = item.GetValue();
                        j++;
                    }

                    pt[8] = wrd[0] << 21 | wrd[1] << 10 | wrd[2] >> 1;
                    pt[9] = wrd[2] << 31 | wrd[3] << 20 | wrd[4] << 9 | wrd[5] >> 2;
                    pt[10] = wrd[5] << 30 | wrd[6] << 19 | wrd[7] << 8 | wrd[8] >> 3;
                    pt[11] = wrd[8] << 29 | wrd[9] << 18 | wrd[10] << 7 | wrd[11] >> 4;
                    pt[12] = wrd[11] << 28 | wrd[12] << 17 | wrd[13] << 6 | wrd[14] >> 5;
                    pt[13] = wrd[14] << 27 | wrd[15] << 16 | wrd[16] << 5 | wrd[17] >> 6;
                    pt[14] = wrd[17] << 26 | wrd[18] << 15 | wrd[19] << 4 | wrd[20] >> 7;
                    pt[15] = wrd[20] << 25 | wrd[21] << 14 | wrd[22] << 3 | wrd[23] >> 8;

                    Sha256Fo.Init(pt);
                    Sha256Fo.Compress32(pt);

                    if ((byte)wrd[23] == pt[0] >> 24)
                    {
                        int mnLen = 0;
                        for (int i = 0; i < 24; i++)
                        {
                            byte[] temp = localCopy[wrd[i]];
                            Buffer.BlockCopy(temp, 0, mnBuffer, mnLen, temp.Length);
                            mnLen += temp.Length;
                        }

                        if (SetBip32(mnPt, mnLen - 1, bigBuffer, localComp))
                        {
                            SetResultParallel(mnPt, mnLen - 1);
                            loopState.Stop();
                            return;
                        }
                    }
                } while (MoveNext(itemsPt, permutations.Length));
            }

            report.IncrementProgress();
        }

        private unsafe void Loop24()
        {
            if (searchSpace.MissCount > 1)
            {
                report.SetProgressStep(searchSpace.PermutationCounts[0]);
                int firstIndex = searchSpace.MissingIndexes[0];
                ParallelOptions opts = report.BuildParallelOptions();
                Parallel.For(0, searchSpace.PermutationCounts[0], opts, (firstItem, state) => Loop24(firstItem, firstIndex, state));
            }
            else
            {
                int misIndex = searchSpace.MissingIndexes[0];
                byte[] mnBuffer = new byte[maxMnBufferLen];
                ulong* bigBuffer = stackalloc ulong[Sha512Fo.UBufferSize + 80 + 80 + 80 + 8 + 8 + 8];
                uint* pt = stackalloc uint[Sha256Fo.UBufferSize];
                fixed (uint* wrd = &searchSpace.wordIndexes[0])
                fixed (int* mi = &searchSpace.MissingIndexes[0])
                fixed (byte* mnPt = &mnBuffer[0])
                fixed (uint* valPt = &searchSpace.AllPermutationValues[0])
                {
                    Permutation item = new(searchSpace.PermutationCounts[0], valPt);

                    pt[16] = 0b10000000_00000000_00000000_00000000U;
                    pt[23] = 256;

                    do
                    {
                        wrd[misIndex] = item.GetValue();

                        // 0000_0000 0000_0000 0000_0111 1111_1111 -> 1111_1111 1110_0000 0000_0000 0000_0000
                        // 0000_0000 0000_0000 0000_0222 2222_2222 -> 0000_0000 0002_2222 2222_2200 0000_0000
                        // 0000_0000 0000_0000 0000_0333 3333_3333 -> 0000_0000 0000_0000 0000_0033 3333_3333 -> 3
                        //                                            1111_1111 1112_2222 2222_2233 3333_3333
                        pt[8] = wrd[0] << 21 | wrd[1] << 10 | wrd[2] >> 1;

                        // 0000_0000 0000_0000 0000_0000 0000_0003 -> 3000_0000 0000_0000 0000_0000 0000_0000
                        // 0000_0000 0000_0000 0000_0444 4444_4444 -> 0444_4444 4444_0000 0000_0000 0000_0000
                        // 0000_0000 0000_0000 0000_0555 5555_5555 -> 0000_0000 0000_5555 5555_5550 0000_0000
                        // 0000_0000 0000_0000 0000_0666 6666_6666 -> 0000_0000 0000_0000 0000_0006 6666_6666 -> 66
                        //                                            3444_4444 4444_5555 5555_5556 6666_6666
                        pt[9] = wrd[2] << 31 | wrd[3] << 20 | wrd[4] << 9 | wrd[5] >> 2;

                        // 0000_0000 0000_0000 0000_0000 0000_0066 -> 6600_0000 0000_0000 0000_0000 0000_0000
                        // 0000_0000 0000_0000 0000_0777 7777_7777 -> 0077_7777 7777_7000 0000_0000 0000_0000
                        // 0000_0000 0000_0000 0000_0888 8888_8888 -> 0000_0000 0000_0888 8888_8888 0000_0000
                        // 0000_0000 0000_0000 0000_0999 9999_9999 -> 0000_0000 0000_0000 0000_0000 9999_9999 -> 999
                        //                                            6677_7777 7777_7888 8888_8888 9999_9999
                        pt[10] = wrd[5] << 30 | wrd[6] << 19 | wrd[7] << 8 | wrd[8] >> 3;

                        // 0000_0000 0000_0000 0000_0000 0000_0999 -> 9990_0000 0000_0000 0000_0000 0000_0000
                        // 0000_0000 0000_0000 0000_0AAA AAAA_AAAA -> 000A_AAAA AAAA_AA00 0000_0000 0000_0000
                        // 0000_0000 0000_0000 0000_0BBB BBBB_BBBB -> 0000_0000 0000_00BB BBBB_BBBB B000_0000
                        // 0000_0000 0000_0000 0000_0CCC CCCC_CCCC -> 0000_0000 0000_0000 0000_0000 0CCC_CCCC -> CCCC
                        //                                            999A_AAAA AAAA_AABB BBBB_BBBB BCCC_CCCC
                        pt[11] = wrd[8] << 29 | wrd[9] << 18 | wrd[10] << 7 | wrd[11] >> 4;

                        // 0000_0000 0000_0000 0000_0000 0000_CCCC -> CCCC_0000 0000_0000 0000_0000 0000_0000
                        // 0000_0000 0000_0000 0000_0DDD DDDD_DDDD -> 0000_DDDD DDDD_DDD0 0000_0000 0000_0000
                        // 0000_0000 0000_0000 0000_0EEE EEEE_EEEE -> 0000_0000 0000_000E EEEE_EEEE EE00_0000
                        // 0000_0000 0000_0000 0000_0FFF FFFF_FFFF -> 0000_0000 0000_0000 0000_0000 00FF_FFFF -> FFFF_F
                        //                                            CCCC_DDDD DDDD_DDDE EEEE_EEEE EEFF_FFFF
                        pt[12] = wrd[11] << 28 | wrd[12] << 17 | wrd[13] << 6 | wrd[14] >> 5;

                        // 0000_0000 0000_0000 0000_0000 000F_FFFF -> FFFF_F000 0000_0000 0000_0000 0000_0000
                        // 0000_0000 0000_0000 0000_0GGG GGGG_GGGG -> 0000_0GGG GGGG_GGGG 0000_0000 0000_0000
                        // 0000_0000 0000_0000 0000_0HHH HHHH_HHHH -> 0000_0000 0000_0000 HHHH_HHHH HHH0_0000
                        // 0000_0000 0000_0000 0000_0III IIII_IIII -> 0000_0000 0000_0000 0000_0000 000I_IIII -> IIII_II
                        //                                         -> FFFF_FGGG GGGG_GGGG HHHH_HHHH HHHI_IIII
                        pt[13] = wrd[14] << 27 | wrd[15] << 16 | wrd[16] << 5 | wrd[17] >> 6;

                        // 0000_0000 0000_0000 0000_0000 00II_IIII -> IIII_II00 0000_0000 0000_0000 0000_0000
                        // 0000_0000 0000_0000 0000_0JJJ JJJJ_JJJJ -> 0000_00JJ JJJJ_JJJJ J000_0000 0000_0000
                        // 0000_0000 0000_0000 0000_0KKK KKKK_KKKK -> 0000_0000 0000_0000 0KKK_KKKK KKKK_0000
                        // 0000_0000 0000_0000 0000_0LLL LLLL_LLLL -> 0000_0000 0000_0000 0000_0000 0000_LLLL -> LLLL_LLL
                        //                                         -> IIII_IIJJ JJJJ_JJJJ JKKK_KKKK KKKK_LLLL
                        pt[14] = wrd[17] << 26 | wrd[18] << 15 | wrd[19] << 4 | wrd[20] >> 7;

                        // 0000_0000 0000_0000 0000_0000 0LLL_LLLL -> LLLL_LLL0 0000_0000 0000_0000 0000_0000
                        // 0000_0000 0000_0000 0000_0MMM MMMM_MMMM -> 0000_000M MMMM_MMMM MM00_0000 0000_0000
                        // 0000_0000 0000_0000 0000_0NNN NNNN_NNNN -> 0000_0000 0000_0000 00NN_NNNN NNNN_N000
                        // 0000_0000 0000_0000 0000_0OOO OOOO_OOOO -> 0000_0000 0000_0000 0000_0000 0000_0OOO -> OOOO_OOOO
                        //                                         -> LLLL_LLLM MMMM_MMMM MMNN_NNNN NNNN_NOOO
                        pt[15] = wrd[20] << 25 | wrd[21] << 14 | wrd[22] << 3 | wrd[23] >> 8;

                        Sha256Fo.Init(pt);
                        Sha256Fo.Compress32(pt);

                        if ((byte)wrd[23] == pt[0] >> 24)
                        {
                            int mnLen = 0;
                            for (int i = 0; i < 24; i++)
                            {
                                byte[] temp = allWordsBytes[wrd[i]];
                                Buffer.BlockCopy(temp, 0, mnBuffer, mnLen, temp.Length);
                                mnLen += temp.Length;
                            }

                            if (SetBip32(mnPt, mnLen - 1, bigBuffer, comparer))
                            {
                                SetResultParallel(mnPt, mnLen - 1);
                                return;
                            }
                        }
                    } while (item.Increment());
                }
            }
        }


        private unsafe void Loop21(int firstItem, int firstIndex, ParallelLoopState loopState)
        {
            ICompareService localComp = comparer.Clone();

            byte[] mnBuffer = new byte[maxMnBufferLen];

            byte[][] localCopy = new byte[allWordsBytes.Length][];
            Array.Copy(allWordsBytes, localCopy, allWordsBytes.Length);

            uint[] localWIndex = new uint[searchSpace.wordIndexes.Length];
            Array.Copy(searchSpace.wordIndexes, localWIndex, searchSpace.wordIndexes.Length);

            ulong* bigBuffer = stackalloc ulong[Sha512Fo.UBufferSize + 80 + 80 + 80 + 8 + 8 + 8];
            uint* pt = stackalloc uint[Sha256Fo.UBufferSize];
            Permutation[] permutations = new Permutation[searchSpace.MissCount - 1];

            fixed (Permutation* itemsPt = &permutations[0])
            fixed (uint* wrd = &localWIndex[0])
            fixed (int* mi = &searchSpace.MissingIndexes[1])
            fixed (byte* mnPt = &mnBuffer[0])
            fixed (uint* valPt = &searchSpace.AllPermutationValues[0])
            {
                uint* tempPt = valPt;
                for (int i = 0; i < permutations.Length; i++)
                {
                    tempPt += searchSpace.PermutationCounts[i];
                    itemsPt[i] = new(searchSpace.PermutationCounts[i + 1], tempPt);
                }

                pt[15] = 0b10000000_00000000_00000000_00000000U;
                pt[23] = 224;
                wrd[firstIndex] = valPt[firstItem];

                do
                {
                    if (loopState.IsStopped)
                    {
                        return;
                    }

                    int j = 0;
                    foreach (Permutation item in permutations)
                    {
                        wrd[mi[j]] = item.GetValue();
                        j++;
                    }

                    pt[8] = wrd[0] << 21 | wrd[1] << 10 | wrd[2] >> 1;
                    pt[9] = wrd[2] << 31 | wrd[3] << 20 | wrd[4] << 9 | wrd[5] >> 2;
                    pt[10] = wrd[5] << 30 | wrd[6] << 19 | wrd[7] << 8 | wrd[8] >> 3;
                    pt[11] = wrd[8] << 29 | wrd[9] << 18 | wrd[10] << 7 | wrd[11] >> 4;
                    pt[12] = wrd[11] << 28 | wrd[12] << 17 | wrd[13] << 6 | wrd[14] >> 5;
                    pt[13] = wrd[14] << 27 | wrd[15] << 16 | wrd[16] << 5 | wrd[17] >> 6;
                    pt[14] = wrd[17] << 26 | wrd[18] << 15 | wrd[19] << 4 | wrd[20] >> 7;

                    Sha256Fo.Init(pt);
                    Sha256Fo.Compress28(pt);

                    if ((wrd[20] & 0b111_1111) == pt[0] >> 25)
                    {
                        int mnLen = 0;
                        for (int i = 0; i < 21; i++)
                        {
                            byte[] temp = localCopy[wrd[i]];
                            Buffer.BlockCopy(temp, 0, mnBuffer, mnLen, temp.Length);
                            mnLen += temp.Length;
                        }

                        if (SetBip32(mnPt, mnLen - 1, bigBuffer, localComp))
                        {
                            SetResultParallel(mnPt, mnLen - 1);
                            loopState.Stop();
                            return;
                        }
                    }
                } while (MoveNext(itemsPt, permutations.Length));
            }

            report.IncrementProgress();
        }

        private unsafe void Loop21()
        {
            if (searchSpace.MissCount > 1)
            {
                report.SetProgressStep(searchSpace.PermutationCounts[0]);
                int firstIndex = searchSpace.MissingIndexes[0];
                ParallelOptions opts = report.BuildParallelOptions();
                Parallel.For(0, searchSpace.PermutationCounts[0], opts, (firstItem, state) => Loop21(firstItem, firstIndex, state));
            }
            else
            {
                int misIndex = searchSpace.MissingIndexes[0];
                byte[] mnBuffer = new byte[maxMnBufferLen];
                ulong* bigBuffer = stackalloc ulong[Sha512Fo.UBufferSize + 80 + 80 + 80 + 8 + 8 + 8];
                uint* pt = stackalloc uint[Sha256Fo.UBufferSize];
                fixed (uint* wrd = &searchSpace.wordIndexes[0])
                fixed (byte* mnPt = &mnBuffer[0])
                fixed (uint* valPt = &searchSpace.AllPermutationValues[0])
                {
                    Permutation item = new(searchSpace.PermutationCounts[0], valPt);

                    pt[15] = 0b10000000_00000000_00000000_00000000U;
                    pt[23] = 224;

                    do
                    {
                        wrd[misIndex] = item.GetValue();

                        pt[8] = wrd[0] << 21 | wrd[1] << 10 | wrd[2] >> 1;
                        pt[9] = wrd[2] << 31 | wrd[3] << 20 | wrd[4] << 9 | wrd[5] >> 2;
                        pt[10] = wrd[5] << 30 | wrd[6] << 19 | wrd[7] << 8 | wrd[8] >> 3;
                        pt[11] = wrd[8] << 29 | wrd[9] << 18 | wrd[10] << 7 | wrd[11] >> 4;
                        pt[12] = wrd[11] << 28 | wrd[12] << 17 | wrd[13] << 6 | wrd[14] >> 5;
                        pt[13] = wrd[14] << 27 | wrd[15] << 16 | wrd[16] << 5 | wrd[17] >> 6;
                        pt[14] = wrd[17] << 26 | wrd[18] << 15 | wrd[19] << 4 | wrd[20] >> 7;

                        Sha256Fo.Init(pt);
                        Sha256Fo.Compress28(pt);

                        if ((wrd[20] & 0b111_1111) == pt[0] >> 25)
                        {
                            int mnLen = 0;
                            for (int i = 0; i < 21; i++)
                            {
                                byte[] temp = allWordsBytes[wrd[i]];
                                Buffer.BlockCopy(temp, 0, mnBuffer, mnLen, temp.Length);
                                mnLen += temp.Length;
                            }

                            if (SetBip32(mnPt, mnLen - 1, bigBuffer, comparer))
                            {
                                SetResultParallel(mnPt, mnLen - 1);
                                break;
                            }
                        }
                    } while (item.Increment());
                }
            }
        }


        private unsafe void Loop18(int firstItem, int firstIndex, ParallelLoopState loopState)
        {
            ICompareService localComp = comparer.Clone();

            byte[] mnBuffer = new byte[maxMnBufferLen];

            byte[][] localCopy = new byte[allWordsBytes.Length][];
            Array.Copy(allWordsBytes, localCopy, allWordsBytes.Length);

            uint[] localWIndex = new uint[searchSpace.wordIndexes.Length];
            Array.Copy(searchSpace.wordIndexes, localWIndex, searchSpace.wordIndexes.Length);

            ulong* bigBuffer = stackalloc ulong[Sha512Fo.UBufferSize + 80 + 80 + 80 + 8 + 8 + 8];
            uint* pt = stackalloc uint[Sha256Fo.UBufferSize];
            Permutation[] permutations = new Permutation[searchSpace.MissCount - 1];

            fixed (Permutation* itemsPt = &permutations[0])
            fixed (uint* wrd = &localWIndex[0])
            fixed (int* mi = &searchSpace.MissingIndexes[1])
            fixed (byte* mnPt = &mnBuffer[0])
            fixed (uint* valPt = &searchSpace.AllPermutationValues[0])
            {
                uint* tempPt = valPt;
                for (int i = 0; i < permutations.Length; i++)
                {
                    tempPt += searchSpace.PermutationCounts[i];
                    itemsPt[i] = new(searchSpace.PermutationCounts[i + 1], tempPt);
                }

                pt[14] = 0b10000000_00000000_00000000_00000000U;
                pt[23] = 192;
                wrd[firstIndex] = valPt[firstItem];

                do
                {
                    if (loopState.IsStopped)
                    {
                        return;
                    }

                    int j = 0;
                    foreach (Permutation item in permutations)
                    {
                        wrd[mi[j]] = item.GetValue();
                        j++;
                    }

                    pt[8] = wrd[0] << 21 | wrd[1] << 10 | wrd[2] >> 1;
                    pt[9] = wrd[2] << 31 | wrd[3] << 20 | wrd[4] << 9 | wrd[5] >> 2;
                    pt[10] = wrd[5] << 30 | wrd[6] << 19 | wrd[7] << 8 | wrd[8] >> 3;
                    pt[11] = wrd[8] << 29 | wrd[9] << 18 | wrd[10] << 7 | wrd[11] >> 4;
                    pt[12] = wrd[11] << 28 | wrd[12] << 17 | wrd[13] << 6 | wrd[14] >> 5;
                    pt[13] = wrd[14] << 27 | wrd[15] << 16 | wrd[16] << 5 | wrd[17] >> 6;

                    Sha256Fo.Init(pt);
                    Sha256Fo.Compress24(pt);

                    if ((wrd[17] & 0b11_1111) == pt[0] >> 26)
                    {
                        int mnLen = 0;
                        for (int i = 0; i < 18; i++)
                        {
                            byte[] temp = localCopy[wrd[i]];
                            Buffer.BlockCopy(temp, 0, mnBuffer, mnLen, temp.Length);
                            mnLen += temp.Length;
                        }

                        if (SetBip32(mnPt, mnLen - 1, bigBuffer, localComp))
                        {
                            SetResultParallel(mnPt, mnLen - 1);
                            loopState.Stop();
                            return;
                        }
                    }
                } while (MoveNext(itemsPt, permutations.Length));
            }

            report.IncrementProgress();
        }

        private unsafe void Loop18()
        {
            if (searchSpace.MissCount > 1)
            {
                report.SetProgressStep(searchSpace.PermutationCounts[0]);
                int firstIndex = searchSpace.MissingIndexes[0];
                ParallelOptions opts = report.BuildParallelOptions();
                Parallel.For(0, searchSpace.PermutationCounts[0], opts, (firstItem, state) => Loop18(firstItem, firstIndex, state));
            }
            else
            {
                int misIndex = searchSpace.MissingIndexes[0];
                byte[] mnBuffer = new byte[maxMnBufferLen];
                ulong* bigBuffer = stackalloc ulong[Sha512Fo.UBufferSize + 80 + 80 + 80 + 8 + 8 + 8];
                uint* pt = stackalloc uint[Sha256Fo.UBufferSize];
                fixed (uint* wrd = &searchSpace.wordIndexes[0])
                fixed (byte* mnPt = &mnBuffer[0])
                fixed (uint* valPt = &searchSpace.AllPermutationValues[0])
                {
                    Permutation item = new(searchSpace.PermutationCounts[0], valPt);

                    pt[14] = 0b10000000_00000000_00000000_00000000U;
                    pt[23] = 192;

                    do
                    {
                        wrd[misIndex] = item.GetValue();

                        pt[8] = wrd[0] << 21 | wrd[1] << 10 | wrd[2] >> 1;
                        pt[9] = wrd[2] << 31 | wrd[3] << 20 | wrd[4] << 9 | wrd[5] >> 2;
                        pt[10] = wrd[5] << 30 | wrd[6] << 19 | wrd[7] << 8 | wrd[8] >> 3;
                        pt[11] = wrd[8] << 29 | wrd[9] << 18 | wrd[10] << 7 | wrd[11] >> 4;
                        pt[12] = wrd[11] << 28 | wrd[12] << 17 | wrd[13] << 6 | wrd[14] >> 5;
                        pt[13] = wrd[14] << 27 | wrd[15] << 16 | wrd[16] << 5 | wrd[17] >> 6;

                        Sha256Fo.Init(pt);
                        Sha256Fo.Compress24(pt);

                        if ((wrd[17] & 0b11_1111) == pt[0] >> 26)
                        {
                            int mnLen = 0;
                            for (int i = 0; i < 18; i++)
                            {
                                byte[] temp = allWordsBytes[wrd[i]];
                                Buffer.BlockCopy(temp, 0, mnBuffer, mnLen, temp.Length);
                                mnLen += temp.Length;
                            }

                            if (SetBip32(mnPt, mnLen - 1, bigBuffer, comparer))
                            {
                                SetResultParallel(mnPt, mnLen - 1);
                                break;
                            }
                        }
                    } while (item.Increment());
                }
            }
        }


        private unsafe void Loop15(int firstItem, int firstIndex, ParallelLoopState loopState)
        {
            ICompareService localComp = comparer.Clone();

            byte[] mnBuffer = new byte[maxMnBufferLen];

            byte[][] localCopy = new byte[allWordsBytes.Length][];
            Array.Copy(allWordsBytes, localCopy, allWordsBytes.Length);

            uint[] localWIndex = new uint[searchSpace.wordIndexes.Length];
            Array.Copy(searchSpace.wordIndexes, localWIndex, searchSpace.wordIndexes.Length);

            ulong* bigBuffer = stackalloc ulong[Sha512Fo.UBufferSize + 80 + 80 + 80 + 8 + 8 + 8];
            uint* pt = stackalloc uint[Sha256Fo.UBufferSize];
            Permutation[] permutations = new Permutation[searchSpace.MissCount - 1];

            fixed (Permutation* itemsPt = &permutations[0])
            fixed (uint* wrd = &localWIndex[0])
            fixed (int* mi = &searchSpace.MissingIndexes[1])
            fixed (byte* mnPt = &mnBuffer[0])
            fixed (uint* valPt = &searchSpace.AllPermutationValues[0])
            {
                uint* tempPt = valPt;
                for (int i = 0; i < permutations.Length; i++)
                {
                    tempPt += searchSpace.PermutationCounts[i];
                    itemsPt[i] = new(searchSpace.PermutationCounts[i + 1], tempPt);
                }

                pt[13] = 0b10000000_00000000_00000000_00000000U;
                pt[23] = 160;
                wrd[firstIndex] = valPt[firstItem];

                do
                {
                    if (loopState.IsStopped)
                    {
                        return;
                    }

                    int j = 0;
                    foreach (Permutation item in permutations)
                    {
                        wrd[mi[j]] = item.GetValue();
                        j++;
                    }

                    pt[8] = wrd[0] << 21 | wrd[1] << 10 | wrd[2] >> 1;
                    pt[9] = wrd[2] << 31 | wrd[3] << 20 | wrd[4] << 9 | wrd[5] >> 2;
                    pt[10] = wrd[5] << 30 | wrd[6] << 19 | wrd[7] << 8 | wrd[8] >> 3;
                    pt[11] = wrd[8] << 29 | wrd[9] << 18 | wrd[10] << 7 | wrd[11] >> 4;
                    pt[12] = wrd[11] << 28 | wrd[12] << 17 | wrd[13] << 6 | wrd[14] >> 5;

                    Sha256Fo.Init(pt);
                    Sha256Fo.Compress20(pt);

                    if ((wrd[14] & 0b1_1111) == pt[0] >> 27)
                    {
                        int mnLen = 0;
                        for (int i = 0; i < 15; i++)
                        {
                            byte[] temp = localCopy[wrd[i]];
                            Buffer.BlockCopy(temp, 0, mnBuffer, mnLen, temp.Length);
                            mnLen += temp.Length;
                        }

                        if (SetBip32(mnPt, mnLen - 1, bigBuffer, localComp))
                        {
                            SetResultParallel(mnPt, mnLen - 1);
                            loopState.Stop();
                            return;
                        }
                    }
                } while (MoveNext(itemsPt, permutations.Length));
            }

            report.IncrementProgress();
        }

        private unsafe void Loop15()
        {
            if (searchSpace.MissCount > 1)
            {
                report.SetProgressStep(searchSpace.PermutationCounts[0]);
                int firstIndex = searchSpace.MissingIndexes[0];
                ParallelOptions opts = report.BuildParallelOptions();
                Parallel.For(0, searchSpace.PermutationCounts[0], opts, (firstItem, state) => Loop15(firstItem, firstIndex, state));
            }
            else
            {
                int misIndex = searchSpace.MissingIndexes[0];
                byte[] mnBuffer = new byte[maxMnBufferLen];
                ulong* bigBuffer = stackalloc ulong[Sha512Fo.UBufferSize + 80 + 80 + 80 + 8 + 8 + 8];
                uint* pt = stackalloc uint[Sha256Fo.UBufferSize];
                fixed (uint* wrd = &searchSpace.wordIndexes[0])
                fixed (byte* mnPt = &mnBuffer[0])
                fixed (uint* valPt = &searchSpace.AllPermutationValues[0])
                {
                    pt[13] = 0b10000000_00000000_00000000_00000000U;
                    pt[23] = 160;

                    Permutation item = new(searchSpace.PermutationCounts[0], valPt);

                    do
                    {
                        wrd[misIndex] = item.GetValue();

                        pt[8] = wrd[0] << 21 | wrd[1] << 10 | wrd[2] >> 1;
                        pt[9] = wrd[2] << 31 | wrd[3] << 20 | wrd[4] << 9 | wrd[5] >> 2;
                        pt[10] = wrd[5] << 30 | wrd[6] << 19 | wrd[7] << 8 | wrd[8] >> 3;
                        pt[11] = wrd[8] << 29 | wrd[9] << 18 | wrd[10] << 7 | wrd[11] >> 4;
                        pt[12] = wrd[11] << 28 | wrd[12] << 17 | wrd[13] << 6 | wrd[14] >> 5;

                        Sha256Fo.Init(pt);
                        Sha256Fo.Compress20(pt);

                        if ((wrd[14] & 0b1_1111) == pt[0] >> 27)
                        {
                            int mnLen = 0;
                            for (int i = 0; i < 15; i++)
                            {
                                byte[] temp = allWordsBytes[wrd[i]];
                                Buffer.BlockCopy(temp, 0, mnBuffer, mnLen, temp.Length);
                                mnLen += temp.Length;
                            }

                            if (SetBip32(mnPt, mnLen - 1, bigBuffer, comparer))
                            {
                                SetResultParallel(mnPt, mnLen - 1);
                                break;
                            }
                        }
                    } while (item.Increment());
                }
            }
        }



        private unsafe void Loop12(int firstItem, int firstIndex, ParallelLoopState loopState)
        {
            ICompareService localComp = comparer.Clone();

            byte[] mnBuffer = new byte[maxMnBufferLen];

            byte[][] localCopy = new byte[allWordsBytes.Length][];
            Array.Copy(allWordsBytes, localCopy, allWordsBytes.Length);

            uint[] localWIndex = new uint[searchSpace.wordIndexes.Length];
            Array.Copy(searchSpace.wordIndexes, localWIndex, searchSpace.wordIndexes.Length);

            ulong* bigBuffer = stackalloc ulong[Sha512Fo.UBufferSize + 80 + 80 + 80 + 8 + 8 + 8];
            uint* pt = stackalloc uint[Sha256Fo.UBufferSize];
            Permutation[] permutations = new Permutation[searchSpace.MissCount - 1];

            fixed (Permutation* itemsPt = &permutations[0])
            fixed (uint* wrd = &localWIndex[0])
            fixed (int* mi = &searchSpace.MissingIndexes[1])
            fixed (byte* mnPt = &mnBuffer[0])
            fixed (uint* valPt = &searchSpace.AllPermutationValues[0])
            {
                uint* tempPt = valPt;
                for (int i = 0; i < permutations.Length; i++)
                {
                    tempPt += searchSpace.PermutationCounts[i];
                    itemsPt[i] = new(searchSpace.PermutationCounts[i + 1], tempPt);
                }

                pt[12] = 0b10000000_00000000_00000000_00000000U;
                pt[23] = 128;

                wrd[firstIndex] = valPt[firstItem];

                do
                {
                    if (loopState.IsStopped)
                    {
                        return;
                    }

                    int j = 0;
                    foreach (Permutation item in permutations)
                    {
                        wrd[mi[j]] = item.GetValue();
                        j++;
                    }

                    pt[8] = wrd[0] << 21 | wrd[1] << 10 | wrd[2] >> 1;
                    pt[9] = wrd[2] << 31 | wrd[3] << 20 | wrd[4] << 9 | wrd[5] >> 2;
                    pt[10] = wrd[5] << 30 | wrd[6] << 19 | wrd[7] << 8 | wrd[8] >> 3;
                    pt[11] = wrd[8] << 29 | wrd[9] << 18 | wrd[10] << 7 | wrd[11] >> 4;

                    Sha256Fo.Init(pt);
                    Sha256Fo.Compress16(pt);

                    if ((wrd[11] & 0b1111) == pt[0] >> 28)
                    {
                        int mnLen = 0;
                        for (int i = 0; i < 12; i++)
                        {
                            byte[] temp = localCopy[wrd[i]];
                            Buffer.BlockCopy(temp, 0, mnBuffer, mnLen, temp.Length);
                            mnLen += temp.Length;
                        }

                        if (SetBip32(mnPt, mnLen - 1, bigBuffer, localComp))
                        {
                            SetResultParallel(mnPt, mnLen - 1);
                            loopState.Stop();
                            return;
                        }
                    }
                } while (MoveNext(itemsPt, permutations.Length));
            }

            report.IncrementProgress();
        }

        private unsafe void Loop12()
        {
            if (searchSpace.MissCount > 1)
            {
                report.SetProgressStep(searchSpace.PermutationCounts[0]);
                int firstIndex = searchSpace.MissingIndexes[0];
                ParallelOptions opts = report.BuildParallelOptions();
                Parallel.For(0, searchSpace.PermutationCounts[0], opts, (firstItem, state) => Loop12(firstItem, firstIndex, state));
            }
            else
            {
                // We can't call the same parallel method due to usage of LoopState so we at least optimize this by
                // avoiding the inner loop over the IEnumerable
                int misIndex = searchSpace.MissingIndexes[0];
                byte[] mnBuffer = new byte[maxMnBufferLen];
                ulong* bigBuffer = stackalloc ulong[Sha512Fo.UBufferSize + 80 + 80 + 80 + 8 + 8 + 8];
                uint* pt = stackalloc uint[Sha256Fo.UBufferSize];
                fixed (uint* wrd = &searchSpace.wordIndexes[0])
                fixed (byte* mnPt = &mnBuffer[0])
                fixed (uint* valPt = &searchSpace.AllPermutationValues[0])
                {
                    Permutation item = new(searchSpace.PermutationCounts[0], valPt);

                    pt[12] = 0b10000000_00000000_00000000_00000000U;
                    pt[23] = 128;

                    do
                    {
                        wrd[misIndex] = item.GetValue();

                        pt[8] = wrd[0] << 21 | wrd[1] << 10 | wrd[2] >> 1;
                        pt[9] = wrd[2] << 31 | wrd[3] << 20 | wrd[4] << 9 | wrd[5] >> 2;
                        pt[10] = wrd[5] << 30 | wrd[6] << 19 | wrd[7] << 8 | wrd[8] >> 3;
                        pt[11] = wrd[8] << 29 | wrd[9] << 18 | wrd[10] << 7 | wrd[11] >> 4;

                        Sha256Fo.Init(pt);
                        Sha256Fo.Compress16(pt);

                        if ((wrd[11] & 0b1111) == pt[0] >> 28)
                        {
                            int mnLen = 0;
                            for (int i = 0; i < 12; i++)
                            {
                                byte[] temp = allWordsBytes[wrd[i]];
                                Buffer.BlockCopy(temp, 0, mnBuffer, mnLen, temp.Length);
                                mnLen += temp.Length;
                            }

                            if (SetBip32(mnPt, mnLen - 1, bigBuffer, comparer))
                            {
                                SetResultParallel(mnPt, mnLen - 1);
                                break;
                            }
                        }
                    } while (item.Increment());
                }
            }
        }



        private unsafe void LoopElectrum(int firstItem, int firstIndex, ulong mask, ulong expected, ParallelLoopState loopState)
        {
            ICompareService localComp = comparer.Clone();

            byte[] mnBuffer = new byte[maxMnBufferLen];

            byte[][] localCopy = new byte[allWordsBytes.Length][];
            Array.Copy(allWordsBytes, localCopy, allWordsBytes.Length);

            uint[] localWIndex = new uint[searchSpace.wordIndexes.Length];
            Array.Copy(searchSpace.wordIndexes, localWIndex, searchSpace.wordIndexes.Length);

            ulong* bigBuffer = stackalloc ulong[Sha512Fo.UBufferSize + 80 + 80 + 80 + 8 + 8 + 8];
            ulong* hPt = bigBuffer;
            ulong* wPt = hPt + Sha512Fo.HashStateSize;
            Permutation[] permutations = new Permutation[searchSpace.MissCount - 1];

            fixed (Permutation* itemsPt = &permutations[0])
            fixed (uint* wrd = &localWIndex[0])
            fixed (int* mi = &searchSpace.MissingIndexes[1])
            fixed (byte* mnPt = &mnBuffer[0])
            fixed (uint* valPt = &searchSpace.AllPermutationValues[0])
            {
                uint* tempPt = valPt;
                for (int i = 0; i < permutations.Length; i++)
                {
                    tempPt += searchSpace.PermutationCounts[i];
                    itemsPt[i] = new(searchSpace.PermutationCounts[i + 1], tempPt);
                }

                wrd[firstIndex] = valPt[firstItem];

                do
                {
                    if (loopState.IsStopped)
                    {
                        return;
                    }

                    int j = 0;
                    foreach (Permutation item in permutations)
                    {
                        wrd[mi[j]] = item.GetValue();
                        j++;
                    }

                    int mnLen = 0;
                    for (int i = 0; i < 12; i++)
                    {
                        byte[] temp = localCopy[wrd[i]];
                        Buffer.BlockCopy(temp, 0, mnBuffer, mnLen, temp.Length);
                        mnLen += temp.Length;
                    }

                    // Remove last space
                    mnLen--;

                    // Compute HMACSHA512("Seed version", normalized_mnemonic)
                    // 1. Compute SHA512(inner_pad | data)
                    Sha512Fo.Init_InnerPad_SeedVersion(hPt);
                    Sha512Fo.SetW(wPt);
                    Sha512Fo.CompressData(mnPt, mnLen, mnLen + 128, hPt, wPt);

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
                    Sha512Fo.Init_OuterPad_SeedVersion(hPt);
                    Sha512Fo.Compress192SecondBlock(hPt, wPt);

                    if ((hPt[0] & mask) == expected && SetBip32(mnPt, mnLen, bigBuffer, localComp))
                    {
                        SetResultParallel(mnPt, mnLen);
                        loopState.Stop();
                        break;
                    }
                } while (MoveNext(itemsPt, permutations.Length));
            }

            report.IncrementProgress();
        }

        private unsafe void LoopElectrum(ElectrumMnemonic.MnemonicType mnType)
        {
            ulong mask = mnType switch
            {
                ElectrumMnemonic.MnemonicType.Standard => 0xff000000_00000000,
                ElectrumMnemonic.MnemonicType.Undefined => 0,
                ElectrumMnemonic.MnemonicType.SegWit => 0xfff00000_00000000,
                ElectrumMnemonic.MnemonicType.Legacy2Fa => 0xfff00000_00000000,
                ElectrumMnemonic.MnemonicType.SegWit2Fa => 0xfff00000_00000000,
                _ => 0
            };

            ulong expected = mnType switch
            {
                ElectrumMnemonic.MnemonicType.Standard => 0x01000000_00000000,
                ElectrumMnemonic.MnemonicType.Undefined => 0,
                ElectrumMnemonic.MnemonicType.SegWit => 0x10000000_00000000,
                ElectrumMnemonic.MnemonicType.Legacy2Fa => 0x10100000_00000000,
                ElectrumMnemonic.MnemonicType.SegWit2Fa => 0x10200000_00000000,
                _ => 0
            };

            if (mask == 0 || expected == 0)
            {
                report.AddMessageSafe("Invalid Electrum mnemonic type.");
                return;
            }

            if (searchSpace.MissCount > 1)
            {
                report.SetProgressStep(searchSpace.PermutationCounts[0]);
                int firstIndex = searchSpace.MissingIndexes[0];
                ParallelOptions opts = report.BuildParallelOptions();
                Parallel.For(0, searchSpace.PermutationCounts[0], opts, (firstItem, state) => LoopElectrum(firstItem, firstIndex, mask, expected, state));
            }
            else
            {
                int misIndex = searchSpace.MissingIndexes[0];
                byte[] mnBuffer = new byte[maxMnBufferLen];
                ulong* bigBuffer = stackalloc ulong[Sha512Fo.UBufferSize + 80 + 80 + 80 + 8 + 8 + 8];
                ulong* hPt = bigBuffer;
                ulong* wPt = bigBuffer + Sha512Fo.HashStateSize;
                fixed (uint* wrd = &searchSpace.wordIndexes[0])
                fixed (byte* mnPt = &mnBuffer[0])
                fixed (uint* valPt = &searchSpace.AllPermutationValues[0])
                {
                    Permutation item = new(searchSpace.PermutationCounts[0], valPt);

                    do
                    {
                        wrd[misIndex] = item.GetValue();

                        int mnLen = 0;
                        for (int i = 0; i < 12; i++)
                        {
                            byte[] temp = allWordsBytes[wrd[i]];
                            Buffer.BlockCopy(temp, 0, mnBuffer, mnLen, temp.Length);
                            mnLen += temp.Length;
                        }

                        // Remove last space
                        mnLen--;

                        // Compute HMACSHA512("Seed version", normalized_mnemonic)
                        // 1. Compute SHA512(inner_pad | data)
                        Sha512Fo.Init_InnerPad_SeedVersion(hPt);
                        Sha512Fo.SetW(wPt);
                        Sha512Fo.CompressData(mnPt, mnLen, mnLen + 128, hPt, wPt);

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
                        Sha512Fo.Init_OuterPad_SeedVersion(hPt);
                        Sha512Fo.Compress192SecondBlock(hPt, wPt);

                        if ((hPt[0] & mask) == expected && SetBip32(mnPt, mnLen, bigBuffer, comparer))
                        {
                            SetResultParallel(mnPt, mnLen);
                            break;
                        }
                    } while (item.Increment());
                }
            }
        }



        public static bool TrySetWordList(BIP0039.WordLists wl, out string[] allWords, out int maxWordLen)
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
        /// Returns maximum possible length of the byte array representation of the mnemonic.
        /// Number of words * maximum word byte length + number of spaces in between
        /// </summary>
        /// <param name="seedLen"></param>
        /// <param name="maxWordLen"></param>
        /// <returns></returns>
        public static int GetSeedMaxByteSize(int seedLen, int maxWordLen) => (seedLen * maxWordLen) + (seedLen - 1);


        public void SetPbkdf2Salt(string pass)
        {
            byte[] salt = Encoding.UTF8.GetBytes($"mnemonic{pass?.Normalize(NormalizationForm.FormKD)}");
            pbkdf2Salt = new byte[salt.Length + 4];
            Buffer.BlockCopy(salt, 0, pbkdf2Salt, 0, salt.Length);
            pbkdf2Salt[^1] = 1;
        }

        public void SetPbkdf2SaltElectrum(string pass)
        {
            byte[] salt = Encoding.UTF8.GetBytes($"electrum{ElectrumMnemonic.Normalize(pass)}");
            pbkdf2Salt = new byte[salt.Length + 4];
            Buffer.BlockCopy(salt, 0, pbkdf2Salt, 0, salt.Length);
            pbkdf2Salt[^1] = 1;
        }


        // https://github.com/spesmilo/electrum/blob/1c07777e135d28fffa157019f90ccdaa002b614e/electrum/keystore.py#L984-L1003
        public static string GetElectrumPath(ElectrumMnemonic.MnemonicType value)
        {
            return value switch
            {
                ElectrumMnemonic.MnemonicType.Undefined => "m",
                ElectrumMnemonic.MnemonicType.Standard => "m/0/KEY_INDEX",
                ElectrumMnemonic.MnemonicType.SegWit => "m/0'/0/KEY_INDEX",
                ElectrumMnemonic.MnemonicType.Legacy2Fa => "m/1'/0/KEY_INDEX",
                ElectrumMnemonic.MnemonicType.SegWit2Fa => "m/1'/0/KEY_INDEX",
                _ => "m",
            };
        }


        public async void FindMissing(MnemonicSearchSpace ss, string pass, string path, string comp, CompareInputType compType)
        {
            report.Init();

            // TODO: implement Electrum seed recovery with other word lists (they need normalization)
            if (ss.mnType == MnemonicTypes.Electrum && ss.wl != BIP0039.WordLists.English)
            {
                report.Fail("Only English words are currently supported for Electrum mnemonics.");
                return;
            }

            if (!InputService.TryGetCompareService(compType, comp, out comparer))
            {
                report.Fail($"Invalid extra input or input type {compType}.");
                comparer = null;
            }

            this.path = MnemonicSearchSpace.ProcessPath(path, out string pathError);

            if (ss.MissCount == 0)
            {
                report.FoundAnyResult = ss.ProcessNoMissing(comparer, pass, this.path, out string message);
                report.AddMessageSafe(message);
                return;
            }

            if (path is null)
            {
                report.Fail($"Could not parse the given derivation path (error message: {pathError}).");
                return;
            }

            if (comparer is null || !comparer.IsInitialized)
            {
                report.Fail("Set the compare value correctly to verify the derived key/address.");
                return;
            }

            maxMnBufferLen = GetSeedMaxByteSize(ss.wordCount, ss.maxWordLen);

            for (uint i = 0; i < ss.allWords.Length; i++)
            {
                allWordsBytes[i] = Encoding.UTF8.GetBytes($"{ss.allWords[i]} ");
            }

            report.AddMessageSafe($"There are {ss.wordCount} words in the given mnemonic with {ss.MissCount} missing.");
            report.SetTotal(ss.GetTotal());

            searchSpace = ss;

            report.Timer.Start();

            if (ss.mnType == MnemonicTypes.BIP39)
            {
                SetPbkdf2Salt(pass);
                await Task.Run(() =>
                {
                    switch (ss.wordCount)
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
                });
            }
            else if (ss.mnType == MnemonicTypes.Electrum)
            {
                if (ss.elecMnType == ElectrumMnemonic.MnemonicType.Undefined)
                {
                    report.Fail("Undefined mnemonic type.");
                    report.Timer.Reset();
                    return;
                }

                SetPbkdf2SaltElectrum(pass);
                await Task.Run(() => LoopElectrum(ss.elecMnType));
            }
            else
            {
                report.Fail("Undefined mnemonic type.");
                report.Timer.Reset();
                return;
            }

            report.Finalize();
        }
    }
}
