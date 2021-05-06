// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.ImprovementProposals;
using FinderOuter.Backend.Cryptography.Asymmetric.EllipticCurve;
using FinderOuter.Backend.Cryptography.Hashing;
using FinderOuter.Backend.ECC;
using FinderOuter.Models;
using FinderOuter.Services.Comparers;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
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
            calc = new ECCalc();
        }


        private readonly IReport report;
        private readonly InputService inputService;
        private readonly ECCalc calc;

        private Dictionary<uint, byte[]> wordBytes = new(2048);
        private readonly byte[][] allWordsBytes = new byte[2048][];
        public const byte SpaceByte = 32;

        private readonly int[] allowedWordLengths = { 12, 15, 18, 21, 24 };
        private uint[] wordIndexes;
        private int[] missingIndexes;
        private string[] allWords;
        // TODO: this could be converted to SHA512 working vector and then leave the compression 
        //       to SetBip32() after setting HMAC key
        private byte[] pbkdf2Salt;
        // TODO: change this to an int only storing the length (has to be instantiated per thread anyways)
        private byte[] mnBytes;
        private BIP0032Path path;
        private ICompareService comparer;

        private int missCount;
        private string[] words;


        public unsafe bool SetBip32(Sha512Fo sha, byte* mnPt, int mnLen, ulong* bigBuffer, ICompareService comparer)
        {
            // The process is: PBKDF2(password=UTF8(mnemonic), salt=UTF8("mnemonic+passphrase") -> BIP32 seed
            //                 BIP32 -> HMACSHA(data=seed, key=MasterKeyHashKey) -> HMACSHA(data=key|index, key=ChainCode)
            // All HMACSHAs are using 512 variant

            // *** PBKDF2 ***
            // dkLen/HmacLen=1 => only 1 block => no loop needed
            // Salt is the "mnemonic+passPhrase" + blockNumber(=1) => fixed and set during precomputing

            ulong* uPt = bigBuffer;
            ulong* iPt = uPt + 80;
            ulong* oPt = iPt + 80;

            ulong* seedPt = oPt + 80;
            ulong* ihPt = seedPt + 8;
            ulong* ohPt = ihPt + 8;

            fixed (byte* dPt = &pbkdf2Salt[0])
            fixed (ulong* hPt = &sha.hashState[0], wPt = &sha.w[0])
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

                var sclrParent = new Scalar(hPt, out int overflow);
                if (overflow != 0)
                {
                    return false;
                }

                foreach (var index in path.Indexes)
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
                        Span<byte> pubkeyBytes = comparer.Calc2.GetPubkey(sclrParent, true);
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
                    sclrParent = sclrParent.Add(new Scalar(hPt, out _), out _);
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
            var missingItems = new uint[missCount - 1];
            var localComp = comparer.Clone();

            using Sha512Fo sha512 = new();
            using Sha256Fo sha256 = new();
            byte[] localMnBytes = new byte[mnBytes.Length];

            var localCopy = new byte[allWordsBytes.Length][];
            Array.Copy(allWordsBytes, localCopy, allWordsBytes.Length);

            uint[] localWIndex = new uint[wordIndexes.Length];
            Array.Copy(wordIndexes, localWIndex, wordIndexes.Length);

            ulong* bigBuffer = stackalloc ulong[80 + 80 + 80 + 8 + 8 + 8];

            fixed (uint* wPt = &sha256.w[0], hPt = &sha256.hashState[0], wrd = &localWIndex[0])
            fixed (uint* itemsPt = &missingItems[0])
            fixed (int* mi = &missingIndexes[1])
            fixed (byte* mnPt = &localMnBytes[0])
            {
                wPt[8] = 0b10000000_00000000_00000000_00000000U;
                wPt[15] = 256;
                wrd[firstIndex] = (uint)firstItem;

                do
                {
                    if (loopState.IsStopped)
                    {
                        return;
                    }

                    int j = 0;
                    foreach (var item in missingItems)
                    {
                        wrd[mi[j]] = item;
                        j++;
                    }

                    wPt[0] = wrd[0] << 21 | wrd[1] << 10 | wrd[2] >> 1;
                    wPt[1] = wrd[2] << 31 | wrd[3] << 20 | wrd[4] << 9 | wrd[5] >> 2;
                    wPt[2] = wrd[5] << 30 | wrd[6] << 19 | wrd[7] << 8 | wrd[8] >> 3;
                    wPt[3] = wrd[8] << 29 | wrd[9] << 18 | wrd[10] << 7 | wrd[11] >> 4;
                    wPt[4] = wrd[11] << 28 | wrd[12] << 17 | wrd[13] << 6 | wrd[14] >> 5;
                    wPt[5] = wrd[14] << 27 | wrd[15] << 16 | wrd[16] << 5 | wrd[17] >> 6;
                    wPt[6] = wrd[17] << 26 | wrd[18] << 15 | wrd[19] << 4 | wrd[20] >> 7;
                    wPt[7] = wrd[20] << 25 | wrd[21] << 14 | wrd[22] << 3 | wrd[23] >> 8;

                    Sha256Fo.Init(hPt);
                    sha256.Compress32(hPt, wPt);

                    if ((byte)wrd[23] == hPt[0] >> 24)
                    {
                        int mnLen = 0;
                        for (int i = 0; i < 24; i++)
                        {
                            var temp = localCopy[wrd[i]];
                            Buffer.BlockCopy(temp, 0, localMnBytes, mnLen, temp.Length);
                            mnLen += temp.Length;
                        }

                        if (SetBip32(sha512, mnPt, mnLen - 1, bigBuffer, localComp))
                        {
                            SetResultParallel(mnPt, mnLen - 1);
                            loopState.Stop();
                            return;
                        }
                    }
                } while (MoveNext(itemsPt, missingItems.Length));
            }

            report.IncrementProgress();
        }

        private unsafe void Loop24()
        {
            if (missCount > 1)
            {
                report.AddMessageSafe("Running in parallel.");
                report.SetProgressStep(2048);
                int firstIndex = missingIndexes[0];
                Parallel.For(0, 2048, (firstItem, state) => Loop24(firstItem, firstIndex, state));
            }
            else
            {
                using Sha512Fo sha512 = new();
                using Sha256Fo sha256 = new();

                int misIndex = missingIndexes[0];
                ulong* bigBuffer = stackalloc ulong[80 + 80 + 80 + 8 + 8 + 8];
                fixed (uint* wPt = &sha256.w[0], hPt = &sha256.hashState[0], wrd = &wordIndexes[0])
                fixed (int* mi = &missingIndexes[0])
                fixed (byte* mnPt = &mnBytes[0])
                {
                    wPt[8] = 0b10000000_00000000_00000000_00000000U;
                    wPt[15] = 256;

                    for (uint item = 0; item < 2048; item++)
                    {
                        wrd[misIndex] = item;

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

                        Sha256Fo.Init(hPt);
                        sha256.Compress32(hPt, wPt);

                        if ((byte)wrd[23] == hPt[0] >> 24)
                        {
                            int mnLen = 0;
                            for (int i = 0; i < 24; i++)
                            {
                                var temp = allWordsBytes[wrd[i]];
                                Buffer.BlockCopy(temp, 0, mnBytes, mnLen, temp.Length);
                                mnLen += temp.Length;
                            }

                            if (SetBip32(sha512, mnPt, mnLen - 1, bigBuffer, comparer))
                            {
                                SetResultParallel(mnPt, mnLen - 1);
                                return;
                            }
                        }
                    }
                }
            }
        }


        private unsafe void Loop21(int firstItem, int firstIndex, ParallelLoopState loopState)
        {
            var missingItems = new uint[missCount - 1];
            var localComp = comparer.Clone();

            using Sha512Fo sha512 = new();
            using Sha256Fo sha256 = new();
            byte[] localMnBytes = new byte[mnBytes.Length];

            var localCopy = new byte[allWordsBytes.Length][];
            Array.Copy(allWordsBytes, localCopy, allWordsBytes.Length);

            uint[] localWIndex = new uint[wordIndexes.Length];
            Array.Copy(wordIndexes, localWIndex, wordIndexes.Length);

            ulong* bigBuffer = stackalloc ulong[80 + 80 + 80 + 8 + 8 + 8];

            fixed (uint* wPt = &sha256.w[0], hPt = &sha256.hashState[0], wrd = &localWIndex[0])
            fixed (uint* itemsPt = &missingItems[0])
            fixed (int* mi = &missingIndexes[1])
            fixed (byte* mnPt = &localMnBytes[0])
            {
                wPt[7] = 0b10000000_00000000_00000000_00000000U;
                wPt[15] = 224;
                wrd[firstIndex] = (uint)firstItem;

                do
                {
                    if (loopState.IsStopped)
                    {
                        return;
                    }

                    int j = 0;
                    foreach (var item in missingItems)
                    {
                        wrd[mi[j]] = item;
                        j++;
                    }

                    wPt[0] = wrd[0] << 21 | wrd[1] << 10 | wrd[2] >> 1;
                    wPt[1] = wrd[2] << 31 | wrd[3] << 20 | wrd[4] << 9 | wrd[5] >> 2;
                    wPt[2] = wrd[5] << 30 | wrd[6] << 19 | wrd[7] << 8 | wrd[8] >> 3;
                    wPt[3] = wrd[8] << 29 | wrd[9] << 18 | wrd[10] << 7 | wrd[11] >> 4;
                    wPt[4] = wrd[11] << 28 | wrd[12] << 17 | wrd[13] << 6 | wrd[14] >> 5;
                    wPt[5] = wrd[14] << 27 | wrd[15] << 16 | wrd[16] << 5 | wrd[17] >> 6;
                    wPt[6] = wrd[17] << 26 | wrd[18] << 15 | wrd[19] << 4 | wrd[20] >> 7;

                    Sha256Fo.Init(hPt);
                    sha256.Compress28(hPt, wPt);

                    if ((wrd[20] & 0b111_1111) == hPt[0] >> 25)
                    {
                        int mnLen = 0;
                        for (int i = 0; i < 21; i++)
                        {
                            var temp = localCopy[wrd[i]];
                            Buffer.BlockCopy(temp, 0, localMnBytes, mnLen, temp.Length);
                            mnLen += temp.Length;
                        }

                        if (SetBip32(sha512, mnPt, mnLen - 1, bigBuffer, localComp))
                        {
                            SetResultParallel(mnPt, mnLen - 1);
                            loopState.Stop();
                            return;
                        }
                    }
                } while (MoveNext(itemsPt, missingItems.Length));
            }

            report.IncrementProgress();
        }

        private unsafe void Loop21()
        {
            if (missCount > 1)
            {
                report.AddMessageSafe("Running in parallel.");
                report.SetProgressStep(2048);
                int firstIndex = missingIndexes[0];
                Parallel.For(0, 2048, (firstItem, state) => Loop21(firstItem, firstIndex, state));
            }
            else
            {
                using Sha512Fo sha512 = new();
                using Sha256Fo sha256 = new();

                int misIndex = missingIndexes[0];
                ulong* bigBuffer = stackalloc ulong[80 + 80 + 80 + 8 + 8 + 8];
                fixed (uint* wPt = &sha256.w[0], hPt = &sha256.hashState[0], wrd = &wordIndexes[0])
                fixed (byte* mnPt = &mnBytes[0])
                {
                    wPt[7] = 0b10000000_00000000_00000000_00000000U;
                    wPt[15] = 224;

                    for (uint item = 0; item < 2048; item++)
                    {
                        wrd[misIndex] = item;

                        wPt[0] = wrd[0] << 21 | wrd[1] << 10 | wrd[2] >> 1;
                        wPt[1] = wrd[2] << 31 | wrd[3] << 20 | wrd[4] << 9 | wrd[5] >> 2;
                        wPt[2] = wrd[5] << 30 | wrd[6] << 19 | wrd[7] << 8 | wrd[8] >> 3;
                        wPt[3] = wrd[8] << 29 | wrd[9] << 18 | wrd[10] << 7 | wrd[11] >> 4;
                        wPt[4] = wrd[11] << 28 | wrd[12] << 17 | wrd[13] << 6 | wrd[14] >> 5;
                        wPt[5] = wrd[14] << 27 | wrd[15] << 16 | wrd[16] << 5 | wrd[17] >> 6;
                        wPt[6] = wrd[17] << 26 | wrd[18] << 15 | wrd[19] << 4 | wrd[20] >> 7;

                        Sha256Fo.Init(hPt);
                        sha256.Compress28(hPt, wPt);

                        if ((wrd[20] & 0b111_1111) == hPt[0] >> 25)
                        {
                            int mnLen = 0;
                            for (int i = 0; i < 21; i++)
                            {
                                var temp = allWordsBytes[wrd[i]];
                                Buffer.BlockCopy(temp, 0, mnBytes, mnLen, temp.Length);
                                mnLen += temp.Length;
                            }

                            if (SetBip32(sha512, mnPt, mnLen - 1, bigBuffer, comparer))
                            {
                                SetResultParallel(mnPt, mnLen - 1);
                                break;
                            }
                        }
                    }
                }
            }
        }


        private unsafe void Loop18(int firstItem, int firstIndex, ParallelLoopState loopState)
        {
            var missingItems = new uint[missCount - 1];
            var localComp = comparer.Clone();

            using Sha512Fo sha512 = new();
            using Sha256Fo sha256 = new();
            byte[] localMnBytes = new byte[mnBytes.Length];

            var localCopy = new byte[allWordsBytes.Length][];
            Array.Copy(allWordsBytes, localCopy, allWordsBytes.Length);

            uint[] localWIndex = new uint[wordIndexes.Length];
            Array.Copy(wordIndexes, localWIndex, wordIndexes.Length);

            ulong* bigBuffer = stackalloc ulong[80 + 80 + 80 + 8 + 8 + 8];

            fixed (uint* wPt = &sha256.w[0], hPt = &sha256.hashState[0], wrd = &localWIndex[0])
            fixed (uint* itemsPt = &missingItems[0])
            fixed (int* mi = &missingIndexes[1])
            fixed (byte* mnPt = &localMnBytes[0])
            {
                wPt[6] = 0b10000000_00000000_00000000_00000000U;
                wPt[15] = 192;
                wrd[firstIndex] = (uint)firstItem;

                do
                {
                    if (loopState.IsStopped)
                    {
                        return;
                    }

                    int j = 0;
                    foreach (var item in missingItems)
                    {
                        wrd[mi[j]] = item;
                        j++;
                    }

                    wPt[0] = wrd[0] << 21 | wrd[1] << 10 | wrd[2] >> 1;
                    wPt[1] = wrd[2] << 31 | wrd[3] << 20 | wrd[4] << 9 | wrd[5] >> 2;
                    wPt[2] = wrd[5] << 30 | wrd[6] << 19 | wrd[7] << 8 | wrd[8] >> 3;
                    wPt[3] = wrd[8] << 29 | wrd[9] << 18 | wrd[10] << 7 | wrd[11] >> 4;
                    wPt[4] = wrd[11] << 28 | wrd[12] << 17 | wrd[13] << 6 | wrd[14] >> 5;
                    wPt[5] = wrd[14] << 27 | wrd[15] << 16 | wrd[16] << 5 | wrd[17] >> 6;

                    Sha256Fo.Init(hPt);
                    sha256.Compress24(hPt, wPt);

                    if ((wrd[17] & 0b11_1111) == hPt[0] >> 26)
                    {
                        int mnLen = 0;
                        for (int i = 0; i < 18; i++)
                        {
                            var temp = localCopy[wrd[i]];
                            Buffer.BlockCopy(temp, 0, localMnBytes, mnLen, temp.Length);
                            mnLen += temp.Length;
                        }

                        if (SetBip32(sha512, mnPt, mnLen - 1, bigBuffer, localComp))
                        {
                            SetResultParallel(mnPt, mnLen - 1);
                            loopState.Stop();
                            return;
                        }
                    }
                } while (MoveNext(itemsPt, missingItems.Length));
            }

            report.IncrementProgress();
        }

        private unsafe void Loop18()
        {
            if (missCount > 1)
            {
                report.AddMessageSafe("Running in parallel.");
                report.SetProgressStep(2048);
                int firstIndex = missingIndexes[0];
                Parallel.For(0, 2048, (firstItem, state) => Loop18(firstItem, firstIndex, state));
            }
            else
            {
                using Sha512Fo sha512 = new();
                using Sha256Fo sha256 = new();

                int misIndex = missingIndexes[0];
                ulong* bigBuffer = stackalloc ulong[80 + 80 + 80 + 8 + 8 + 8];
                fixed (uint* wPt = &sha256.w[0], hPt = &sha256.hashState[0], wrd = &wordIndexes[0])
                fixed (byte* mnPt = &mnBytes[0])
                {
                    wPt[6] = 0b10000000_00000000_00000000_00000000U;
                    wPt[15] = 192;

                    for (uint item = 0; item < 2048; item++)
                    {
                        wrd[misIndex] = item;

                        wPt[0] = wrd[0] << 21 | wrd[1] << 10 | wrd[2] >> 1;
                        wPt[1] = wrd[2] << 31 | wrd[3] << 20 | wrd[4] << 9 | wrd[5] >> 2;
                        wPt[2] = wrd[5] << 30 | wrd[6] << 19 | wrd[7] << 8 | wrd[8] >> 3;
                        wPt[3] = wrd[8] << 29 | wrd[9] << 18 | wrd[10] << 7 | wrd[11] >> 4;
                        wPt[4] = wrd[11] << 28 | wrd[12] << 17 | wrd[13] << 6 | wrd[14] >> 5;
                        wPt[5] = wrd[14] << 27 | wrd[15] << 16 | wrd[16] << 5 | wrd[17] >> 6;

                        Sha256Fo.Init(hPt);
                        sha256.Compress24(hPt, wPt);

                        if ((wrd[17] & 0b11_1111) == hPt[0] >> 26)
                        {
                            int mnLen = 0;
                            for (int i = 0; i < 18; i++)
                            {
                                var temp = allWordsBytes[wrd[i]];
                                Buffer.BlockCopy(temp, 0, mnBytes, mnLen, temp.Length);
                                mnLen += temp.Length;
                            }

                            if (SetBip32(sha512, mnPt, mnLen - 1, bigBuffer, comparer))
                            {
                                SetResultParallel(mnPt, mnLen - 1);
                                break;
                            }
                        }
                    }
                }
            }
        }


        private unsafe void Loop15(int firstItem, int firstIndex, ParallelLoopState loopState)
        {
            var missingItems = new uint[missCount - 1];
            var localComp = comparer.Clone();

            using Sha512Fo sha512 = new();
            using Sha256Fo sha256 = new();
            byte[] localMnBytes = new byte[mnBytes.Length];

            var localCopy = new byte[allWordsBytes.Length][];
            Array.Copy(allWordsBytes, localCopy, allWordsBytes.Length);

            uint[] localWIndex = new uint[wordIndexes.Length];
            Array.Copy(wordIndexes, localWIndex, wordIndexes.Length);

            ulong* bigBuffer = stackalloc ulong[80 + 80 + 80 + 8 + 8 + 8];

            fixed (uint* wPt = &sha256.w[0], hPt = &sha256.hashState[0], wrd = &localWIndex[0])
            fixed (uint* itemsPt = &missingItems[0])
            fixed (int* mi = &missingIndexes[1])
            fixed (byte* mnPt = &localMnBytes[0])
            {
                wPt[5] = 0b10000000_00000000_00000000_00000000U;
                wPt[15] = 160;
                wrd[firstIndex] = (uint)firstItem;

                do
                {
                    if (loopState.IsStopped)
                    {
                        return;
                    }

                    int j = 0;
                    foreach (var item in missingItems)
                    {
                        wrd[mi[j]] = item;
                        j++;
                    }

                    wPt[0] = wrd[0] << 21 | wrd[1] << 10 | wrd[2] >> 1;
                    wPt[1] = wrd[2] << 31 | wrd[3] << 20 | wrd[4] << 9 | wrd[5] >> 2;
                    wPt[2] = wrd[5] << 30 | wrd[6] << 19 | wrd[7] << 8 | wrd[8] >> 3;
                    wPt[3] = wrd[8] << 29 | wrd[9] << 18 | wrd[10] << 7 | wrd[11] >> 4;
                    wPt[4] = wrd[11] << 28 | wrd[12] << 17 | wrd[13] << 6 | wrd[14] >> 5;

                    Sha256Fo.Init(hPt);
                    sha256.Compress20(hPt, wPt);

                    if ((wrd[14] & 0b1_1111) == hPt[0] >> 27)
                    {
                        int mnLen = 0;
                        for (int i = 0; i < 15; i++)
                        {
                            var temp = localCopy[wrd[i]];
                            Buffer.BlockCopy(temp, 0, localMnBytes, mnLen, temp.Length);
                            mnLen += temp.Length;
                        }

                        if (SetBip32(sha512, mnPt, mnLen - 1, bigBuffer, localComp))
                        {
                            SetResultParallel(mnPt, mnLen - 1);
                            loopState.Stop();
                            return;
                        }
                    }
                } while (MoveNext(itemsPt, missingItems.Length));
            }

            report.IncrementProgress();
        }

        private unsafe void Loop15()
        {
            if (missCount > 1)
            {
                report.AddMessageSafe("Running in parallel.");
                report.SetProgressStep(2048);
                int firstIndex = missingIndexes[0];
                Parallel.For(0, 2048, (firstItem, state) => Loop15(firstItem, firstIndex, state));
            }
            else
            {
                using Sha512Fo sha512 = new();
                using Sha256Fo sha256 = new();

                int misIndex = missingIndexes[0];
                ulong* bigBuffer = stackalloc ulong[80 + 80 + 80 + 8 + 8 + 8];
                fixed (uint* wPt = &sha256.w[0], hPt = &sha256.hashState[0], wrd = &wordIndexes[0])
                fixed (byte* mnPt = &mnBytes[0])
                {
                    wPt[5] = 0b10000000_00000000_00000000_00000000U;
                    wPt[15] = 160;

                    for (uint item = 0; item < 2048; item++)
                    {
                        wrd[misIndex] = item;

                        wPt[0] = wrd[0] << 21 | wrd[1] << 10 | wrd[2] >> 1;
                        wPt[1] = wrd[2] << 31 | wrd[3] << 20 | wrd[4] << 9 | wrd[5] >> 2;
                        wPt[2] = wrd[5] << 30 | wrd[6] << 19 | wrd[7] << 8 | wrd[8] >> 3;
                        wPt[3] = wrd[8] << 29 | wrd[9] << 18 | wrd[10] << 7 | wrd[11] >> 4;
                        wPt[4] = wrd[11] << 28 | wrd[12] << 17 | wrd[13] << 6 | wrd[14] >> 5;

                        Sha256Fo.Init(hPt);
                        sha256.Compress20(hPt, wPt);

                        if ((wrd[14] & 0b1_1111) == hPt[0] >> 27)
                        {
                            int mnLen = 0;
                            for (int i = 0; i < 15; i++)
                            {
                                var temp = allWordsBytes[wrd[i]];
                                Buffer.BlockCopy(temp, 0, mnBytes, mnLen, temp.Length);
                                mnLen += temp.Length;
                            }

                            if (SetBip32(sha512, mnPt, mnLen - 1, bigBuffer, comparer))
                            {
                                SetResultParallel(mnPt, mnLen - 1);
                                break;
                            }
                        }
                    }
                }
            }
        }


        private unsafe void Loop12(int firstItem, int firstIndex, ParallelLoopState loopState)
        {
            var missingItems = new uint[missCount - 1];
            var localComp = comparer.Clone();

            using Sha512Fo sha512 = new();
            using Sha256Fo sha256 = new();
            byte[] localMnBytes = new byte[mnBytes.Length];

            var localCopy = new byte[allWordsBytes.Length][];
            Array.Copy(allWordsBytes, localCopy, allWordsBytes.Length);

            uint[] localWIndex = new uint[wordIndexes.Length];
            Array.Copy(wordIndexes, localWIndex, wordIndexes.Length);

            ulong* bigBuffer = stackalloc ulong[80 + 80 + 80 + 8 + 8 + 8];

            fixed (uint* wPt = &sha256.w[0], hPt = &sha256.hashState[0], wrd = &localWIndex[0])
            fixed (uint* itemsPt = &missingItems[0])
            fixed (int* mi = &missingIndexes[1])
            fixed (byte* mnPt = &localMnBytes[0])
            {
                wPt[4] = 0b10000000_00000000_00000000_00000000U;
                wPt[15] = 128;

                wrd[firstIndex] = (uint)firstItem;

                do
                {
                    if (loopState.IsStopped)
                    {
                        return;
                    }

                    int j = 0;
                    foreach (var item in missingItems)
                    {
                        wrd[mi[j]] = item;
                        j++;
                    }

                    wPt[0] = wrd[0] << 21 | wrd[1] << 10 | wrd[2] >> 1;
                    wPt[1] = wrd[2] << 31 | wrd[3] << 20 | wrd[4] << 9 | wrd[5] >> 2;
                    wPt[2] = wrd[5] << 30 | wrd[6] << 19 | wrd[7] << 8 | wrd[8] >> 3;
                    wPt[3] = wrd[8] << 29 | wrd[9] << 18 | wrd[10] << 7 | wrd[11] >> 4;

                    Sha256Fo.Init(hPt);
                    sha256.Compress16(hPt, wPt);

                    if ((wrd[11] & 0b1111) == hPt[0] >> 28)
                    {
                        int mnLen = 0;
                        for (int i = 0; i < 12; i++)
                        {
                            var temp = localCopy[wrd[i]];
                            Buffer.BlockCopy(temp, 0, localMnBytes, mnLen, temp.Length);
                            mnLen += temp.Length;
                        }

                        if (SetBip32(sha512, mnPt, mnLen - 1, bigBuffer, localComp))
                        {
                            SetResultParallel(mnPt, mnLen - 1);
                            loopState.Stop();
                            return;
                        }
                    }
                } while (MoveNext(itemsPt, missingItems.Length));
            }

            report.IncrementProgress();
        }

        private unsafe void Loop12()
        {
            if (missCount > 1)
            {
                report.AddMessageSafe("Running in parallel.");
                report.SetProgressStep(2048);
                int firstIndex = missingIndexes[0];
                Parallel.For(0, 2048, (firstItem, state) => Loop12(firstItem, firstIndex, state));
            }
            else
            {
                // We can't call the same parallel method due to usage of LoopState so we at least optimize this by
                // avoiding the inner loop over the IEnumerable
                using Sha512Fo sha512 = new();
                using Sha256Fo sha256 = new();

                int misIndex = missingIndexes[0];
                ulong* bigBuffer = stackalloc ulong[80 + 80 + 80 + 8 + 8 + 8];
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

                        Sha256Fo.Init(hPt);
                        sha256.Compress16(hPt, wPt);

                        if ((wrd[11] & 0b1111) == hPt[0] >> 28)
                        {
                            int mnLen = 0;
                            for (int i = 0; i < 12; i++)
                            {
                                var temp = allWordsBytes[wrd[i]];
                                Buffer.BlockCopy(temp, 0, mnBytes, mnLen, temp.Length);
                                mnLen += temp.Length;
                            }

                            if (SetBip32(sha512, mnPt, mnLen - 1, bigBuffer, comparer))
                            {
                                SetResultParallel(mnPt, mnLen - 1);
                                break;
                            }
                        }
                    }
                }
            }
        }



        private unsafe void LoopElectrum(int firstItem, int firstIndex, ulong mask, ulong expected, ParallelLoopState loopState)
        {
            var missingItems = new uint[missCount - 1];
            var localComp = comparer.Clone();

            byte[] localMnBytes = new byte[mnBytes.Length];

            var localCopy = new byte[allWordsBytes.Length][];
            Array.Copy(allWordsBytes, localCopy, allWordsBytes.Length);

            uint[] localWIndex = new uint[wordIndexes.Length];
            Array.Copy(wordIndexes, localWIndex, wordIndexes.Length);


            using Sha512Fo sha512 = new();

            ulong* bigBuffer = stackalloc ulong[80 + 80 + 80 + 8 + 8 + 8];
            fixed (uint* wrd = &localWIndex[0], itemsPt = &missingItems[0])
            fixed (int* mi = &missingIndexes[1])
            fixed (ulong* hPt = &sha512.hashState[0], wPt = &sha512.w[0])
            fixed (byte* mnPt = &localMnBytes[0])
            {
                wrd[firstIndex] = (uint)firstItem;

                do
                {
                    if (loopState.IsStopped)
                    {
                        return;
                    }

                    int j = 0;
                    foreach (var item in missingItems)
                    {
                        wrd[mi[j]] = item;
                        j++;
                    }

                    int mnLen = 0;
                    for (int i = 0; i < 12; i++)
                    {
                        var temp = localCopy[wrd[i]];
                        Buffer.BlockCopy(temp, 0, localMnBytes, mnLen, temp.Length);
                        mnLen += temp.Length;
                    }

                    // Remove last space
                    mnLen--;

                    // Compute HMACSHA512("Seed version", normalized_mnemonic)
                    // 1. Compute SHA512(inner_pad | data)
                    sha512.Init_InnerPad_SeedVersion(hPt);
                    sha512.CompressData(mnPt, mnLen, mnLen + 128, hPt, wPt);

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
                    sha512.Init_OuterPad_SeedVersion(hPt);
                    sha512.Compress192SecondBlock(hPt, wPt);

                    if ((hPt[0] & mask) == expected && SetBip32(sha512, mnPt, mnLen, bigBuffer, localComp))
                    {
                        SetResultParallel(mnPt, mnLen);
                        loopState.Stop();
                        break;
                    }
                } while (MoveNext(itemsPt, missingItems.Length));
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

            if (missCount > 1)
            {
                report.AddMessageSafe("Running in parallel.");
                report.SetProgressStep(2048);
                int firstIndex = missingIndexes[0];
                Parallel.For(0, 2048, (firstItem, state) => LoopElectrum(firstItem, firstIndex, mask, expected, state));
            }
            else
            {
                using Sha512Fo sha512 = new();

                int misIndex = missingIndexes[0];
                ulong* bigBuffer = stackalloc ulong[80 + 80 + 80 + 8 + 8 + 8];
                fixed (uint* wrd = &wordIndexes[0])
                fixed (ulong* hPt = &sha512.hashState[0], wPt = &sha512.w[0])
                fixed (byte* mnPt = &mnBytes[0])
                {
                    for (uint item = 0; item < 2048; item++)
                    {
                        wrd[misIndex] = item;

                        int mnLen = 0;
                        for (int i = 0; i < 12; i++)
                        {
                            var temp = allWordsBytes[wrd[i]];
                            Buffer.BlockCopy(temp, 0, mnBytes, mnLen, temp.Length);
                            mnLen += temp.Length;
                        }

                        // Remove last space
                        mnLen--;

                        // Compute HMACSHA512("Seed version", normalized_mnemonic)
                        // 1. Compute SHA512(inner_pad | data)
                        sha512.Init_InnerPad_SeedVersion(hPt);
                        sha512.CompressData(mnPt, mnLen, mnLen + 128, hPt, wPt);

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
                        sha512.Init_OuterPad_SeedVersion(hPt);
                        sha512.Compress192SecondBlock(hPt, wPt);

                        if ((hPt[0] & mask) == expected && SetBip32(sha512, mnPt, mnLen, bigBuffer, comparer))
                        {
                            SetResultParallel(mnPt, mnLen);
                            break;
                        }
                    }
                }
            }
        }


        private static BigInteger GetTotalCount(int missCount) => BigInteger.Pow(2048, missCount);

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
        /// Returns a buffer to hold byte array representation of the mnemonic with maximum possible length.
        /// Number of words * maximum word byte length + number of spaces in between
        /// </summary>
        /// <param name="seedLen"></param>
        /// <param name="maxWordLen"></param>
        /// <returns></returns>
        public static byte[] GetSeedByte(int seedLen, int maxWordLen) => new byte[(seedLen * maxWordLen) + (seedLen - 1)];


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

                var missCharStr = new string(new char[] { missingChar });
                bool invalidWord = false;
                for (int i = 0; i < words.Length; i++)
                {
                    if (words[i] != missCharStr && !allWords.Contains(words[i]))
                    {
                        invalidWord = true;
                        report.Fail($"Given mnemonic contains invalid word at index {i} ({words[i]}).");
                    }
                }
                if (invalidWord)
                {
                    words = null;
                    return false;
                }
                missCount = words.Count(s => s == missCharStr);
                wordIndexes = new uint[words.Length];
                missingIndexes = new int[missCount];
                for (int i = 0, j = 0; i < words.Length; i++)
                {
                    if (words[i] != missCharStr)
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


        public async void FindMissing(string mnemonic, char missChar, string pass, string extra, InputType extraType,
                                      string path, MnemonicTypes mnType, BIP0039.WordLists wl,
                                      ElectrumMnemonic.MnemonicType elecMnType)
        {
            report.Init();

            // TODO: implement Electrum seed recovery with other word lists (they need normalization)
            if (mnType == MnemonicTypes.Electrum && wl != BIP0039.WordLists.English)
                report.Fail("Only English words are currently supported for Electrum mnemonics.");
            else if (!inputService.IsMissingCharValid(missChar))
                report.Fail("Missing character is not accepted.");
            else if (!TrySetWordList(wl, out allWords, out int maxWordLen))
                report.Fail($"Could not find {wl} word list among resources.");
            else if (!TrySplitMnemonic(mnemonic, missChar))
                return;
            else
            {
                if (missCount == 0)
                {
                    try
                    {
                        if (mnType == MnemonicTypes.BIP39)
                        {
                            using BIP0039 temp = new(mnemonic, wl, pass);
                        }
                        else if (mnType == MnemonicTypes.Electrum)
                        {
                            using ElectrumMnemonic temp = new(mnemonic, wl, pass);
                        }

                        report.Pass($"Given mnemonic is a valid {mnType}.");
                    }
                    catch (Exception ex)
                    {
                        report.Fail($"Mnemonic is not missing any characters but is invalid. Error: {ex.Message}.");
                    }

                    return;
                }


                mnBytes = GetSeedByte(words.Length, maxWordLen);

                wordBytes = new Dictionary<uint, byte[]>(2048);
                for (uint i = 0; i < allWords.Length; i++)
                {
                    wordBytes.Add(i, Encoding.UTF8.GetBytes(allWords[i]));
                    allWordsBytes[i] = Encoding.UTF8.GetBytes($"{allWords[i]} ");
                }

                try
                {
                    this.path = new BIP0032Path(path);
                }
                catch (Exception ex)
                {
                    report.Fail($"Invalid path ({ex.Message}).");
                    return;
                }

                if (!inputService.TryGetCompareService(extraType, extra, out comparer))
                {
                    report.Fail($"Invalid extra input or input type {extraType}.");
                    return;
                }

                report.AddMessageSafe($"There are {words.Length} words in the given mnemonic with {missCount} missing.");
                report.AddMessageSafe($"A total of {GetTotalCount(missCount):n0} mnemonics should be checked.");

                Stopwatch watch = Stopwatch.StartNew();

                if (mnType == MnemonicTypes.BIP39)
                {
                    SetPbkdf2Salt(pass);
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
                    });
                }
                else if (mnType == MnemonicTypes.Electrum)
                {
                    if (elecMnType == ElectrumMnemonic.MnemonicType.Undefined)
                    {
                        report.Fail("Undefined mnemonic type.");
                        watch.Stop();
                        return;
                    }

                    SetPbkdf2SaltElectrum(pass);
                    await Task.Run(() => LoopElectrum(elecMnType));
                }
                else
                {
                    report.Fail("Undefined mnemonic type.");
                    watch.Stop();
                    return;
                }

                watch.Stop();

                report.AddMessageSafe($"Elapsed time: {watch.Elapsed}");
                report.SetKeyPerSecSafe(GetTotalCount(missCount), watch.Elapsed.TotalSeconds);

                report.Finalize();
            }
        }
    }
}
