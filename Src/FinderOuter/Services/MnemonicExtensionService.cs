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
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace FinderOuter.Services
{
    public class MnemonicExtensionService
    {
        public MnemonicExtensionService(IReport rep)
        {
            report = rep;
        }


        private readonly IReport report;
        private BIP0032Path path;
        private ICompareService comparer;


        public unsafe bool SetBip32(ulong* bigBuffer, ICompareService comparer)
        {
            ulong* hPt = bigBuffer;
            ulong* wPt = hPt + Sha512Fo.HashStateSize;
            ulong* seedPt = wPt + Sha512Fo.WorkingVectorSize;
            ulong* iPt = seedPt + Sha512Fo.HashStateSize;
            ulong* oPt = iPt + Sha512Fo.WorkingVectorSize;

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
            // TODO: this part can be set by the caller outside its loop
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
                    wPt[0] = (ulong)sclrParent.b7 << 24 | (ulong)sclrParent.b6 >> 8;
                    wPt[1] = (ulong)sclrParent.b6 << 56 | (ulong)sclrParent.b5 << 24 | (ulong)sclrParent.b4 >> 8;
                    wPt[2] = (ulong)sclrParent.b4 << 56 | (ulong)sclrParent.b3 << 24 | (ulong)sclrParent.b2 >> 8;
                    wPt[3] = (ulong)sclrParent.b2 << 56 | (ulong)sclrParent.b1 << 24 | (ulong)sclrParent.b0 >> 8;
                    wPt[4] = (ulong)sclrParent.b0 << 56 |
                             (ulong)index << 24 |
                             0b00000000_00000000_00000000_00000000_00000000_10000000_00000000_00000000UL;
                }
                else
                {
                    Span<byte> pubkeyBytes = comparer.Calc.GetPubkey(sclrParent, true);
                    fixed (byte* pubXPt = &pubkeyBytes[0])
                    {
                        wPt[0] = (ulong)pubXPt[0] << 56 |
                                 (ulong)pubXPt[1] << 48 |
                                 (ulong)pubXPt[2] << 40 |
                                 (ulong)pubXPt[3] << 32 |
                                 (ulong)pubXPt[4] << 24 |
                                 (ulong)pubXPt[5] << 16 |
                                 (ulong)pubXPt[6] << 8 |
                                        pubXPt[7];
                        wPt[1] = (ulong)pubXPt[8] << 56 |
                                 (ulong)pubXPt[9] << 48 |
                                 (ulong)pubXPt[10] << 40 |
                                 (ulong)pubXPt[11] << 32 |
                                 (ulong)pubXPt[12] << 24 |
                                 (ulong)pubXPt[13] << 16 |
                                 (ulong)pubXPt[14] << 8 |
                                        pubXPt[15];
                        wPt[2] = (ulong)pubXPt[16] << 56 |
                                 (ulong)pubXPt[17] << 48 |
                                 (ulong)pubXPt[18] << 40 |
                                 (ulong)pubXPt[19] << 32 |
                                 (ulong)pubXPt[20] << 24 |
                                 (ulong)pubXPt[21] << 16 |
                                 (ulong)pubXPt[22] << 8 |
                                        pubXPt[23];
                        wPt[3] = (ulong)pubXPt[24] << 56 |
                                 (ulong)pubXPt[25] << 48 |
                                 (ulong)pubXPt[26] << 40 |
                                 (ulong)pubXPt[27] << 32 |
                                 (ulong)pubXPt[28] << 24 |
                                 (ulong)pubXPt[29] << 16 |
                                 (ulong)pubXPt[30] << 8 |
                                        pubXPt[31];
                        wPt[4] = (ulong)pubXPt[32] << 56 |
                                 (ulong)index << 24 |
                                 0b00000000_00000000_00000000_00000000_00000000_10000000_00000000_00000000UL;
                    }
                }

                wPt[5] = 0;
                wPt[6] = 0;
                wPt[7] = 0;
                wPt[8] = 0;
                wPt[9] = 0;
                wPt[10] = 0;
                wPt[11] = 0;
                wPt[12] = 0;
                wPt[13] = 0;
                wPt[14] = 0;
                wPt[15] = 1320; // (1+32+4 + 128)*8

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
                Sha512Fo.Compress165SecondBlock(hPt, wPt);

                // 2. Compute SHA512(outer_pad | hash)
                *(Block64*)wPt = *(Block64*)hPt;
                wPt[8] = 0b10000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000UL;
                wPt[9] = 0;
                wPt[10] = 0;
                wPt[11] = 0;
                wPt[12] = 0;
                wPt[13] = 0;
                wPt[14] = 0;
                wPt[15] = 1536; // (128+64)*8

                Sha512Fo.Init(hPt);
                Sha512Fo.SetW(oPt);
                Sha512Fo.CompressBlockWithWSet(hPt, oPt);
                Sha512Fo.Compress192SecondBlock(hPt, wPt);

                // New private key is (parentPrvKey + int(hPt)) % order
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


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe bool MoveNext(int* items, int len, int max)
        {
            for (int i = len - 1; i >= 0; --i)
            {
                items[i] += 1;

                if (items[i] == max)
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


        // pads are HMAC inner and outer pad hashstates that are already computed using mnemonic
        public unsafe void LoopBip39(ulong[] pads, byte[] salt, byte[] allValues, int passLength, ParallelLoopState loopState)
        {
            Debug.Assert(pads != null && pads.Length == Sha512Fo.HashStateSize * 2);
            Debug.Assert(salt != null && salt.Length == Sha512Fo.BlockByteSize);

            ulong* bigBuffer = stackalloc ulong[Sha512Fo.UBufferSize + Sha512Fo.HashStateSize + (2 * Sha512Fo.WorkingVectorSize)];
            ulong* hPt = bigBuffer;
            ulong* wPt = hPt + Sha512Fo.HashStateSize;
            ulong* seedPt = wPt + Sha512Fo.WorkingVectorSize;

            Debug.Assert(passLength - 1 > 0);
            int[] items = new int[passLength - 1];

            fixed (byte* dPt = &salt[0], valPt = &allValues[0])
            fixed (ulong* iPt = &pads[0], oPt = &pads[Sha512Fo.HashStateSize])
            fixed (int* itemsPt = &items[0])
            {
                do
                {
                    if (loopState.IsStopped)
                    {
                        return;
                    }

                    int startIndex = 9;
                    for (int i = 0; i < items.Length; i++)
                    {
                        Debug.Assert(itemsPt[i] < allValues.Length);
                        dPt[startIndex++] = valPt[itemsPt[i]];
                    }

                    // 1. SHA512(inner_pad | data) -> 2 blocks; first one is already compressed
                    *(Block64*)hPt = *(Block64*)iPt;
                    // Data length is unknown and an initial block of 128 bytes was already compressed
                    // but we already reject anything big that needs another block (there is only one more block to compress)
                    // The pad and data length is also already set
                    Sha512Fo.CompressSingleBlock(dPt, hPt, wPt);

                    // 2. SHA512(outer_pad | hash) -> 2 blocks; first one is already compressed
                    // Copy hashstate into next block before changing it
                    *(Block64*)wPt = *(Block64*)hPt;
                    wPt[8] = 0b10000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000UL;
                    wPt[9] = 0;
                    wPt[10] = 0;
                    wPt[11] = 0;
                    wPt[12] = 0;
                    wPt[13] = 0;
                    wPt[14] = 0;
                    wPt[15] = 1536; // oPad.Length(=128) + hashState.Lengh(=64) = 192 byte *8 = 1,536 bit

                    *(Block64*)hPt = *(Block64*)oPt;
                    Sha512Fo.Compress192SecondBlock(hPt, wPt);

                    // Copy u1 to result of F() to be XOR'ed with each result on iterations, and result of F() is the seed
                    *(Block64*)seedPt = *(Block64*)hPt;

                    // Compute u2 to u(c-1) where c is iteration and each u is the HMAC of previous u
                    for (int j = 1; j < 2048; j++)
                    {
                        // Each u is calculated by computing HMAC(previous_u) where previous_u is 64 bytes hPt
                        // Start by making a copy of hPt so Init() can be called
                        *(Block64*)wPt = *(Block64*)hPt;

                        // Final result is SHA512(outer_pad | SHA512(inner_pad | 64_byte_data))
                        // 1. Compute SHA512(inner_pad | 64_byte_data)
                        // 2. Compute SHA512(outer_pad | hash)
                        //    Since pads don't change and each step is Init() then Compress(pad) the hashState is always the same
                        //    after these 2 steps and is already computed and stored in temp arrays above
                        //    by doing this 2*2047=4094 SHA512 block compressions are skipped

                        // Replace: sha.Init(hPt); sha.CompressBlockWithWSet(hPt, iPt); with line below:
                        *(Block64*)hPt = *(Block64*)iPt;
                        Sha512Fo.Compress192SecondBlock(hPt, wPt);

                        // 2. Compute SHA512(outer_pad | hash)
                        *(Block64*)wPt = *(Block64*)hPt;
                        // The rest of wPt is set above and is unchanged

                        // Replace: sha.Init(hPt); sha.CompressBlock(hPt, oPt); with line below:
                        *(Block64*)hPt = *(Block64*)oPt;
                        Sha512Fo.Compress192SecondBlock(hPt, wPt);

                        // result of F() is XOR sum of all u arrays
                        seedPt[0] ^= hPt[0];
                        seedPt[1] ^= hPt[1];
                        seedPt[2] ^= hPt[2];
                        seedPt[3] ^= hPt[3];
                        seedPt[4] ^= hPt[4];
                        seedPt[5] ^= hPt[5];
                        seedPt[6] ^= hPt[6];
                        seedPt[7] ^= hPt[7];
                    }

                    if (SetBip32(bigBuffer, comparer))
                    {
                        loopState.Stop();
                        report.FoundAnyResult = true;

                        byte[] temp = new byte[items.Length + 1];
                        temp[0] = dPt[8];
                        for (int i = 1; i < temp.Length; i++)
                        {
                            temp[i] = valPt[items[i - 1]];
                        }
                        string finalResult = Encoding.UTF8.GetString(temp);

                        report.AddMessageSafe($"Passphrase is: {finalResult}");

                        return;
                    }

                } while (MoveNext(itemsPt, items.Length, allValues.Length));
            }

            report.IncrementProgress();
        }


        private static byte[] ParallelSalt(byte[] salt, byte firstItem)
        {
            byte[] result = new byte[salt.Length];
            Buffer.BlockCopy(salt, 0, result, 0, salt.Length);
            result[8] = firstItem;
            return result;
        }
        public unsafe void MainLoop(ulong[] pads, byte[] salt, byte[] allValues, int passLength)
        {
            Debug.Assert(pads != null && pads.Length == Sha512Fo.HashStateSize * 2);
            Debug.Assert(salt != null && salt.Length == Sha512Fo.BlockByteSize);

            if (passLength == 1)
            {
                ulong* bigBuffer = stackalloc ulong[Sha512Fo.UBufferSize + Sha512Fo.HashStateSize + (2 * Sha512Fo.WorkingVectorSize)];
                ulong* hPt = bigBuffer;
                ulong* wPt = hPt + Sha512Fo.HashStateSize;
                ulong* seedPt = wPt + Sha512Fo.WorkingVectorSize;

                fixed (byte* dPt = &salt[0], valPt = &allValues[0])
                fixed (ulong* iPt = &pads[0], oPt = &pads[Sha512Fo.HashStateSize])
                {
                    foreach (byte val in allValues)
                    {
                        dPt[8] = val;

                        // 1. SHA512(inner_pad | data) -> 2 blocks; first one is already compressed
                        *(Block64*)hPt = *(Block64*)iPt;
                        // Data length is unknown and an initial block of 128 bytes was already compressed
                        // but we already reject anything big that needs another block (there is only one more block to compress)
                        // The pad and data length is also already set
                        Sha512Fo.CompressSingleBlock(dPt, hPt, wPt);

                        // 2. SHA512(outer_pad | hash) -> 2 blocks; first one is already compressed
                        // Copy hashstate into next block before changing it
                        *(Block64*)wPt = *(Block64*)hPt;
                        wPt[8] = 0b10000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000UL;
                        wPt[9] = 0;
                        wPt[10] = 0;
                        wPt[11] = 0;
                        wPt[12] = 0;
                        wPt[13] = 0;
                        wPt[14] = 0;
                        wPt[15] = 1536; // oPad.Length(=128) + hashState.Lengh(=64) = 192 byte *8 = 1,536 bit

                        *(Block64*)hPt = *(Block64*)oPt;
                        Sha512Fo.Compress192SecondBlock(hPt, wPt);

                        // Copy u1 to result of F() to be XOR'ed with each result on iterations, and result of F() is the seed
                        *(Block64*)seedPt = *(Block64*)hPt;

                        // Compute u2 to u(c-1) where c is iteration and each u is the HMAC of previous u
                        for (int j = 1; j < 2048; j++)
                        {
                            // Each u is calculated by computing HMAC(previous_u) where previous_u is 64 bytes hPt
                            // Start by making a copy of hPt so Init() can be called
                            *(Block64*)wPt = *(Block64*)hPt;

                            // Final result is SHA512(outer_pad | SHA512(inner_pad | 64_byte_data))
                            // 1. Compute SHA512(inner_pad | 64_byte_data)
                            // 2. Compute SHA512(outer_pad | hash)
                            //    Since pads don't change and each step is Init() then Compress(pad) the hashState is always the same
                            //    after these 2 steps and is already computed and stored in temp arrays above
                            //    by doing this 2*2047=4094 SHA512 block compressions are skipped

                            // Replace: sha.Init(hPt); sha.CompressBlockWithWSet(hPt, iPt); with line below:
                            *(Block64*)hPt = *(Block64*)iPt;
                            Sha512Fo.Compress192SecondBlock(hPt, wPt);

                            // 2. Compute SHA512(outer_pad | hash)
                            *(Block64*)wPt = *(Block64*)hPt;
                            // The rest of wPt is set above and is unchanged

                            // Replace: sha.Init(hPt); sha.CompressBlock(hPt, oPt); with line below:
                            *(Block64*)hPt = *(Block64*)oPt;
                            Sha512Fo.Compress192SecondBlock(hPt, wPt);

                            // result of F() is XOR sum of all u arrays
                            seedPt[0] ^= hPt[0];
                            seedPt[1] ^= hPt[1];
                            seedPt[2] ^= hPt[2];
                            seedPt[3] ^= hPt[3];
                            seedPt[4] ^= hPt[4];
                            seedPt[5] ^= hPt[5];
                            seedPt[6] ^= hPt[6];
                            seedPt[7] ^= hPt[7];
                        }

                        if (SetBip32(bigBuffer, comparer))
                        {
                            report.FoundAnyResult = true;
                            string finalResult = Encoding.UTF8.GetString(new byte[] { val });
                            report.AddMessageSafe($"Passphrase is: {finalResult}");

                            return;
                        }
                    }
                }
            }
            else
            {
                report.SetProgressStep(allValues.Length);
                ParallelOptions opts = report.BuildParallelOptions();
                Parallel.For(0, allValues.Length, opts,
                    (firstItem, state) => LoopBip39(pads, ParallelSalt(salt, allValues[firstItem]), allValues, passLength, state));
            }
        }


        public bool TryDecodeMnemonic(string mnemonic, MnemonicTypes mnType, string[] allWords, out byte[] bytes)
        {
            bytes = null;
            if (string.IsNullOrWhiteSpace(mnemonic))
            {
                return report.Fail("Mnemonic can not be null or empty.");
            }
            else
            {
                string[] words = mnemonic.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (!MnemonicSearchSpace.allowedWordLengths.Contains(words.Length))
                {
                    return report.Fail("Invalid mnemonic length.");
                }

                bool invalidWord = false;
                for (int i = 0; i < words.Length; i++)
                {
                    if (!allWords.Contains(words[i]))
                    {
                        invalidWord = true;
                        report.Fail($"Given mnemonic contains invalid word at index {i} ({words[i]}).");
                    }
                }
                if (invalidWord)
                {
                    return false;
                }

                string temp = string.Join(' ', words);
                string normalized = mnType == MnemonicTypes.Electrum ? ElectrumMnemonic.Normalize(temp) : temp;

                bytes = Encoding.UTF8.GetBytes(normalized);
                return true;
            }
        }

        private bool TrySetPath(string path)
        {
            try
            {
                this.path = new BIP0032Path(path);
                return true;
            }
            catch (Exception ex)
            {
                report.Fail($"Invalid path ({ex.Message}).");
                return false;
            }
        }

        private static unsafe void SetHmacPads(byte[] mnBytes, ulong[] pads)
        {
            Debug.Assert(mnBytes != null && mnBytes.Length > 0);
            Debug.Assert(pads != null && pads.Length == 2 * Sha512Fo.HashStateSize);

            // PBKDF2:
            // compute u1 = hmac.ComputeHash(data=pbkdf2Salt/pass, key=mnemonic);
            //         u1 = SHA512(outer_pad | SHA512(inner_pad | pass | 0x00000001 ))
            // First block of each SHA512 is the pad with key already set to mnemonic so they can be pre-computed

            ulong* hPt = stackalloc ulong[Sha512Fo.UBufferSize + Sha512Fo.WorkingVectorSize];
            ulong* iPt = hPt + Sha512Fo.HashStateSize;
            ulong* oPt = hPt + Sha512Fo.UBufferSize;
            fixed (byte* mnPt = &mnBytes[0])
            fixed (ulong* rPt = &pads[0])
            {
                if (mnBytes.Length > Sha512Fo.BlockByteSize)
                {
                    // Key bytes must be hashed first
                    Sha512Fo.Init(hPt);
                    Sha512Fo.CompressData(mnPt, mnBytes.Length, mnBytes.Length, hPt, iPt);
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
                        Buffer.MemoryCopy(mnPt, tPt, Sha512Fo.BlockByteSize, mnBytes.Length);
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

                Sha512Fo.Init(hPt);
                Sha512Fo.SetW(iPt);
                Sha512Fo.CompressBlockWithWSet(hPt, iPt);
                *(Block64*)rPt = *(Block64*)hPt;

                Sha512Fo.Init(hPt);
                Sha512Fo.SetW(oPt);
                Sha512Fo.CompressBlockWithWSet(hPt, oPt);
                *(Block64*)(rPt + Sha512Fo.HashStateSize) = *(Block64*)hPt;
            }
        }

        private const int MnStartStringLen = 8;
        private const int Pbkdf2BlockNumberLength = 4;

        private bool TrySetSalt(int len, MnemonicTypes mnType, out byte[] result)
        {
            if (len < 1)
            {
                result = null;
                report.Fail("Password length must be at least 1.");
                return false;
            }

            // Each SHA512 block is 128 bytes, last 16 bytes are data length, PBKDF2 adds 4 byte block int, 
            // BIP39 and Electrum both add a string that is 8 bytes
            // Anything smaller than that is a single block. We reject big passphrases (>=100 byte) to make things simple
            // and it doesn't matter because recovering such big passphrases is already impossible!
            if (len >= Sha512Fo.BlockByteSize - 16 - Pbkdf2BlockNumberLength - MnStartStringLen)
            {
                result = null;
                report.Fail($"Password length={len} are not supported. Start a new issue on GitHub if you need this.");
                return false;
            }

            result = new byte[Sha512Fo.BlockByteSize];
            // Pad:
            result[len + MnStartStringLen + Pbkdf2BlockNumberLength] = 0b1000_0000;
            // PBKDF2 block number = 1
            result[len + MnStartStringLen + 3] = 1;
            // Salt is used in HMACSHA512 where a block (inner pad) is already compressed so total data length is +128
            int totalLen = len + MnStartStringLen + Pbkdf2BlockNumberLength + 128;
            // See SHA512 to understand why this is correct:
            result[127] = (byte)(totalLen << 3);
            result[126] = (byte)(totalLen >> 5);
            result[125] = (byte)(totalLen >> 13);
            result[124] = (byte)(totalLen >> 21);
            result[123] = (byte)(totalLen >> 29);

            byte[] start = mnType == MnemonicTypes.BIP39 ? Encoding.UTF8.GetBytes("mnemonic") : Encoding.UTF8.GetBytes("electrum");
            Debug.Assert(start.Length == MnStartStringLen);
            Buffer.BlockCopy(start, 0, result, 0, start.Length);

            return true;
        }

        public async void Find(string mnemonic, MnemonicTypes mnType, BIP0039.WordLists wl,
                               string comp, CompareInputType compType, string path, int passLength, byte[] allValues)
        {
            report.Init();

            if (mnType != MnemonicTypes.BIP39 && mnType != MnemonicTypes.Electrum)
                report.Fail("Mnemonic type is not defined.");
            if (!MnemonicSevice.TrySetWordList(wl, out string[] allWords, out int maxWordLen))
                report.Fail($"Could not find {wl} word list among resources.");
            else if (!TryDecodeMnemonic(mnemonic, mnType, allWords, out byte[] mnBytes))
                return;
            else if (!TrySetPath(path))
                return;
            else if (!InputService.TryGetCompareService(compType, comp, out comparer))
                report.Fail($"Invalid extra input or input type {compType}.");
            else if (!TrySetSalt(passLength, mnType, out byte[] salt))
                return;
            else
            {
                ulong[] pads = new ulong[16];
                SetHmacPads(mnBytes, pads);

                report.SetTotal(allValues.Length, passLength);
                report.Timer.Start();

                await Task.Run(() => MainLoop(pads, salt, allValues, passLength));

                report.Finalize();
            }
        }
    }
}
