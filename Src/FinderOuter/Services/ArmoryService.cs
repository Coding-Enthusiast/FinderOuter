// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using Autarkysoft.Bitcoin.Cryptography.Asymmetric.EllipticCurve;
using Autarkysoft.Bitcoin.Cryptography.EllipticCurve;
using FinderOuter.Backend;
using FinderOuter.Backend.Hashing;
using FinderOuter.Models;
using FinderOuter.Services.Comparers;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace FinderOuter.Services
{
    public class ArmoryService
    {
        public ArmoryService(IReport rep)
        {
            report = rep;
        }



        private readonly IReport report;
        private readonly Calc calc = new();

        private ICompareService comparer;
        private int[] missingIndexes;
        private bool hasChainCode;
        private byte[] chainCode;
        private readonly BigInteger N = new SecP256k1().N;



        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe bool MoveNext(byte* items, int len)
        {
            for (int i = len - 1; i >= 0; --i)
            {
                items[i] += 1;

                if (items[i] == 16)
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

        private unsafe void SetResult(byte* kPt)
        {
            string res = EncodeFull(new ReadOnlySpan<byte>(kPt, 32));
            report.AddMessageSafe($"Found the correct recovery phrase:{Environment.NewLine}{res}");
            report.FoundAnyResult = true;
        }


        private unsafe Scalar8x32 ComputeKey(uint* pt, byte* kPt)
        {
            uint* oPt = pt + Sha256Fo.UBufferSize;

            byte[] chainCode;
            if (hasChainCode)
            {
                chainCode = this.chainCode;
            }
            else
            {
                // Compute chain-code
                // h1 = SHA256( SHA256(SHA256(key)) XOR 0x36 | "Derive Chaincode from Root Key")
                // Chain-code = SHA256( SHA256(SHA256(key)) XOR 0x5c | h1)
                Sha256Fo.Init(pt);
                pt[8] = (uint)((kPt[0] << 24) | (kPt[1] << 16) | (kPt[2] << 8) | kPt[3]);
                pt[9] = (uint)((kPt[4] << 24) | (kPt[5] << 16) | (kPt[6] << 8) | kPt[7]);
                pt[10] = (uint)((kPt[8] << 24) | (kPt[9] << 16) | (kPt[10] << 8) | kPt[11]);
                pt[11] = (uint)((kPt[12] << 24) | (kPt[13] << 16) | (kPt[14] << 8) | kPt[15]);
                pt[12] = (uint)((kPt[16] << 24) | (kPt[17] << 16) | (kPt[18] << 8) | kPt[19]);
                pt[13] = (uint)((kPt[20] << 24) | (kPt[21] << 16) | (kPt[22] << 8) | kPt[23]);
                pt[14] = (uint)((kPt[24] << 24) | (kPt[25] << 16) | (kPt[26] << 8) | kPt[27]);
                pt[15] = (uint)((kPt[28] << 24) | (kPt[29] << 16) | (kPt[30] << 8) | kPt[31]);
                pt[16] = 0b10000000_00000000_00000000_00000000U;
                // From 9 to 14 remain 0
                pt[23] = 256;

                Sha256Fo.CompressDouble32(pt);

                // Use hPt in both iPt and oPt here before it is changed
                oPt[0] = pt[0] ^ 0x5c5c5c5cU;
                oPt[1] = pt[1] ^ 0x5c5c5c5cU;
                oPt[2] = pt[2] ^ 0x5c5c5c5cU;
                oPt[3] = pt[3] ^ 0x5c5c5c5cU;
                oPt[4] = pt[4] ^ 0x5c5c5c5cU;
                oPt[5] = pt[5] ^ 0x5c5c5c5cU;
                oPt[6] = pt[6] ^ 0x5c5c5c5cU;
                oPt[7] = pt[7] ^ 0x5c5c5c5cU;

                pt[8] = pt[0] ^ 0x36363636U;
                pt[9] = pt[1] ^ 0x36363636U;
                pt[10] = pt[2] ^ 0x36363636U;
                pt[11] = pt[3] ^ 0x36363636U;
                pt[12] = pt[4] ^ 0x36363636U;
                pt[13] = pt[5] ^ 0x36363636U;
                pt[14] = pt[6] ^ 0x36363636U;
                pt[15] = pt[7] ^ 0x36363636U;
                pt[16] = 0x44657269;  // Deri
                pt[17] = 0x76652043;  // ve C
                pt[18] = 0x6861696e; // hain
                pt[19] = 0x636f6465; // code
                pt[20] = 0x2066726f; //  fro
                pt[21] = 0x6d20526f; // m Ro
                pt[22] = 0x6f74204b; // ot K
                pt[23] = 0x65798000; // ey + 0x80 pad

                Sha256Fo.Init(pt);
                Sha256Fo.SetW(pt + Sha256Fo.HashStateSize);
                Sha256Fo.CompressBlockWithWSet(pt);

                pt[8] = 0;
                pt[9] = 0;
                pt[10] = 0;
                pt[11] = 0;
                pt[12] = 0;
                pt[13] = 0;
                pt[14] = 0;
                pt[15] = 0;
                pt[16] = 0;
                pt[17] = 0;
                pt[18] = 0;
                pt[19] = 0;
                pt[20] = 0;
                pt[21] = 0;
                pt[22] = 0;
                pt[23] = 496; // 32+30 * 8

                Sha256Fo.Compress62SecondBlock(pt);

                *(Block32*)(pt + Sha256Fo.HashStateSize) = *(Block32*)oPt;
                *(Block32*)(pt + Sha256Fo.HashStateSize + 8) = *(Block32*)pt;

                Sha256Fo.Init(pt);
                Sha256Fo.SetW(pt + Sha256Fo.HashStateSize);
                Sha256Fo.CompressBlockWithWSet(pt);

                pt[8] = 0b10000000_00000000_00000000_00000000U;
                pt[9] = 0;
                pt[10] = 0;
                pt[11] = 0;
                pt[12] = 0;
                pt[13] = 0;
                pt[14] = 0;
                pt[15] = 0;
                pt[16] = 0;
                pt[17] = 0;
                pt[18] = 0;
                pt[19] = 0;
                pt[20] = 0;
                pt[21] = 0;
                pt[22] = 0;
                pt[23] = 512; // 32+32 * 8

                Sha256Fo.Compress64SecondBlock(pt);

                // TODO: this could be improved a bit
                chainCode = Sha256Fo.GetBytes(pt);
            }

            // hPt is chain-code now
            ReadOnlySpan<byte> key = new(kPt, 32);
            Scalar8x32 scalar = new(key, out bool overflow);
            Debug.Assert(!overflow);

            Span<byte> pubBa = calc.GetPubkey(scalar, false);
            Debug.Assert(pubBa.Length == 65);

            Span<byte> chainXor = Sha256Fo.CompressDouble65(pubBa);
            for (int i = 0; i < chainXor.Length; i++)
            {
                chainXor[i] ^= chainCode[i];
            }

            Scalar8x32 A = new(chainXor, out _);
            Scalar8x32 secexp = scalar.Multiply(A);
            return secexp;
        }


        private unsafe void Loop2(byte[] preComputed, int missCount1, int missCount2,
                                  uint mask1, uint mask2, uint comp1, uint comp2)
        {
            // Note that in the following context HMAC is NOT HMACSHA256 despite the name
            // because it is using wrong inner/outer pads. For reference:
            // https://github.com/etotheipi/BitcoinArmory/blob/2a6fc5355bb0c6fe26e387ccba30a5baafe8cd98/armoryengine/ArmoryUtils.py#L1823

            // ChainCode is result of HMAC with 2x hash of private key as HMAC key 
            // and "Derive Chaincode from Root Key" as its message

            byte* kPt = stackalloc byte[32 + missingIndexes.Length];
            byte* item1 = kPt + 32;
            byte* item2 = item1 + missCount1;
            uint* pt = stackalloc uint[Sha256Fo.UBufferSize + 8];
            fixed (byte* pre = &preComputed[0])
            fixed (int* mi = &missingIndexes[0])
            {
                do
                {
                    *(Block32*)kPt = *(Block32*)pre;
                    int mIndex = 0;
                    for (int i = 0; i < missCount1; i++)
                    {
                        int index = mi[mIndex++];
                        kPt[index / 2] |= (index % 2 == 0) ? (byte)(item1[i] << 4) : item1[i];
                    }

                    pt[8] = (uint)((kPt[0] << 24) | (kPt[1] << 16) | (kPt[2] << 8) | kPt[3]);
                    pt[9] = (uint)((kPt[4] << 24) | (kPt[5] << 16) | (kPt[6] << 8) | kPt[7]);
                    pt[10] = (uint)((kPt[8] << 24) | (kPt[9] << 16) | (kPt[10] << 8) | kPt[11]);
                    pt[11] = (uint)((kPt[12] << 24) | (kPt[13] << 16) | (kPt[14] << 8) | kPt[15]);
                    pt[12] = 0b10000000_00000000_00000000_00000000U;
                    pt[13] = 0;
                    pt[14] = 0;
                    pt[15] = 0;
                    pt[16] = 0;
                    // From 9 to 14 remain 0
                    pt[23] = 128;

                    Sha256Fo.Init(pt);
                    Sha256Fo.CompressDouble16(pt);

                    if ((pt[0] & mask1) == comp1)
                    {
                        int mIndexInternal = mIndex;
                        do
                        {
                            for (int i = 0; i < missCount2; i++)
                            {
                                int index = mi[mIndex++];
                                kPt[(index / 2) + 16] |= (index % 2 == 0) ? (byte)(item2[i] << 4) : item2[i];
                            }

                            pt[8] = (uint)((kPt[16] << 24) | (kPt[17] << 16) | (kPt[18] << 8) | kPt[19]);
                            pt[9] = (uint)((kPt[20] << 24) | (kPt[21] << 16) | (kPt[22] << 8) | kPt[23]);
                            pt[10] = (uint)((kPt[24] << 24) | (kPt[25] << 16) | (kPt[26] << 8) | kPt[27]);
                            pt[11] = (uint)((kPt[28] << 24) | (kPt[29] << 16) | (kPt[30] << 8) | kPt[31]);
                            pt[12] = 0b10000000_00000000_00000000_00000000U;
                            pt[13] = 0;
                            pt[14] = 0;
                            pt[15] = 0;
                            pt[16] = 0;
                            // From 9 to 14 remain 0
                            pt[23] = 128;

                            Sha256Fo.Init(pt);
                            Sha256Fo.CompressDouble16(pt);

                            if ((pt[0] & mask2) == comp2)
                            {
                                Scalar8x32 secexp = ComputeKey(pt, kPt);
                                if (comparer.Compare(secexp))
                                {
                                    SetResult(kPt);
                                    return;
                                }
                            }

                            // Reset second part for next round
                            *(Block16*)(kPt + 16) = *(Block16*)(pre + 16);
                            mIndex = mIndexInternal;

                        } while (MoveNext(item2, missCount2));

                        // Checking second line reached the end and failed, item2 must be reset to 0
                        for (int i = 0; i < missCount2; i++)
                        {
                            item2[i] = 0;
                        }
                    }
                } while (MoveNext(item1, missCount1));
            }
        }


        private unsafe void Loop2NoCS(byte[] preComputed, int missCount1, int missCount2)
        {
            byte* kPt = stackalloc byte[32 + missingIndexes.Length];
            byte* item1 = kPt + 32;
            byte* item2 = item1 + missCount1;
            uint* pt = stackalloc uint[Sha256Fo.UBufferSize + 8];
            fixed (byte* pre = &preComputed[0])
            fixed (int* mi = &missingIndexes[0])
            {
                do
                {
                    *(Block32*)kPt = *(Block32*)pre;
                    int mIndex = 0;
                    for (int i = 0; i < missCount1; i++)
                    {
                        int index = mi[mIndex++];
                        kPt[index / 2] |= (index % 2 == 0) ? (byte)(item1[i] << 4) : item1[i];
                    }

                    int mIndexInternal = mIndex;
                    do
                    {
                        for (int i = 0; i < missCount2; i++)
                        {
                            int index = mi[mIndex++];
                            kPt[(index / 2) + 16] |= (index % 2 == 0) ? (byte)(item2[i] << 4) : item2[i];
                        }

                        Scalar8x32 secexp = ComputeKey(pt, kPt);
                        if (comparer.Compare(secexp))
                        {
                            SetResult(kPt);
                            return;
                        }

                        // Reset second part for next round
                        *(Block16*)(kPt + 16) = *(Block16*)(pre + 16);
                        mIndex = mIndexInternal;

                    } while (MoveNext(item2, missCount2));

                    // Checking second line reached the end and failed, item2 must be reset to 0
                    for (int i = 0; i < missCount2; i++)
                    {
                        item2[i] = 0;
                    }
                } while (MoveNext(item1, missCount1));
            }
        }

        private unsafe void Loop2NoCS2(byte[] preComputed, int missCount1, int missCount2, uint mask1, uint cs1)
        {
            byte* kPt = stackalloc byte[32 + missingIndexes.Length];
            byte* item1 = kPt + 32;
            byte* item2 = item1 + missCount1;
            uint* pt = stackalloc uint[Sha256Fo.UBufferSize + 8];
            fixed (byte* pre = &preComputed[0])
            fixed (int* mi = &missingIndexes[0])
            {
                do
                {
                    *(Block32*)kPt = *(Block32*)pre;
                    int mIndex = 0;
                    for (int i = 0; i < missCount1; i++)
                    {
                        int index = mi[mIndex++];
                        kPt[index / 2] |= (index % 2 == 0) ? (byte)(item1[i] << 4) : item1[i];
                    }

                    pt[8] = (uint)((kPt[0] << 24) | (kPt[1] << 16) | (kPt[2] << 8) | kPt[3]);
                    pt[9] = (uint)((kPt[4] << 24) | (kPt[5] << 16) | (kPt[6] << 8) | kPt[7]);
                    pt[10] = (uint)((kPt[8] << 24) | (kPt[9] << 16) | (kPt[10] << 8) | kPt[11]);
                    pt[11] = (uint)((kPt[12] << 24) | (kPt[13] << 16) | (kPt[14] << 8) | kPt[15]);
                    pt[12] = 0b10000000_00000000_00000000_00000000U;
                    pt[13] = 0;
                    pt[14] = 0;
                    pt[15] = 0;
                    pt[16] = 0;
                    // From 9 to 14 remain 0
                    pt[23] = 128;

                    Sha256Fo.Init(pt);
                    Sha256Fo.CompressDouble16(pt);

                    if ((pt[0] & mask1) == cs1)
                    {
                        int mIndexInternal = mIndex;
                        do
                        {
                            for (int i = 0; i < missCount2; i++)
                            {
                                int index = mi[mIndex++];
                                kPt[(index / 2) + 16] |= (index % 2 == 0) ? (byte)(item2[i] << 4) : item2[i];
                            }

                            // Second checksum is missing so we can't compute second part's hash to reject invalid
                            // keys, instead all keys must be checked using the ICompareService instance.
                            Scalar8x32 secexp = ComputeKey(pt, kPt);
                            if (comparer.Compare(secexp))
                            {
                                SetResult(kPt);
                                return;
                            }

                            // Reset second part for next round
                            *(Block16*)(kPt + 16) = *(Block16*)(pre + 16);
                            mIndex = mIndexInternal;

                        } while (MoveNext(item2, missCount2));

                        // Checking second line reached the end and failed, item2 must be reset to 0
                        for (int i = 0; i < missCount2; i++)
                        {
                            item2[i] = 0;
                        }
                    }
                } while (MoveNext(item1, missCount1));
            }
        }

        private unsafe void Loop2NoCS1(byte[] preComputed, int missCount1, int missCount2, uint mask2, uint cs2)
        {
            byte* kPt = stackalloc byte[32 + missingIndexes.Length];
            byte* item1 = kPt + 32;
            byte* item2 = item1 + missCount1;
            uint* pt = stackalloc uint[Sha256Fo.UBufferSize + 8];
            fixed (byte* pre = &preComputed[0])
            fixed (int* mi = &missingIndexes[0])
            {
                do
                {
                    *(Block32*)kPt = *(Block32*)pre;
                    int mIndex = 0;
                    for (int i = 0; i < missCount1; i++)
                    {
                        int index = mi[mIndex++];
                        kPt[index / 2] |= (index % 2 == 0) ? (byte)(item1[i] << 4) : item1[i];
                    }

                    // First checksum is missing so we can't compute first part's hash to reject invalid
                    // keys, instead all keys must be checked using the ICompareService instance.

                    int mIndexInternal = mIndex;
                    do
                    {
                        for (int i = 0; i < missCount2; i++)
                        {
                            int index = mi[mIndex++];
                            kPt[(index / 2) + 16] |= (index % 2 == 0) ? (byte)(item2[i] << 4) : item2[i];
                        }

                        pt[8] = (uint)((kPt[16] << 24) | (kPt[17] << 16) | (kPt[18] << 8) | kPt[19]);
                        pt[9] = (uint)((kPt[20] << 24) | (kPt[21] << 16) | (kPt[22] << 8) | kPt[23]);
                        pt[10] = (uint)((kPt[24] << 24) | (kPt[25] << 16) | (kPt[26] << 8) | kPt[27]);
                        pt[11] = (uint)((kPt[28] << 24) | (kPt[29] << 16) | (kPt[30] << 8) | kPt[31]);
                        pt[12] = 0b10000000_00000000_00000000_00000000U;
                        pt[13] = 0;
                        pt[14] = 0;
                        pt[15] = 0;
                        pt[16] = 0;
                        // From 9 to 14 remain 0
                        pt[23] = 128;

                        Sha256Fo.Init(pt);
                        Sha256Fo.CompressDouble16(pt);

                        Scalar8x32 secexp = ComputeKey(pt, kPt);
                        if (comparer.Compare(secexp))
                        {
                            SetResult(kPt);
                            return;
                        }

                        // Reset second part for next round
                        *(Block16*)(kPt + 16) = *(Block16*)(pre + 16);
                        mIndex = mIndexInternal;

                    } while (MoveNext(item2, missCount2));

                    // Checking second line reached the end and failed, item2 must be reset to 0
                    for (int i = 0; i < missCount2; i++)
                    {
                        item2[i] = 0;
                    }
                } while (MoveNext(item1, missCount1));
            }
        }



        private static BigInteger GetTotalCount(int missCount) => BigInteger.Pow(16, missCount);

        private static string EncodeLineWithChecksum(ReadOnlySpan<byte> data)
        {
            Debug.Assert(data.Length == 16);

            byte[] full = new byte[18];
            Buffer.BlockCopy(data.ToArray(), 0, full, 0, data.Length);

            byte[] cs = Sha256Fo.ComputeHashTwice(data.ToArray()).SubArray(0, 2);
            full[16] = cs[0];
            full[17] = cs[1];

            return EncodeLine(full);
        }

        private static string EncodeLine(ReadOnlySpan<byte> data)
        {
            Debug.Assert(data.Length == 18);

            Span<char> result = new char[44];
            result.Fill(' ');
            for (int i = 0, j = 0; i < data.Length; i += 2, j += 5)
            {
                int x = data[i];
                result[j] = ConstantsFO.ArmoryChars[x >> 4];
                result[j + 1] = ConstantsFO.ArmoryChars[x & 0b1111];

                x = data[i + 1];
                result[j + 2] = ConstantsFO.ArmoryChars[x >> 4];
                result[j + 3] = ConstantsFO.ArmoryChars[x & 0b1111];
            }
            return new string(result);
        }

        private static string EncodeFull(ReadOnlySpan<byte> data)
        {
            Debug.Assert(data.Length == 32);
            return $"{EncodeLineWithChecksum(data.Slice(0, 16))}{Environment.NewLine}{EncodeLineWithChecksum(data.Slice(16, 16))}";
        }

        private static void Split(ReadOnlySpan<char> s, byte[] data, int offset, out int[] missIndex, out uint cs, out uint mask)
        {
            Debug.Assert(s.Length == 36);

            List<int> temp = new(36);
            for (int i = 0; i < 32; i++)
            {
                int index = ConstantsFO.ArmoryChars.IndexOf(s[i]);
                if (index < 0)
                {
                    temp.Add(i);
                }
                else
                {
                    data[offset + (i / 2)] |= (i % 2) == 0 ? (byte)(index << 4) : (byte)index;
                }
            }

            cs = 0;
            mask = 0;
            for (int i = 32, j = 28; i < 36; i++, j -= 4)
            {
                int index = ConstantsFO.ArmoryChars.IndexOf(s[i]);
                if (index >= 0)
                {
                    cs |= (uint)index << j;
                    mask |= (uint)0xf << j;
                }
            }

            missIndex = temp.ToArray();
        }


        public async void FindMissing(string phrase, char missChar, string comp, CompareInputType compType)
        {
            report.Init();

            if (!InputService.IsMissingCharValid(missChar))
                report.Fail("Missing character is not accepted.");
            else if (!InputService.TryGetCompareService(compType, comp, out comparer))
                report.Fail($"Invalid extra input or input type {compType}.");
            else if (string.IsNullOrWhiteSpace(phrase))
                report.Fail("Recovery phrase can not be null or empty.");
            else
            {
                // (There may be more but since Armory doesn't have any documentation, it is hard to figure out)
                // Armory recovery phrases (that we support for now) are either 2 lines or 4.
                // Each line is 36 chars or 18 bytes split into groups of 2 bytes (4 chars).
                // First 16 bytes is the data, the remaining 2 bytes is checksum.
                // The first 2 lines are the private key.
                // The second 2 lines are the chain code. If it exists then chain-code is randomly generated
                // (unrelated to private key), if it doesn't then it is derived from private key.

                string[] lines = phrase.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries)
                                       .Select(x => x = x.Replace(" ", ""))
                                       .ToArray();

                if (lines.Length != 2 && lines.Length != 4)
                {
                    report.Fail("Armory back ups are either 2 lines or 4 lines.");
                }
                else if (lines.Any(x => x.Length != 36))
                {
                    report.Fail("Each line has to have 36 characters representing 18 bytes.");
                }
                else if (lines.Any(line => line.Any(c => !ConstantsFO.ArmoryChars.Contains(c) && c != missChar)))
                {
                    report.Fail("Input contains invalid characters.");
                }
                else
                {
                    byte[] key = new byte[32];
                    Split(lines[0], key, 0, out int[] miss1, out uint cs1, out uint mask1);
                    Split(lines[1], key, 16, out int[] miss2, out uint cs2, out uint mask2);

                    int missCount = miss1.Length + miss2.Length;

                    if (missCount == 0)
                    {
                        report.AddMessageSafe("The given recovery phrase isn't missing any characters.");
                        if (mask1 != 0xffff0000)
                        {
                            report.AddMessageSafe("First line of the given recovery phrase is missing its checksum.");
                            report.AddMessageSafe(EncodeLineWithChecksum(key.SubArray(0, 16)));
                        }
                        if (mask2 != 0xffff0000)
                        {
                            report.AddMessageSafe("Second line of the given recovery phrase is missing its checksum.");
                            report.AddMessageSafe(EncodeLineWithChecksum(key.SubArray(16, 16)));
                        }

                        report.Finalize(true);
                        return;
                    }

                    report.AddMessageSafe($"Given phrase is missing {missCount:n0} characters.");
                    report.AddMessageSafe($"A total of {GetTotalCount(missCount):n0} phrases should be checked.");

                    missingIndexes = new int[missCount];
                    Array.Copy(miss1, 0, missingIndexes, 0, miss1.Length);
                    Array.Copy(miss2, 0, missingIndexes, miss1.Length, miss2.Length);

                    Stopwatch watch = Stopwatch.StartNew();

                    if (lines.Length == 4)
                    {
                        // We only support the case where chain-code is known
                        // TODO: maybe change this in the future?
                        chainCode = new byte[32];
                        Split(lines[2], chainCode, 0, out int[] ccMiss1, out _, out uint ccMask1);
                        Split(lines[3], chainCode, 16, out int[] ccMiss2, out _, out uint ccMask2);
                        if (ccMiss1.Length + ccMiss2.Length != 0)
                        {
                            report.AddMessageSafe("FinderOuter currently doesn't support recovering chain-code." +
                                                  "Open a new issue if you need this feature.");
                            report.Finalize(false);
                            return;
                        }
                        if (ccMask1 != 0xffff0000)
                        {
                            report.AddMessageSafe("Third line of the given recovery phrase is missing its checksum.");
                            report.AddMessageSafe(EncodeLineWithChecksum(chainCode.SubArray(0, 16)));
                        }
                        if (ccMask2 != 0xffff0000)
                        {
                            report.AddMessageSafe("Forth line of the given recovery phrase is missing its checksum.");
                            report.AddMessageSafe(EncodeLineWithChecksum(chainCode.SubArray(16, 16)));
                        }
                        hasChainCode = true;
                    }
                    else
                    {
                        hasChainCode = false;
                        chainCode = null;
                    }

                    if (mask1 != 0 && mask2 != 0)
                    {
                        await Task.Run(() => Loop2(key, miss1.Length, miss2.Length, mask1, mask2, cs1, cs2));
                    }
                    else if (mask1 != 0)
                    {
                        await Task.Run(() => Loop2NoCS2(key, miss1.Length, miss2.Length, mask1, cs1));
                    }
                    else if (mask2 != 0)
                    {
                        await Task.Run(() => Loop2NoCS1(key, miss1.Length, miss2.Length, mask2, cs2));
                    }
                    else
                    {
                        await Task.Run(() => Loop2NoCS(key, miss1.Length, miss2.Length));
                    }

                    watch.Stop();

                    report.AddMessageSafe($"Elapsed time: {watch.Elapsed}");
                    report.SetKeyPerSecSafe(GetTotalCount(missCount), watch.Elapsed.TotalSeconds);
                }

                report.Finalize();
            }
        }
    }
}
