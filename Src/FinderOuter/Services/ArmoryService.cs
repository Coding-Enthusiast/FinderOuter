// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using Autarkysoft.Bitcoin.Cryptography.Asymmetric.EllipticCurve;
using FinderOuter.Backend;
using FinderOuter.Backend.Cryptography.Asymmetric.EllipticCurve;
using FinderOuter.Backend.Cryptography.Hashing;
using FinderOuter.Models;
using FinderOuter.Services.Comparers;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace FinderOuter.Services
{
    public class ArmoryService
    {
        public ArmoryService(IReport rep)
        {
            report = rep;
            inputService = new InputService();
            calc = new ECCalc();
        }



        private readonly IReport report;
        private readonly InputService inputService;
        private readonly ECCalc calc;

        private ICompareService comparer;
        private int[] missingIndexes;
        private readonly BigInteger N = new SecP256k1().N;



        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private unsafe bool MoveNext(byte* items, int len)
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


        private unsafe void Loop2(byte[] preComputed, int missCount1, int missCount2,
                                  uint mask1, uint mask2, uint comp1, uint comp2)
        {
            // Note that in the following context HMAC is NOT HMACSHA256 despite the name
            // because it is using wrong inner/outer pads. For reference:
            // https://github.com/etotheipi/BitcoinArmory/blob/2a6fc5355bb0c6fe26e387ccba30a5baafe8cd98/armoryengine/ArmoryUtils.py#L1823

            // ChainCode is result of HMAC with 2x hash of private key as HMAC key 
            // and "Derive Chaincode from Root Key" as its message
            byte[] message = Encoding.UTF8.GetBytes("Derive Chaincode from Root Key");

            using Sha256Fo sha = new Sha256Fo();
            byte* kPt = stackalloc byte[32 + missingIndexes.Length];
            byte* item1 = kPt + 32;
            byte* item2 = item1 + missCount1;
            uint* oPt = stackalloc uint[8];
            fixed (byte* pre = &preComputed[0])
            fixed (int* mi = &missingIndexes[0])
            fixed (uint* wPt = &sha.w[0], hPt = &sha.hashState[0])
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

                    wPt[0] = (uint)((kPt[0] << 24) | (kPt[1] << 16) | (kPt[2] << 8) | kPt[3]);
                    wPt[1] = (uint)((kPt[4] << 24) | (kPt[5] << 16) | (kPt[6] << 8) | kPt[7]);
                    wPt[2] = (uint)((kPt[8] << 24) | (kPt[9] << 16) | (kPt[10] << 8) | kPt[11]);
                    wPt[3] = (uint)((kPt[12] << 24) | (kPt[13] << 16) | (kPt[14] << 8) | kPt[15]);
                    wPt[4] = 0b10000000_00000000_00000000_00000000U;
                    wPt[5] = 0;
                    wPt[6] = 0;
                    wPt[7] = 0;
                    wPt[8] = 0;
                    // From 9 to 14 remain 0
                    wPt[15] = 128;

                    sha.Init(hPt);
                    sha.CompressDouble16(hPt, wPt);

                    if ((hPt[0] & mask1) == comp1)
                    {
                        int mIndexInternal = mIndex;
                        do
                        {
                            mIndex = mIndexInternal;
                            for (int i = 0; i < missCount2; i++)
                            {
                                int index = mi[mIndex++];
                                kPt[(index / 2) + 16] |= (index % 2 == 0) ? (byte)(item2[i] << 4) : item2[i];
                            }

                            wPt[0] = (uint)((kPt[16] << 24) | (kPt[17] << 16) | (kPt[18] << 8) | kPt[19]);
                            wPt[1] = (uint)((kPt[20] << 24) | (kPt[21] << 16) | (kPt[22] << 8) | kPt[23]);
                            wPt[2] = (uint)((kPt[24] << 24) | (kPt[25] << 16) | (kPt[26] << 8) | kPt[27]);
                            wPt[3] = (uint)((kPt[28] << 24) | (kPt[29] << 16) | (kPt[30] << 8) | kPt[31]);
                            wPt[4] = 0b10000000_00000000_00000000_00000000U;
                            wPt[5] = 0;
                            wPt[6] = 0;
                            wPt[7] = 0;
                            wPt[8] = 0;
                            // From 9 to 14 remain 0
                            wPt[15] = 128;

                            sha.Init(hPt);
                            sha.CompressDouble16(hPt, wPt);

                            if ((hPt[0] & mask2) == comp2)
                            {
                                // Compute chain-code
                                // h1 = SHA256( SHA256(SHA256(key)) XOR 0x36 | "Derive Chaincode from Root Key")
                                // Chain-code = SHA256( SHA256(SHA256(key)) XOR 0x5c | h1)
                                sha.Init(hPt);
                                wPt[0] = (uint)((kPt[0] << 24) | (kPt[1] << 16) | (kPt[2] << 8) | kPt[3]);
                                wPt[1] = (uint)((kPt[4] << 24) | (kPt[5] << 16) | (kPt[6] << 8) | kPt[7]);
                                wPt[2] = (uint)((kPt[8] << 24) | (kPt[9] << 16) | (kPt[10] << 8) | kPt[11]);
                                wPt[3] = (uint)((kPt[12] << 24) | (kPt[13] << 16) | (kPt[14] << 8) | kPt[15]);
                                wPt[4] = (uint)((kPt[16] << 24) | (kPt[17] << 16) | (kPt[18] << 8) | kPt[19]);
                                wPt[5] = (uint)((kPt[20] << 24) | (kPt[21] << 16) | (kPt[22] << 8) | kPt[23]);
                                wPt[6] = (uint)((kPt[24] << 24) | (kPt[25] << 16) | (kPt[26] << 8) | kPt[27]);
                                wPt[7] = (uint)((kPt[28] << 24) | (kPt[29] << 16) | (kPt[30] << 8) | kPt[31]);
                                wPt[8] = 0b10000000_00000000_00000000_00000000U;
                                // From 9 to 14 remain 0
                                wPt[15] = 256;

                                sha.CompressDouble32(hPt, wPt);

                                // Use hPt in both iPt and oPt here before it is changed
                                oPt[0] = hPt[0] ^ 0x5c5c5c5cU;
                                oPt[1] = hPt[1] ^ 0x5c5c5c5cU;
                                oPt[2] = hPt[2] ^ 0x5c5c5c5cU;
                                oPt[3] = hPt[3] ^ 0x5c5c5c5cU;
                                oPt[4] = hPt[4] ^ 0x5c5c5c5cU;
                                oPt[5] = hPt[5] ^ 0x5c5c5c5cU;
                                oPt[6] = hPt[6] ^ 0x5c5c5c5cU;
                                oPt[7] = hPt[7] ^ 0x5c5c5c5cU;

                                wPt[0] = hPt[0] ^ 0x36363636U;
                                wPt[1] = hPt[1] ^ 0x36363636U;
                                wPt[2] = hPt[2] ^ 0x36363636U;
                                wPt[3] = hPt[3] ^ 0x36363636U;
                                wPt[4] = hPt[4] ^ 0x36363636U;
                                wPt[5] = hPt[5] ^ 0x36363636U;
                                wPt[6] = hPt[6] ^ 0x36363636U;
                                wPt[7] = hPt[7] ^ 0x36363636U;
                                wPt[8] = 0x44657269;  // Deri
                                wPt[9] = 0x76652043;  // ve C
                                wPt[10] = 0x6861696e; // hain
                                wPt[11] = 0x636f6465; // code
                                wPt[12] = 0x2066726f; //  fro
                                wPt[13] = 0x6d20526f; // m Ro
                                wPt[14] = 0x6f74204b; // ot K
                                wPt[15] = 0x65798000; // ey + 0x80 pad

                                sha.Init(hPt);
                                sha.CompressBlock(hPt, wPt);

                                wPt[0] = 0;
                                wPt[1] = 0;
                                wPt[2] = 0;
                                wPt[3] = 0;
                                wPt[4] = 0;
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
                                wPt[15] = 496; // 32+30 * 8

                                sha.Compress62SecondBlock(hPt, wPt);

                                *(Block32*)wPt = *(Block32*)oPt;
                                wPt[8] = hPt[0];
                                wPt[9] = hPt[1];
                                wPt[10] = hPt[2];
                                wPt[11] = hPt[3];
                                wPt[12] = hPt[4];
                                wPt[13] = hPt[5];
                                wPt[14] = hPt[6];
                                wPt[15] = hPt[7];

                                sha.Init(hPt);
                                sha.CompressBlock(hPt, wPt);

                                wPt[0] = 0b10000000_00000000_00000000_00000000U;
                                wPt[1] = 0;
                                wPt[2] = 0;
                                wPt[3] = 0;
                                wPt[4] = 0;
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
                                wPt[15] = 512; // 32+32 * 8

                                sha.Compress64SecondBlock(hPt, wPt);


                                // hPt is chain-code now
                                ReadOnlySpan<byte> key = new ReadOnlySpan<byte>(kPt, 32);
                                BigInteger k = new BigInteger(key, true, true);
                                EllipticCurvePoint point = calc.MultiplyByG(k);
                                byte[] pubBa = new byte[65];
                                pubBa[0] = 4;
                                byte[] xBytes = point.X.ToByteArray(true, true);
                                byte[] yBytes = point.Y.ToByteArray(true, true);
                                Buffer.BlockCopy(xBytes, 0, pubBa, 33 - xBytes.Length, xBytes.Length);
                                Buffer.BlockCopy(yBytes, 0, pubBa, 65 - yBytes.Length, yBytes.Length);

                                // TODO: this could be improved a bit
                                byte[] temp = sha.GetBytes(hPt);

                                byte[] chainXor = sha.CompressDouble65(pubBa);

                                for (var i = 0; i < chainXor.Length; i++)
                                {
                                    chainXor[i] ^= temp[i];
                                }

                                BigInteger A = new BigInteger(chainXor, true, true);
                                BigInteger B = new BigInteger(key, true, true);

                                BigInteger secexp = (A * B).Mod(N);
                                if (comparer.Compare(secexp))
                                {
                                    SetResult(kPt);
                                    return;
                                }
                            }
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

        }

        private void Loop2NoCS2(byte[] preComputed, int missCount1, int missCount2, uint mask1, uint cs1)
        {

        }

        private void Loop2NoCS1(byte[] preComputed, int missCount1, int missCount2, uint mask2, uint cs2)
        {

        }



        private static BigInteger GetTotalCount(int missCount) => BigInteger.Pow(16, missCount);

        private static string EncodeLineWithChecksum(ReadOnlySpan<byte> data)
        {
            Debug.Assert(data.Length == 16);

            byte[] full = new byte[18];
            Buffer.BlockCopy(data.ToArray(), 0, full, 0, data.Length);

            using Sha256Fo sha256 = new Sha256Fo(true);
            byte[] cs = sha256.ComputeHash(data.ToArray()).SubArray(0, 2);
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

            List<int> temp = new List<int>(36);
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


        public async void FindMissing(string phrase, char missChar, string extra, InputType extraType)
        {
            report.Init();

            if (!inputService.IsMissingCharValid(missChar))
                report.Fail("Missing character is not accepted.");
            else if (!inputService.TryGetCompareService(extraType, extra, out comparer))
                report.Fail($"Invalid extra input or input type {extraType}.");
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
                    return;
                }
                if (lines.Any(x => x.Length != 36))
                {
                    report.Fail("Each line has to have 36 characters representing 18 bytes.");
                    return;
                }
                if (lines.Any(line => line.Any(c => !ConstantsFO.ArmoryChars.Contains(c) && c != missChar)))
                {
                    report.Fail("Input contains invalid characters.");
                    return;
                }

                byte[] key = new byte[32];
                Split(lines[0], key, 0, out int[] miss1, out uint cs1, out uint mask1);
                Split(lines[1], key, 16, out int[] miss2, out uint cs2, out uint mask2);

                int missCount = miss1.Length + miss2.Length;

                if (missCount == 0)
                {
                    report.AddMessageSafe("The given recovery phrase isn't missing any characters.");
                    if (mask1 != 0)
                    {
                        report.AddMessageSafe("First line of the given recovery phrase is missing its checksum.");
                        report.AddMessageSafe(EncodeLineWithChecksum(key.SubArray(0, 16)));
                    }
                    if (mask2 != 0)
                    {
                        report.AddMessageSafe("Second line of the given recovery phrase is missing its checksum.");
                        report.AddMessageSafe(EncodeLineWithChecksum(key.SubArray(16, 16)));
                    }

                    return;
                }

                report.AddMessageSafe($"A total of {GetTotalCount(missCount):n0} phrases should be checked.");

                missingIndexes = new int[missCount];
                Array.Copy(miss1, 0, missingIndexes, 0, miss1.Length);
                Array.Copy(miss2, 0, missingIndexes, miss1.Length, miss2.Length);

                Stopwatch watch = Stopwatch.StartNew();

                if (lines.Length == 2)
                {
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
                }
                else
                {

                }

                watch.Stop();

                report.AddMessageSafe($"Elapsed time: {watch.Elapsed}");
                report.SetKeyPerSecSafe(GetTotalCount(missCount), watch.Elapsed.TotalSeconds);

                report.Finalize();
            }
        }
    }
}
