// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend;
using FinderOuter.Backend.Cryptography.Hashing;
using FinderOuter.Models;
using FinderOuter.Services.Comparers;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace FinderOuter.Services
{
    public class MiniKeyService
    {
        public MiniKeyService(IReport rep)
        {
            inputService = new InputService();
            report = rep;
        }


        private readonly IReport report;
        private readonly InputService inputService;
        private byte[] precomputed;
        private int[] missingIndexes;
        private int missCount;
        private string keyToCheck;
        private ICompareService comparer;


        private BigInteger GetTotalCount(int missCount) => BigInteger.Pow(58, missCount);

        private void SetResult(IEnumerable<byte> item)
        {
            char[] temp = keyToCheck.ToCharArray();
            int i = 0;
            foreach (var index in item)
            {
                temp[missingIndexes[i++]] = (char)index;
            }

            report.AddMessageSafe($"Found the correct key: {new string(temp)}");
            report.FoundAnyResult = true;
        }

        private unsafe void Loop23()
        {
            // The actual data that is changing is 22 bytes (22 char long mini key) with a fixed starting character ('S')
            // plus an additional byte added to the end (char('?')=0x3f) during checking loop.
            // Checksum is replaced by checking if first byte of hash result is zero.
            // The actual key itself is the hash of the same 22 bytes (without '?') using a single SHA256
            // Note characters are decoded using UTF-8

            var cartesian = CartesianProduct.Create(Enumerable.Repeat(Encoding.UTF8.GetBytes(ConstantsFO.Base58Chars), missCount));
            using Sha256Fo sha = new Sha256Fo();

            byte* tmp = stackalloc byte[precomputed.Length];
            fixed (uint* hPt = &sha.hashState[0], wPt = &sha.w[0])
            fixed (byte* pre = &precomputed[0])
            fixed (int* mi = &missingIndexes[0])
            {
                foreach (var item in cartesian)
                {
                    Buffer.MemoryCopy(pre, tmp, 22, 22);
                    int mis = 0;
                    foreach (var keyItem in item)
                    {
                        tmp[mi[mis]] = keyItem;
                        mis++;
                    }

                    // The added value below is the fixed first char(S)=0x53 shifted left 24 places
                    wPt[0] = 0b01010011_00000000_00000000_00000000U | (uint)tmp[1] << 16 | (uint)tmp[2] << 8 | tmp[3];
                    wPt[1] = (uint)tmp[4] << 24 | (uint)tmp[5] << 16 | (uint)tmp[6] << 8 | tmp[7];
                    wPt[2] = (uint)tmp[8] << 24 | (uint)tmp[9] << 16 | (uint)tmp[10] << 8 | tmp[11];
                    wPt[3] = (uint)tmp[12] << 24 | (uint)tmp[13] << 16 | (uint)tmp[14] << 8 | tmp[15];
                    wPt[4] = (uint)tmp[16] << 24 | (uint)tmp[17] << 16 | (uint)tmp[18] << 8 | tmp[19];
                    // The added value below is the SHA padding and the last added ? char equal to 0x3f shifted right 8 places
                    wPt[5] = (uint)tmp[20] << 24 | (uint)tmp[21] << 16 | 0b00000000_00000000_00111111_10000000U;
                    // from 6 to 14 = 0
                    wPt[15] = 184; // 23 *8 = 184

                    sha.Init(hPt);
                    sha.Compress23(hPt, wPt);

                    if ((hPt[0] & 0b11111111_00000000_00000000_00000000U) == 0)
                    {
                        // The actual key is SHA256 of 22 char key (without '?')
                        // SHA working vector is already set, only the last 2 bytes ('?' and pad) and the length have to change
                        wPt[5] ^= 0b00000000_00000000_10111111_10000000U;
                        // from 6 to 14 (remain) = 0
                        wPt[15] = 176; // 22 *8 = 176

                        sha.Init(hPt);
                        sha.Compress22(hPt, wPt);

                        if (comparer.Compare(sha.GetBytes(hPt)))
                        {
                            SetResult(item);
                            break;
                        }
                    }
                }
            }
        }


        private unsafe void Loop27()
        {
            // Same as above but key is 26 chars
            var cartesian = CartesianProduct.Create(Enumerable.Repeat(Encoding.UTF8.GetBytes(ConstantsFO.Base58Chars), missCount));
            using Sha256Fo sha = new Sha256Fo();

            byte* tmp = stackalloc byte[precomputed.Length];
            fixed (uint* hPt = &sha.hashState[0], wPt = &sha.w[0])
            fixed (byte* pre = &precomputed[0])
            fixed (int* mi = &missingIndexes[0])
            {
                foreach (var item in cartesian)
                {
                    Buffer.MemoryCopy(pre, tmp, 26, 26);
                    int mis = 0;
                    foreach (var keyItem in item)
                    {
                        tmp[mi[mis]] = keyItem;
                        mis++;
                    }

                    wPt[0] = 0b01010011_00000000_00000000_00000000U | (uint)tmp[1] << 16 | (uint)tmp[2] << 8 | tmp[3];
                    wPt[1] = (uint)tmp[4] << 24 | (uint)tmp[5] << 16 | (uint)tmp[6] << 8 | tmp[7];
                    wPt[2] = (uint)tmp[8] << 24 | (uint)tmp[9] << 16 | (uint)tmp[10] << 8 | tmp[11];
                    wPt[3] = (uint)tmp[12] << 24 | (uint)tmp[13] << 16 | (uint)tmp[14] << 8 | tmp[15];
                    wPt[4] = (uint)tmp[16] << 24 | (uint)tmp[17] << 16 | (uint)tmp[18] << 8 | tmp[19];
                    wPt[5] = (uint)tmp[20] << 24 | (uint)tmp[21] << 16 | (uint)tmp[22] << 8 | tmp[23];
                    wPt[6] = (uint)tmp[24] << 24 | (uint)tmp[25] << 16 | 0b00000000_00000000_00111111_10000000U;
                    // from 7 to 14 = 0
                    wPt[15] = 216; // 27 *8 = 216

                    sha.Init(hPt);
                    sha.Compress27(hPt, wPt);

                    if ((hPt[0] & 0b11111111_00000000_00000000_00000000U) == 0)
                    {
                        wPt[6] ^= 0b00000000_00000000_10111111_10000000U;
                        // from 7 to 14 (remain) = 0
                        wPt[15] = 208; // 26 *8 = 208

                        sha.Init(hPt);
                        sha.Compress26(hPt, wPt);

                        if (comparer.Compare(sha.GetBytes(hPt)))
                        {
                            SetResult(item);
                            break;
                        }
                    }
                }
            }
        }


        private unsafe void Loop31()
        {
            var cartesian = CartesianProduct.Create(Enumerable.Repeat(Encoding.UTF8.GetBytes(ConstantsFO.Base58Chars), missCount));
            using Sha256Fo sha = new Sha256Fo();

            byte* tmp = stackalloc byte[precomputed.Length];
            fixed (uint* hPt = &sha.hashState[0], wPt = &sha.w[0])
            fixed (byte* pre = &precomputed[0])
            fixed (int* mi = &missingIndexes[0])
            {
                foreach (var item in cartesian)
                {
                    Buffer.MemoryCopy(pre, tmp, 30, 30);
                    int mis = 0;
                    foreach (var keyItem in item)
                    {
                        tmp[mi[mis]] = keyItem;
                        mis++;
                    }

                    // The added value below is the fixed first char(S)=0x53 shifted left 24 places
                    wPt[0] = 0b01010011_00000000_00000000_00000000U | (uint)tmp[1] << 16 | (uint)tmp[2] << 8 | tmp[3];
                    wPt[1] = (uint)tmp[4] << 24 | (uint)tmp[5] << 16 | (uint)tmp[6] << 8 | tmp[7];
                    wPt[2] = (uint)tmp[8] << 24 | (uint)tmp[9] << 16 | (uint)tmp[10] << 8 | tmp[11];
                    wPt[3] = (uint)tmp[12] << 24 | (uint)tmp[13] << 16 | (uint)tmp[14] << 8 | tmp[15];
                    wPt[4] = (uint)tmp[16] << 24 | (uint)tmp[17] << 16 | (uint)tmp[18] << 8 | tmp[19];
                    wPt[5] = (uint)tmp[20] << 24 | (uint)tmp[21] << 16 | (uint)tmp[22] << 8 | tmp[23];
                    wPt[6] = (uint)tmp[24] << 24 | (uint)tmp[25] << 16 | (uint)tmp[26] << 8 | tmp[27];
                    // The added value below is the SHA padding and the last added ? char equal to 0x3f shifted right 8 places
                    wPt[7] = (uint)tmp[28] << 24 | (uint)tmp[29] << 16 | 0b00000000_00000000_00111111_10000000U;
                    // from 8 to 14 = 0
                    wPt[15] = 248; // 31 *8 = 184

                    sha.Init(hPt);
                    sha.Compress31(hPt, wPt);

                    if ((hPt[0] & 0b11111111_00000000_00000000_00000000U) == 0)
                    {
                        // Same as above
                        wPt[7] ^= 0b00000000_00000000_10111111_10000000U;
                        // from 8 to 14 (remain) = 0
                        wPt[15] = 240; // 30 *8 = 240

                        sha.Init(hPt);
                        sha.Compress30(hPt, wPt);

                        if (comparer.Compare(sha.GetBytes(hPt)))
                        {
                            SetResult(item);
                            break;
                        }
                    }
                }
            }
        }


        private void PreCompute(char missingChar)
        {
            int mis = 0;
            for (int i = 0; i < keyToCheck.Length; i++)
            {
                if (keyToCheck[i] == missingChar)
                {
                    missingIndexes[mis++] = i;
                }
                else
                {
                    precomputed[i] = (byte)keyToCheck[i];
                }
            }
        }

        public async void Find(string key, string extra, InputType extraType, char missingChar)
        {
            report.Init();

            if (!inputService.IsMissingCharValid(missingChar))
                report.Fail("Invalid missing character.");
            else if (string.IsNullOrWhiteSpace(key) || !key.All(c => ConstantsFO.Base58Chars.Contains(c) || c == missingChar))
                report.Fail("Input contains invalid base-58 character(s).");
            else if (!key.StartsWith(ConstantsFO.MiniKeyStart))
                report.Fail($"Minikey must start with {ConstantsFO.MiniKeyStart}.");
            else if (!inputService.TryGetCompareService(extraType, extra, out comparer))
                report.Fail("Invalid extra input or input type.");
            else
            {
                missCount = key.Count(c => c == missingChar);
                if (missCount == 0)
                {
                    report.AddMessageSafe("The given input has no missing characters, verifying it as a complete minikey.");
                    report.AddMessageSafe(inputService.CheckMiniKey(key));
                    report.FoundAnyResult = true;
                    return;
                }

                keyToCheck = key;
                missingIndexes = new int[missCount];

                report.AddMessageSafe($"Total number of minikeys to test: {GetTotalCount(missCount):n0}");
                report.AddMessageSafe("Going throgh each case. Please wait...");
                Stopwatch watch = Stopwatch.StartNew();

                if (key.Length == ConstantsFO.MiniKeyLen1)
                {
                    precomputed = new byte[ConstantsFO.MiniKeyLen1];
                    PreCompute(missingChar);
                    await Task.Run(Loop23);
                }
                else if (key.Length == ConstantsFO.MiniKeyLen2)
                {
                    precomputed = new byte[ConstantsFO.MiniKeyLen2];
                    PreCompute(missingChar);
                    await Task.Run(Loop27);
                }
                else if (key.Length == ConstantsFO.MiniKeyLen3)
                {
                    precomputed = new byte[ConstantsFO.MiniKeyLen3];
                    PreCompute(missingChar);
                    await Task.Run(Loop31);
                }
                else
                {
                    report.Fail($"Minikey length must be {ConstantsFO.MiniKeyLen1} or {ConstantsFO.MiniKeyLen3}.");
                }

                watch.Stop();
                report.AddMessageSafe($"Elapsed time: {watch.Elapsed}");
                report.SetKeyPerSecSafe(GetTotalCount(missCount), watch.Elapsed.TotalSeconds);

                report.Finalize();
            }
        }
    }
}
