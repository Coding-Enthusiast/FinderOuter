// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.ImprovementProposals;
using FinderOuter.Backend.Cryptography.Hashing;
using FinderOuter.Models;
using FinderOuter.Services.Comparers;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Reflection;
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
        private readonly IReport report;
        private readonly InputService inputService;
        private readonly int[] allowedWordLengths = { 12, 15, 18, 21, 24 };
        private uint[] wordIndexes;
        private int[] missingIndexes;
        private string[] allWords;
        private BIP0032Path path;
        private uint keyIndex;
        private readonly PrvToAddrBothComparer comparer;

        private int missCount;
        private string[] words;
        private string passPhrase;

        // Biggest word has 8 chars, biggest mnemonic has 24 words + 23 spaces
        // TODO: replace StringBuilder with a byte[] for an even faster result
        private const int SbCap = (8 * 24) + 23;


        readonly List<IEnumerable<int>> Final = new List<IEnumerable<int>>();
        private void SetResult(IEnumerable<int> item)
        {
            Final.Add(item);
        }


        private unsafe void SetBip32(byte[] mnemonic)
        {
            hmac.Key = mnemonic;

            byte[] salt = Encoding.UTF8.GetBytes($"mnemonic{passPhrase?.Normalize(NormalizationForm.FormKD)}");
            byte[] saltForHmac = new byte[salt.Length + 4];
            Buffer.BlockCopy(salt, 0, saltForHmac, 0, salt.Length);

            byte[] seed = new byte[64];

            fixed (byte* saltPt = &saltForHmac[salt.Length])
            {
                // F()
                byte[] resultOfF = new byte[hmac.OutputSize];

                // Concatinate i after salt
                //saltPt[0] = (byte)(1 >> 24);
                //saltPt[1] = (byte)(1 >> 16);
                //saltPt[2] = (byte)(1 >> 8);
                saltPt[3] = 1;

                // compute u1
                byte[] u1 = hmac.ComputeHash(saltForHmac);

                Buffer.BlockCopy(u1, 0, resultOfF, 0, u1.Length);

                // compute u2 to u(c-1) where c is iteration and each u is the hmac of previous u
                for (int j = 1; j < 2048; j++)
                {
                    u1 = hmac.ComputeHash(u1);

                    // result of F() is XOR sum of all u arrays
                    int len = u1.Length;
                    fixed (byte* first = resultOfF, second = u1)
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

                Buffer.BlockCopy(resultOfF, 0, seed, 0, resultOfF.Length);

                using BIP0032 bip = new BIP0032(seed);
                if (comparer.Compare(bip.GetPrivateKeys(path, keyIndex)[0].ToBytes()))
                {
                    report.AddMessageSafe("Found a key.");
                }
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
                        for (int i = 0; i < 23; i++)
                        {
                            sb.Append($"{allWords[wrd[i]]} ");
                        }

                        // no space at the end.
                        sb.Append($"{allWords[wrd[23]]}");

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
                        for (int i = 0; i < 20; i++)
                        {
                            sb.Append($"{allWords[wrd[i]]} ");
                        }

                        // no space at the end.
                        sb.Append($"{allWords[wrd[20]]}");

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
                        for (int i = 0; i < 17; i++)
                        {
                            sb.Append($"{allWords[wrd[i]]} ");
                        }

                        // no space at the end.
                        sb.Append($"{allWords[wrd[17]]}");

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
                        for (int i = 0; i < 14; i++)
                        {
                            sb.Append($"{allWords[wrd[i]]} ");
                        }

                        // no space at the end.
                        sb.Append($"{allWords[wrd[14]]}");

                        SetBip32(Encoding.UTF8.GetBytes(sb.ToString()));
                    }
                }
            }

            return Final.Count != 0;
        }

        private unsafe bool Loop12()
        {
            using Sha256Fo sha = new Sha256Fo();
            var cartesian = CartesianProduct.Create(Enumerable.Repeat(Enumerable.Range(0, 2048), missCount));

            fixed (uint* wPt = &sha.w[0], hPt = &sha.hashState[0], wrd = &wordIndexes[0])
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

                    sha.Init(hPt);
                    sha.Compress16(hPt, wPt);

                    if ((wrd[11] & 0b1111) == hPt[0] >> 28)
                    {
                        StringBuilder sb = new StringBuilder(SbCap);
                        for (int i = 0; i < 11; i++)
                        {
                            sb.Append($"{allWords[wrd[i]]} ");
                        }

                        // no space at the end.
                        sb.Append($"{allWords[wrd[11]]}");

                        SetBip32(Encoding.UTF8.GetBytes(sb.ToString()));
                    }
                }
            }

            return Final.Count != 0;
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


        private bool TrySetWordList(WordLists wl)
        {
            try
            {
                string fPath = $"FinderOuter.Backend.ImprovementProposals.BIP0039WordLists.{wl}.txt";
                Assembly asm = Assembly.GetExecutingAssembly();
                using (Stream stream = asm.GetManifestResourceStream(fPath))
                {
                    if (stream != null)
                    {
                        using StreamReader reader = new StreamReader(stream);
                        allWords = reader.ReadToEnd().Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
                    }
                    else
                    {
                        return false;
                    }
                }

                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        private bool TrySplitMnemonic(string mnemonic, char missingChar)
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


        public async Task<bool> FindMissing(string mnemonic, char missChar, string pass, MnemonicTypes mnType, WordLists wl)
        {
            report.Init();

            if (!TrySetWordList(wl))
                return report.Fail($"Could not find {wl} word list among resources."); ;
            if (!inputService.IsMissingCharValid(missChar))
                return report.Fail("Missing character is not accepted.");
            if (!TrySplitMnemonic(mnemonic, missChar))
                return false;
            passPhrase = pass;

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


        public async Task<bool> FindPath(string mnemonic, string extra, MnemonicTypes mnType, WordLists wl, string passPhrase)
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
