// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend;
using FinderOuter.Backend.Cryptography.Hashing;
using FinderOuter.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Reflection;
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

    public class MnemonicSevice : ServiceBase
    {
        public MnemonicSevice(Report rep) : base(rep)
        {
        }



        private readonly Sha256 sha = new Sha256();
        private readonly int[] allowedWordLengths = { 12, 15, 18, 21, 24 };
        private uint[] wordIndexes;
        private int[] missingIndexes;
        private string[] allWords;

        private int missCount;
        private string[] words;
        private string passPhrase;


        readonly List<IEnumerable<int>> Final = new List<IEnumerable<int>>();
        private void SetResult(IEnumerable<int> item)
        {
            Final.Add(item);
        }


        private unsafe void SetBip32(byte[] mnemonic)
        {
            HmacSha512 hmac = new HmacSha512(mnemonic);

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
                        byte* fp = first;
                        byte* sp = second;

                        *(ulong*)fp ^= *(ulong*)sp;
                        *(ulong*)(fp + 8) ^= *(ulong*)(sp + 8);
                        *(ulong*)(fp + 16) ^= *(ulong*)(sp + 16);
                        *(ulong*)(fp + 24) ^= *(ulong*)(sp + 24);
                        *(ulong*)(fp + 32) ^= *(ulong*)(sp + 32);
                        *(ulong*)(fp + 40) ^= *(ulong*)(sp + 40);
                        *(ulong*)(fp + 48) ^= *(ulong*)(sp + 48);
                        *(ulong*)(fp + 56) ^= *(ulong*)(sp + 56);
                    }
                }

                Buffer.BlockCopy(resultOfF, 0, seed, 0, resultOfF.Length);
            }
        }


        private unsafe bool Loop24()
        {
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

                    sha.Compress32(hPt, wPt);

                    if ((byte)wrd[23] == hPt[0] >> 24)
                    {
                        StringBuilder sb = new StringBuilder(24);
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

                    sha.Compress28(hPt, wPt);

                    if ((wrd[20] & 0b111_1111) == hPt[0] >> 25)
                    {
                        StringBuilder sb = new StringBuilder(21);
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

                    sha.Compress24(hPt, wPt);

                    if ((wrd[17] & 0b11_1111) == hPt[0] >> 26)
                    {
                        StringBuilder sb = new StringBuilder(18);
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

                    sha.Compress20(hPt, wPt);

                    if ((wrd[14] & 0b1_1111) == hPt[0] >> 27)
                    {
                        StringBuilder sb = new StringBuilder(15);
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

                    sha.Compress16(hPt, wPt);

                    if ((wrd[11] & 0b1111) == hPt[0] >> 28)
                    {
                        StringBuilder sb = new StringBuilder(12);
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




        private bool TrySetEntropy(string mnemonic, MnemonicTypes mnType)
        {
            if (string.IsNullOrWhiteSpace(mnemonic))
            {
                return Fail("Mnemonic can not be null or empty.");
            }

            return Fail("Not yet implemented.");
        }


        private bool TrySetWordList(WordLists wl)
        {
            string fPath = $"FinderOuter.Backend.ImprovementProposals.BIP0039WordLists.{wl.ToString()}.txt";
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
                    return Fail($"Could not find {wl.ToString()} word list among resources."); ;
                }
            }

            return true;
        }

        private BigInteger GetTotalCount(int missCount) => BigInteger.Pow(2048, missCount);
        private bool IsMissingCharValid(char c) => Constants.Symbols.Contains(c);

        private bool TrySplitMnemonic(string mnemonic, char missingChar, out string[] result)
        {
            if (string.IsNullOrWhiteSpace(mnemonic))
            {
                result = null;
                return Fail("Mnemonic can not be null or empty.");
            }
            else
            {
                result = mnemonic.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (!allowedWordLengths.Contains(result.Length))
                {
                    return Fail("Invalid mnemonic length.");
                }

                string miss = new string(new char[] { missingChar });
                if (result.Any(s => s != miss && !allWords.Contains(s)))
                {
                    result = null;
                    return Fail("Mnemonic input contains invalid words.");
                }
                missCount = result.Count(s => s == miss);
                wordIndexes = new uint[result.Length];
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

                AddMessage($"There are {result.Length} words in the given mnemonic with {missCount} missing.");
                AddMessage($"A total of {GetTotalCount(missCount):n0} mnemonics should be checked.");
                return true;
            }
        }


        public async Task<bool> FindMissing(string mnemonic, char missingChar, MnemonicTypes mnType, WordLists wl)
        {
            InitReport();

            if (!TrySetWordList(wl))
                return false;
            if (!IsMissingCharValid(missingChar))
                return Fail("Missing character is not accepted.");
            if (!TrySplitMnemonic(mnemonic, missingChar, out words))
                return false;

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
            AddQueue($"Elapsed time: {watch.Elapsed}");
            AddQueue(GetKeyPerSec(GetTotalCount(missCount), watch.Elapsed.TotalSeconds));
            if (success)
            {
                // TODO: remove this branch after addition of more checks versus address 
                // we should end up with only one correct result.
                AddQueue($"Found {Final.Count:n0} correct mnemonics.");
                Final.Clear();
            }
            return FinishReport(success);
        }


        public async Task<bool> FindPath(string mnemonic, string extra, MnemonicTypes mnType, WordLists wl, string passPhrase)
        {
            InitReport();

            if (!TrySetEntropy(mnemonic, mnType) && !TrySetWordList(wl))
            {
                return false;
            }
            if (string.IsNullOrWhiteSpace(extra))
            {
                return Fail("Additioan info can not be null or empty.");
            }
            else
            {

            }

            return Fail("Not yet implemented");
        }

    }
}
