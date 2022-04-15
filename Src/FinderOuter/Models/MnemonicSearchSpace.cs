// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.ImprovementProposals;
using FinderOuter.Services;
using System;
using System.Linq;
using System.Numerics;
using System.Text;

namespace FinderOuter.Models
{
    public class MnemonicSearchSpace
    {
        public MnemonicSearchSpace()
        {
            inputService = new InputService();
        }


        private readonly InputService inputService;

        internal static readonly int[] allowedWordLengths = { 12, 15, 18, 21, 24 };

        public int wordCount, missCount, maxWordLen;
        public uint[] wordIndexes;
        public int[] missingIndexes;
        public int[] permutationCounts;
        public uint[] allPermutationValues;
        public string[] allWords;
        public BIP0039.WordLists wl;
        public MnemonicTypes mnType;
        public ElectrumMnemonic.MnemonicType elecMnType;
        public string mnemonic;

        public bool IsProcessed { get; private set; }

        public bool TrySetWordList(BIP0039.WordLists wl)
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

        public bool TrySplitMnemonic(string mnemonic, char missingChar, string[] allWords, out string error)
        {
            if (string.IsNullOrWhiteSpace(mnemonic))
            {
                wordCount = 0;
                error = "Mnemonic can not be null or empty.";
                return false;
            }
            else
            {
                string[] words = mnemonic.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                wordCount = words.Length;
                if (!allowedWordLengths.Contains(words.Length))
                {
                    wordCount = 0;
                    error = "Invalid mnemonic length.";
                    return false;
                }

                error = string.Empty;
                string missCharStr = new(new char[] { missingChar });
                bool invalidWord = false;
                for (int i = 0; i < words.Length; i++)
                {
                    if (words[i] != missCharStr && !allWords.Contains(words[i]))
                    {
                        invalidWord = true;
                        error += $"Given mnemonic contains invalid word at index {i} ({words[i]}).{Environment.NewLine}";
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


        public bool Process(string mnemonic, char missChar, MnemonicTypes mnType, BIP0039.WordLists wl,
                            ElectrumMnemonic.MnemonicType elecMnType, out string error)
        {
            IsProcessed = false;

            this.mnemonic = mnemonic;
            this.wl = wl;
            this.mnType = mnType;
            this.elecMnType = elecMnType;

            if (mnType == MnemonicTypes.Electrum && wl != BIP0039.WordLists.English)
                error = "Only English words are currently supported for Electrum mnemonics.";
            else if (!inputService.IsMissingCharValid(missChar))
                error = "Missing character is not accepted.";
            else if (!TrySetWordList(wl))
                error = $"Could not find {wl} word list among resources.";
            else if (!TrySplitMnemonic(mnemonic, missChar, allWords, out error))
                return false;
            else
            {
                IsProcessed = true;
                return true;
            }

            return false;
        }



        public bool SetValues(string[][] result)
        {
            if (result.Length != missCount)
            {
                return false;
            }

            int totalLen = 0;
            int maxLen = 0;
            int maxIndex = 0;
            for (int i = 0; i < result.Length; i++)
            {
                if (result[i].Length <= 1 && result[i].Length > allWords.Length)
                {
                    return false;
                }
                totalLen += result[i].Length;

                if (result[i].Length > maxLen)
                {
                    maxLen = result[i].Length;
                    maxIndex = i;
                }
            }

            if (maxIndex != 0)
            {
                string[] t1 = result[maxIndex];
                result[maxIndex] = result[0];
                result[0] = t1;

                int t2 = missingIndexes[maxIndex];
                missingIndexes[maxIndex] = missingIndexes[0];
                missingIndexes[0] = t2;
            }

            allPermutationValues = new uint[totalLen];
            permutationCounts = new int[missCount];

            int index1 = 0;
            int index2 = 0;
            foreach (string[] item in result)
            {
                permutationCounts[index2++] = item.Length;
                foreach (string s in item)
                {
                    int i = Array.IndexOf(allWords, s);
                    if (i < 0)
                    {
                        return false;
                    }
                    allPermutationValues[index1++] = (uint)i;
                }
            }

            return true;
        }


        public BigInteger GetTotal()
        {
            BigInteger res = BigInteger.One;
            foreach (int item in permutationCounts)
            {
                res *= item;
            }
            return res;
        }
    }
}
