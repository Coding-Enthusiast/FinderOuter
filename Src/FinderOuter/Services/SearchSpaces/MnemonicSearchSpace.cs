// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using Autarkysoft.Bitcoin.ImprovementProposals;
using FinderOuter.Models;
using System;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace FinderOuter.Services.SearchSpaces
{
    public class MnemonicSearchSpace : SearchSpaceBase
    {
        internal static readonly int[] allowedWordLengths = { 12, 15, 18, 21, 24 };

        public int wordCount, maxWordLen;
        public uint[] wordIndexes;
        public string[] allWords;
        public BIP0039.WordLists wl;
        public MnemonicTypes mnType;
        public ElectrumMnemonic.MnemonicType elecMnType;


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
                        error += $"{(i + 1).ToOrdinal()} word ({words[i]}) is invalid.{Environment.NewLine}";
                    }
                }
                if (invalidWord)
                {
                    words = null;
                    return false;
                }

                MissCount = words.Count(s => s == missCharStr);
                wordIndexes = new uint[words.Length];
                MissingIndexes = new int[MissCount];
                for (int i = 0, j = 0; i < words.Length; i++)
                {
                    if (words[i] != missCharStr)
                    {
                        wordIndexes[i] = (uint)Array.IndexOf(allWords, words[i]);
                    }
                    else
                    {
                        MissingIndexes[j] = i;
                        j++;
                    }
                }

                return true;
            }
        }


        public bool Process(string mnemonic, char missChar, MnemonicTypes mnType, BIP0039.WordLists wl,
                            ElectrumMnemonic.MnemonicType elecMnType, out string error)
        {
            Input = mnemonic;
            this.wl = wl;
            this.mnType = mnType;
            this.elecMnType = elecMnType;

            if (mnType == MnemonicTypes.Electrum && wl != BIP0039.WordLists.English)
                error = "Only English words are currently supported for Electrum mnemonics.";
            else if (!InputService.IsMissingCharValid(missChar))
                error = "Missing character is not accepted.";
            else if (!TrySetWordList(wl))
                error = $"Could not find {wl} word list among resources.";
            else if (!TrySplitMnemonic(mnemonic, missChar, allWords, out error))
                return false;
            else
            {
                return true;
            }

            return false;
        }



        public bool SetValues(string[][] array, out string error)
        {
            ProcessValues(array, out error);

            int index1 = 0;
            int index2 = 0;
            for (int i = 0; i < array.Length; i++)
            {
                Debug.Assert(array[i] is not null && array[i].Length >= 2);

                PermutationCounts[index2++] = array[i].Length;
                for (int j = 0; j < array[i].Length; j++)
                {
                    if (string.IsNullOrEmpty(array[i][j]))
                    {
                        error = $"{(j + 1).ToOrdinal()} variable entered for {(i + 1).ToOrdinal()} missing word " +
                                $"({array[i][j]}) can not be null or empty.";
                        return false;
                    }

                    int k = Array.IndexOf(allWords, array[i][j]);
                    if (k < 0)
                    {
                        error = $"{(j + 1).ToOrdinal()} variable entered for {(i + 1).ToOrdinal()} missing word " +
                                $"({array[i][j]}) is not found in the word-list.";
                        return false;
                    }
                    AllPermutationValues[index1++] = (uint)k;
                }
            }

            return true;
        }
    }
}
