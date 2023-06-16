// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using Autarkysoft.Bitcoin.Cryptography.EllipticCurve;
using Autarkysoft.Bitcoin.ImprovementProposals;
using FinderOuter.Models;
using FinderOuter.Services.Comparers;
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


        public static BIP0032Path ProcessPath(string path, out string error)
        {
            BIP0032Path result;
            try
            {
                result = new BIP0032Path(path);
                error = string.Empty;
            }
            catch (Exception ex)
            {
                error = $"Invalid path ({ex.Message}).";
                result = null;
            }

            return result;
        }

        public bool ProcessNoMissing(ICompareService comparer, string pass, BIP0032Path path, out string message)
        {
            if (MissCount != 0)
            {
                message = "This method should not be called with missing characters (this is a bug).";
                return false;
            }

            try
            {
                using BIP0032 temp = mnType switch
                {
                    MnemonicTypes.BIP39 => new BIP0039(Input, wl, pass),
                    MnemonicTypes.Electrum => new ElectrumMnemonic(Input, wl, pass),
                    _ => throw new ArgumentException("Undefined mnemonic type (this is a bug).")
                };

                message = $"Given input is a valid {mnType} mnemonic.";

                if (path is null)
                {
                    message += Environment.NewLine;
                    message += "Set the derivation path correctly to verify the derived key/address.";
                    return true; // The mnemonic is valid, we just can't derive child keys to do extra checks
                }

                if (comparer is null || !comparer.IsInitialized)
                {
                    message += Environment.NewLine;
                    message += "Set the compare value correctly to verify the derived key/address.";
                    return true; // Same as above
                }

                uint startIndex = path.Indexes[^1];
                uint[] indices = new uint[path.Indexes.Length - 1];
                Array.Copy(path.Indexes, 0, indices, 0, indices.Length);
                BIP0032Path newPath = new(indices);

                PrivateKey[] keys = temp.GetPrivateKeys(newPath, 1, startIndex);
                if (keys is null || keys.Length < 1)
                {
                    // The chance of this happening is _nearly_ zero
                    message += Environment.NewLine;
                    message += "Could not derive any keys at the given path.";
                    return false;
                }

                if (comparer.Compare(keys[0].ToBytes()))
                {
                    message += Environment.NewLine;
                    message += $"The given child key is correctly derived from this mnemonic at {path}";
                    return true;
                }
                else
                {
                    message += Environment.NewLine;
                    message += $"The given child key is not derived from this mnemonic or not at {path}";
                    message += $"{Environment.NewLine}" +
                               $"List of all address types that can be derived from this mnemonic at the given path:" +
                               $"{Environment.NewLine}" +
                               $"{AddressService.GetAllAddresses(keys[0].ToPublicKey(comparer.Calc))}";
                    return false;
                }
            }
            catch (Exception ex)
            {
                message = $"Mnemonic is not missing any characters but is invalid. Error: {ex.Message}";
                return false;
            }
        }


        public bool SetValues(string[][] array, out string error)
        {
            if (!ProcessValues(array, out error))
            {
                return false;
            }

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
                                $"can not be null or empty.";
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
