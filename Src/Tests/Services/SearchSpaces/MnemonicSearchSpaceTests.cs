// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.ImprovementProposals;
using FinderOuter.Models;
using FinderOuter.Services.SearchSpaces;
using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace Tests.Services.SearchSpaces
{
    public class MnemonicSearchSpaceTests
    {
        private static string[] GetWordList(BIP0039.WordLists wl, out int maxLen)
        {
            string[] result = BIP0039.GetAllWords(wl);
            maxLen = result.Max(s => s.Length);
            return result;
        }

        public static IEnumerable<object[]> GetProcessCases()
        {
            string[] enLst = GetWordList(BIP0039.WordLists.English, out int enLen);

            yield return new object[]
            {
                "foo", '*', MnemonicTypes.Electrum, BIP0039.WordLists.ChineseSimplified, ElectrumMnemonic.MnemonicType.SegWit,
                false, "Only English words are currently supported for Electrum mnemonics.",
                null, // All words
                0, // Max word length
                0, // Miss count
                null, // Missing indexes
                0, // Word count
                null // Word indexes
            };
            yield return new object[]
            {
                "foo", 'a', MnemonicTypes.BIP39, BIP0039.WordLists.English, ElectrumMnemonic.MnemonicType.Standard,
                false, "Missing character is not accepted.",
                null, // All words
                0, // Max word length
                0, // Miss count
                null, // Missing indexes
                0, // Word count
                null // Word indexes
            };
            yield return new object[]
            {
                "foo", '*', MnemonicTypes.BIP39, 1000, ElectrumMnemonic.MnemonicType.Standard,
                false, "Could not find 1000 word list among resources.",
                null, // All words
                0, // Max word length
                0, // Miss count
                null, // Missing indexes
                0, // Word count
                null // Word indexes
            };
            yield return new object[]
            {
                null, '*', MnemonicTypes.BIP39, BIP0039.WordLists.English, ElectrumMnemonic.MnemonicType.Standard,
                false, "Mnemonic can not be null or empty.",
                enLst, // All words
                enLen, // Max word length
                0, // Miss count
                null, // Missing indexes
                0, // Word count
                null // Word indexes
            };
            yield return new object[]
            {
                string.Empty, '*', MnemonicTypes.BIP39, BIP0039.WordLists.English, ElectrumMnemonic.MnemonicType.Standard,
                false, "Mnemonic can not be null or empty.",
                enLst, // All words
                enLen, // Max word length
                0, // Miss count
                null, // Missing indexes
                0, // Word count
                null // Word indexes
            };
            yield return new object[]
            {
                " ", '*', MnemonicTypes.BIP39, BIP0039.WordLists.English, ElectrumMnemonic.MnemonicType.Standard,
                false, "Mnemonic can not be null or empty.",
                enLst, // All words
                enLen, // Max word length
                0, // Miss count
                null, // Missing indexes
                0, // Word count
                null // Word indexes
            };
            yield return new object[]
            {
                "foo", '*', MnemonicTypes.BIP39, BIP0039.WordLists.English, ElectrumMnemonic.MnemonicType.Standard,
                false, "Invalid mnemonic length.",
                enLst, // All words
                enLen, // Max word length
                0, // Miss count
                null, // Missing indexes
                0, // Word count
                null // Word indexes
            };
            yield return new object[]
            {
                "shed slide foo best wave buddy foobar salmon fresh bitter seek fooo", '*',
                MnemonicTypes.BIP39, BIP0039.WordLists.English, ElectrumMnemonic.MnemonicType.Standard,
                false,
                $"3rd word (foo) is invalid.{Environment.NewLine}" +
                $"7th word (foobar) is invalid.{Environment.NewLine}" +
                $"12th word (fooo) is invalid.{Environment.NewLine}",
                enLst, // All words
                enLen, // Max word length
                0, // Miss count
                null, // Missing indexes
                12, // Word count
                null // Word indexes
            };
            yield return new object[]
            {
                "shed slide night best wave buddy honey salmon fresh bitter seek else", '*',
                MnemonicTypes.BIP39, BIP0039.WordLists.English, ElectrumMnemonic.MnemonicType.Standard,
                true, string.Empty,
                enLst, // All words
                enLen, // Max word length
                0, // Miss count
                Array.Empty<int>(), // Missing indexes
                12, // Word count
                new uint[12] { 1578,1628,1196,170,1983,235,873,1523,742,182,1560,577 } // Word indexes
            };
            yield return new object[]
            {
                "* slide night best wave buddy honey * fresh bitter seek *", '*',
                MnemonicTypes.BIP39, BIP0039.WordLists.English, ElectrumMnemonic.MnemonicType.Standard,
                true, string.Empty,
                enLst, // All words
                enLen, // Max word length
                3, // Miss count
                new int[3] { 0, 7, 11 }, // Missing indexes
                12, // Word count
                new uint[12] { 0, 1628,1196,170,1983,235,873, 0, 742,182,1560, 0 } // Word indexes
            };
        }

        [Theory]
        [MemberData(nameof(GetProcessCases))]
        public void ProcessTest(string mnemonic, char missChar, MnemonicTypes mnType, BIP0039.WordLists wl,
                                ElectrumMnemonic.MnemonicType elecMnType,
                                bool expProcess, string expError, string[] expAllWords, int expMaxWordLen,
                                int expMissCount, int[] expMissingIndexes, int expWordCount, uint[] expWordIndexes)
        {
            MnemonicSearchSpace ss = new();
            bool process = ss.Process(mnemonic, missChar, mnType, wl, elecMnType, out string actulError);

            Assert.Equal(expProcess, process);
            Assert.Equal(expError, actulError);
            Assert.Equal(mnemonic, ss.Input);
            Assert.Equal(wl, ss.wl);
            Assert.Equal(mnType, ss.mnType);
            Assert.Equal(elecMnType, ss.elecMnType);
            Assert.Equal(expAllWords, ss.allWords);
            Assert.Equal(expMaxWordLen, ss.maxWordLen);
            Assert.Equal(expMissCount, ss.MissCount);
            Assert.Equal(expMissingIndexes, ss.MissingIndexes);
            Assert.Equal(expWordCount, ss.wordCount);
            Assert.Equal(expWordIndexes, ss.wordIndexes);
        }
    }
}
