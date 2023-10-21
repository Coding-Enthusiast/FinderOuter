// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.ImprovementProposals;
using FinderOuter.Models;
using FinderOuter.Services.Comparers;
using FinderOuter.Services.SearchSpaces;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Tests.Services.SearchSpaces
{
    public class MnemonicSearchSpaceTests
    {
        private const string NoMiss = "shed slide night best wave buddy honey salmon fresh bitter seek else";
        private const string OneMiss = "shed slide night * wave buddy honey salmon fresh bitter seek else";
        private const string ThreeMiss = "shed slide night * wave * honey salmon fresh bitter * else";
        private static readonly int[] OneMissIndex = new int[1] { 3 };
        private static readonly int[] ThreeMissIndex = new int[3] { 3, 5, 10 };


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
                NoMiss, '*',
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


        private static MnemonicSearchSpace BuildSS(string s, int expMissCount, bool processResult,
                                                   MnemonicTypes mnType = MnemonicTypes.BIP39)
        {
            MnemonicSearchSpace ss = new();
            bool b = ss.Process(s, '*', mnType, BIP0039.WordLists.English, ElectrumMnemonic.MnemonicType.Standard, out _);
            Assert.Equal(expMissCount, ss.MissCount);
            Assert.Equal(processResult, b);

            return ss;
        }


        public static IEnumerable<object[]> GetProcessNoMissingCases()
        {
            ICompareService comp_noInit = new PrvToAddrCompComparer();

            ICompareService comp_wrongAddr = new PrvToAddrCompComparer();
            Assert.True(comp_wrongAddr.Init(KeyHelper.Pub2CompAddr));

            BIP0032Path path = new("m/84'/0'/0'/0/5");
            ICompareService comp_noPass = new PrvToAddrCompComparer();
            Assert.True(comp_noPass.Init("bc1qddpga3fkdgcc0wv64azacykr9vyrvqsahu0eeu"));

            ICompareService comp_withPass = new PrvToAddrCompComparer();
            Assert.True(comp_withPass.Init("bc1qt5e7ynnrazrvcn64dwcwhjyu2wdjzygumtv8jj"));
            string pass = "foobar";

            yield return new object[]
            {
                BuildSS(OneMiss, 1, true), new PrvToPubComparer(), null, null, false,
                "This method should not be called with missing characters (this is a bug)."
            };
            yield return new object[]
            {
                BuildSS("shed slide night best wave buddy honey salmon fresh bitter seek seek", 0, true), comp_noInit,
                null, null, false,
                "Mnemonic is not missing any characters but is invalid. Error: Wrong checksum."
            };
            yield return new object[]
            {
                BuildSS(NoMiss, 0, true, MnemonicTypes.Electrum), comp_noInit,
                null, null, false,
                "Mnemonic is not missing any characters but is invalid. Error: Invalid mnemonic (undefined version)."
            };
            yield return new object[]
            {
                BuildSS(NoMiss, 0, true), comp_noInit,
                null, null, true,
                $"Given input is a valid BIP39 mnemonic.{Environment.NewLine}" +
                $"Set the derivation path correctly to verify the derived key/address."
            };
            yield return new object[]
            {
                BuildSS(NoMiss, 0, true), null,
                null, path, true,
                $"Given input is a valid BIP39 mnemonic.{Environment.NewLine}" +
                $"Set the compare value correctly to verify the derived key/address."
            };
            yield return new object[]
            {
                BuildSS(NoMiss, 0, true), comp_noInit,
                null, path, true,
                $"Given input is a valid BIP39 mnemonic.{Environment.NewLine}" +
                $"Set the compare value correctly to verify the derived key/address."
            };
            yield return new object[]
            {
                BuildSS(NoMiss, 0, true), comp_wrongAddr,
                null, path, false,
                $"Given input is a valid BIP39 mnemonic.{Environment.NewLine}" +
                $"The given child key is not derived from this mnemonic or not at m/84'/0'/0'/0/5{Environment.NewLine}" +
                $"List of all address types that can be derived from this mnemonic at the given path:{Environment.NewLine}"
            };
            yield return new object[]
            {
                BuildSS(NoMiss, 0, true), comp_noPass,
                null, path, true,
                $"Given input is a valid BIP39 mnemonic.{Environment.NewLine}" +
                $"The given child key is correctly derived from this mnemonic at m/84'/0'/0'/0/5"
            };
            yield return new object[]
            {
                BuildSS(NoMiss, 0, true), comp_withPass,
                pass, path, true,
                $"Given input is a valid BIP39 mnemonic.{Environment.NewLine}" +
                $"The given child key is correctly derived from this mnemonic at m/84'/0'/0'/0/5"
            };
        }
        [Theory]
        [MemberData(nameof(GetProcessNoMissingCases))]
        public void ProcessNoMissingTest(MnemonicSearchSpace ss, ICompareService comparer, string pass, BIP0032Path path,
                                         bool expected, string expMsg)
        {
            bool actual = ss.ProcessNoMissing(comparer, pass, path, out string message);
            Assert.Equal(expected, actual);
            Assert.Contains(expMsg, message);
        }


        public static IEnumerable<object[]> GetSetValuesCases()
        {
            // The following cases test SearchSpaceBase.ProcessValues() method that is thoroughly tested elsewhere
            // Some cases are used here to ensure MnemonicSearchSpace treats returned value as it should
            yield return new object[]
            {
                BuildSS(OneMiss, 1, true),
                null, null,
                false, "Permutations list can not be null",
                OneMissIndex, null, Array.Empty<int>()
            };
            yield return new object[]
            {
                BuildSS(OneMiss, 1, true),
                Array.Empty<string[]>(), Array.Empty<string[]>(),
                false, "Permutations list doesn't have the same number of arrays as missing characters count.",
                OneMissIndex, null, Array.Empty<int>()
            };
            yield return new object[]
            {
                BuildSS(ThreeMiss, 3, true),
                new string[1][], new string[1][],
                false, "Permutations list doesn't have the same number of arrays as missing characters count.",
                ThreeMissIndex, null, Array.Empty<int>()
            };
            yield return new object[]
            {
                BuildSS(ThreeMiss, 3, true),
                new string[4][], new string[4][],
                false, "Permutations list doesn't have the same number of arrays as missing characters count.",
                ThreeMissIndex, null, Array.Empty<int>()
            };
            yield return new object[]
            {
                BuildSS(ThreeMiss, 3, true),
                new string[3][] { null, new string[2] { "kidney", "same" }, new string[2] { "drift", "six" } },
                new string[3][] { null, new string[2] { "kidney", "same" }, new string[2] { "drift", "six" } },
                false,
                "Search space values are not correctly set. Add at least 2 possible values for the 1st missing position.",
                ThreeMissIndex, null, Array.Empty<int>()
            };

            // Testing the process part in MnemonicSearchSpace itself
            yield return new object[]
            {
                BuildSS(ThreeMiss, 3, true),
                new string[3][]
                {
                    new string[2] { "kidney", null },
                    new string[2] { "kidney", "same" },
                    new string[2] { "drift", "six" }
                },
                new string[3][]
                {
                    new string[2] { "kidney", null },
                    new string[2] { "kidney", "same" },
                    new string[2] { "drift", "six" }
                },
                false,
                "2nd variable entered for 1st missing word can not be null or empty.",
                ThreeMissIndex,
                new uint[6] { 979,0, 0,0, 0,0 },
                new int[3] { 2, 0, 0 }
            };
            yield return new object[]
            {
                BuildSS(ThreeMiss, 3, true),
                new string[3][]
                {
                    new string[2] { "kidney", "decline" },
                    new string[2] { "kidney", "same" },
                    new string[2] { "", "six" }
                },
                new string[3][]
                {
                    new string[2] { "kidney", "decline" },
                    new string[2] { "kidney", "same" },
                    new string[2] { "", "six" }
                },
                false,
                "1st variable entered for 3rd missing word can not be null or empty.",
                ThreeMissIndex,
                new uint[6] { 979,455, 979,1527, 0,0 },
                new int[3] { 2, 2, 2 }
            };
            yield return new object[]
            {
                BuildSS(ThreeMiss, 3, true),
                new string[3][]
                {
                    new string[2] { "kidney", "decline" },
                    new string[2] { "kidney", "foo" },
                    new string[2] { "drift", "six" }
                },
                new string[3][]
                {
                    new string[2] { "kidney", "decline" },
                    new string[2] { "kidney", "foo" },
                    new string[2] { "drift", "six" }
                },
                false,
                "2nd variable entered for 2nd missing word (foo) is not found in the word-list.",
                ThreeMissIndex,
                new uint[6] { 979,455, 979,0, 0,0 },
                new int[3] { 2, 2, 0 }
            };

            // Valid list (equal size => no swapping)
            yield return new object[]
            {
                BuildSS(ThreeMiss, 3, true),
                new string[3][]
                {
                    new string[2] { "kidney", "decline" },
                    new string[2] { "kidney", "same" },
                    new string[2] { "drift", "six", }
                },
                new string[3][]
                {
                    new string[2] { "kidney", "decline" },
                    new string[2] { "kidney", "same" },
                    new string[2] { "drift", "six", }
                },
                true, string.Empty,
                ThreeMissIndex,
                new uint[6] { 979,455, 979,1527, 534,1614 },
                new int[3] { 2, 2, 2 }
            };
            // Valid list (first array is bigger => no swapping)
            yield return new object[]
            {
                BuildSS(ThreeMiss, 3, true),
                new string[3][]
                {
                    new string[4] { "kidney", "decline", "demand", "nation" },
                    new string[2] { "kidney", "same" },
                    new string[3] { "drift", "six", "gaze" }
                },
                new string[3][]
                {
                    new string[4] { "kidney", "decline", "demand", "nation" },
                    new string[2] { "kidney", "same" },
                    new string[3] { "drift", "six", "gaze" }
                },
                true, string.Empty,
                ThreeMissIndex,
                new uint[9] { 979,455,465,1178, 979,1527, 534,1614,773 },
                new int[3] { 4, 2, 3 }
            };
            // Valid list (third array is bigger => swapped)
            yield return new object[]
            {
                BuildSS(ThreeMiss, 3, true),
                new string[3][]
                {
                    new string[3] { "drift", "six", "gaze" },
                    new string[2] { "kidney", "same" },
                    new string[4] { "kidney", "decline", "demand", "nation" },
                },
                new string[3][]
                {
                    new string[4] { "kidney", "decline", "demand", "nation" },
                    new string[2] { "kidney", "same" },
                    new string[3] { "drift", "six", "gaze" }
                },
                true, string.Empty,
                new int[] { 10, 5, 3 }, // swapped
                new uint[9] { 979,455,465,1178, 979,1527, 534,1614,773 },
                new int[3] { 4, 2, 3 }
            };
        }
        [Theory]
        [MemberData(nameof(GetSetValuesCases))]
        public void SetValuesTest(MnemonicSearchSpace ss, string[][] array, string[][] expArray, bool expected, string expMsg,
                                  int[] expMissIndex, uint[] expPermVals, int[] expPermCounts)
        {
            bool actual = ss.SetValues(array, out string error);

            Assert.Equal(expected, actual);
            Assert.Contains(expMsg, error);
            Assert.Equal(expArray, array);
            Assert.Equal(expMissIndex, ss.MissingIndexes);
            Assert.Equal(expPermVals, ss.AllPermutationValues);
            Assert.Equal(expPermCounts, ss.PermutationCounts);
        }
    }
}
