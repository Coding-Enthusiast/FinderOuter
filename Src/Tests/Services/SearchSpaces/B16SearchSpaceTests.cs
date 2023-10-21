// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend;
using FinderOuter.Services.Comparers;
using FinderOuter.Services.SearchSpaces;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Tests.Services.SearchSpaces
{
    public class B16SearchSpaceTests
    {
        private const string NoMiss = "346c73a81589d046b89ff54a23c4441f1a8a32e87b300cb19211e6bdedec85b3";
        private const string OneMiss = "346c73a81589d046b89ff54a23c4441f1a8a32e87b300cb19211e6bdedec85b*";
        private const string TwoMiss = "346c73a81589d046b89f*54a23c4441f1a8a32e87b300cb19211e6bdedec85b*";
        private const string Max = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        private const string Zero = "0000000000000000000000000000000000000000000000000000000000000000";
        private static readonly int[] OneMissIndex = new int[] { 63 };
        private static readonly int[] TwoMissIndex = new int[] { 20, 63 };

        public static IEnumerable<object[]> GetProcessCases()
        {
            yield return new object[]
            {
                "a", 'z', false, $"Invalid missing character. Choose one from {ConstantsFO.MissingSymbols}", 0, null, null
            };
            yield return new object[] { null, '*', false, "Key can not be null or empty.", 0, null, null };
            yield return new object[] { string.Empty, '*', false, "Key can not be null or empty.", 0, null, null };
            yield return new object[]
            {
                "a", '*', false, "A Base-16 private key must have 64 characters. Input is missing 63 character(s).", 0, null, null
            };
            yield return new object[]
            {
                Max, '*', false, "Out of range (invalid) private key.", 0, null, null
            };
            yield return new object[]
            {
                NoMiss, '*', true, null, 0, null, null
            };
            yield return new object[]
            {
                OneMiss, '*', true, null, 1, OneMissIndex,
                Helper.HexToBytes("346c73a81589d046b89ff54a23c4441f1a8a32e87b300cb19211e6bdedec85b0")
            };
            yield return new object[]
            {
                "346c73a81589d046b89ff54a23c4441f1a8a32e87b300cb19211e6bdedec85*3", '*', true, null, 1, new int[] { 62 },
                Helper.HexToBytes("346c73a81589d046b89ff54a23c4441f1a8a32e87b300cb19211e6bdedec8503")
            };
            yield return new object[]
            {
                "*46c73a81589***6b89ff54a23c444*f**8a32e87b300c*19211e6bdedec8*b3", '*', true, null, 9,
                new int[9] { 0, 12, 13, 14, 30, 32, 33, 46, 61 },
                Helper.HexToBytes("046c73a815890006b89ff54a23c4440f008a32e87b300c019211e6bdedec80b3")
            };
        }
        [Theory]
        [MemberData(nameof(GetProcessCases))]
        public void ProcessTest(string input, char missChar, bool expB, string expErr, int expMisCount, int[] misIndex, byte[] pre)
        {
            B16SearchSpace ss = new();
            bool actualB = ss.Process(input, missChar, out string actualErr);

            Assert.Equal(expB, actualB);
            Assert.Equal(expErr, actualErr);
            Assert.Equal(expMisCount, ss.MissCount);
            if (expB)
            {
                Assert.Equal(input, ss.Input);
                Assert.Equal(misIndex, ss.MissingIndexes);
                Assert.Equal(pre, ss.preComputed);
            }
        }

        private static B16SearchSpace BuildSS(string s, int expMissCount, bool processResult)
        {
            B16SearchSpace ss = new();
            bool b = ss.Process(s, '*', out _);
            Assert.Equal(expMissCount, ss.MissCount);
            Assert.Equal(processResult, b);

            return ss;
        }

        public static IEnumerable<object[]> GetProcessNoMissingCases()
        {
            ICompareService comp = new DefaultComparer();
            ICompareService comp2 = new PrvToAddrCompComparer();
            Assert.True(comp2.Init(KeyHelper.Pub2CompAddr));

            yield return new object[]
            {
                BuildSS(OneMiss, 1, true), new PrvToPubComparer(), false, "Comparer is not initializd."
            };
            yield return new object[]
            {
                BuildSS(OneMiss, 1, true), comp, false, "This method should not be called with missing characters."
            };
            yield return new object[]
            {
                BuildSS(Max, 0, false), comp, false, "The given key is out of range."
            };
            yield return new object[]
            {
                BuildSS(Zero, 0, false), comp, false, "The given key is out of range."
            };
            yield return new object[]
            {
                BuildSS(NoMiss, 0, true), comp, true, "The given key is valid and the given None is correctly derived from it."
            };
            yield return new object[]
            {
                BuildSS(NoMiss, 0, true), comp2, false, "The given key is valid but the given Address can not be derived from it."
            };
        }
        [Theory]
        [MemberData(nameof(GetProcessNoMissingCases))]
        public void ProcessNoMissingTest(B16SearchSpace ss, ICompareService comparer, bool expected, string expMsg)
        {
            bool actual = ss.ProcessNoMissing(comparer, out string message);
            Assert.Equal(expected, actual);
            Assert.Contains(expMsg, message);
        }


        public static IEnumerable<object[]> GetSetValuesCases()
        {
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
                false,
                "Permutations list doesn't have the same number of arrays as missing characters count.",
                OneMissIndex, null, Array.Empty<int>()
            };
            yield return new object[]
            {
                BuildSS(OneMiss, 1, true),
                new string[2][] { new string[] { "" }, new string[] { "" } },
                new string[2][] { new string[] { "" }, new string[] { "" } },
                false,
                "Permutations list doesn't have the same number of arrays as missing characters count.",
                OneMissIndex, null, Array.Empty<int>()
            };
            yield return new object[]
            {
                BuildSS(TwoMiss, 2, true),
                new string[2][] { null, new string[2] { "a", "b" } },
                new string[2][] { null, new string[2] { "a", "b" } },
                false,
                "Search space values are not correctly set. Add at least 2 possible values for the 1st missing position.",
                TwoMissIndex, null, Array.Empty<int>()
            };
            yield return new object[]
            {
                BuildSS(TwoMiss, 2, true),
                new string[2][] { new string[1] { "a" }, new string[2] { "a", "b" } },
                new string[2][] { new string[1] { "a" }, new string[2] { "a", "b" } },
                false,
                "Search space values are not correctly set. Add at least 2 possible values for the 1st missing position.",
                TwoMissIndex, null, Array.Empty<int>()
            };
            yield return new object[]
            {
                BuildSS(TwoMiss, 2, true),
                new string[2][] { new string[2] { "a", "b" }, null },
                new string[2][] { new string[2] { "a", "b" }, null },
                false,
                "Search space values are not correctly set. Add at least 2 possible values for the 2nd missing position.",
                TwoMissIndex, null, Array.Empty<int>()
            };
            yield return new object[]
            {
                BuildSS(TwoMiss, 2, true),
                new string[2][] { new string[2] { "a", "b" }, new string[1] { "a" } },
                new string[2][] { new string[2] { "a", "b" }, new string[1] { "a" } },
                false,
                "Search space values are not correctly set. Add at least 2 possible values for the 2nd missing position.",
                TwoMissIndex, null, Array.Empty<int>()
            };
            yield return new object[]
            {
                BuildSS(TwoMiss, 2, true),
                new string[2][] { new string[2] { null, "b" }, new string[2] { "a", "b" } },
                new string[2][] { new string[2] { null, "b" }, new string[2] { "a", "b" } },
                false,
                "Given value () is not a valid character.",
                TwoMissIndex, new uint[4], new int[2] {2, 0}
            };
            yield return new object[]
            {
                BuildSS(TwoMiss, 2, true),
                new string[2][] { new string[2] { "b", null }, new string[2] { "a", "b" } },
                new string[2][] { new string[2] { "b", null }, new string[2] { "a", "b" } },
                false,
                "Given value () is not a valid character.",
                TwoMissIndex, new uint[4] {11,0, 0,0}, new int[2] {2,0}
            };
            yield return new object[]
            {
                BuildSS(TwoMiss, 2, true),
                new string[2][] { new string[2] { "1", "2" }, new string[2] { null, "b" } },
                new string[2][] { new string[2] { "1", "2" }, new string[2] { null, "b" } },
                false,
                "Given value () is not a valid character.",
                TwoMissIndex, new uint[4] {1,2, 0,0}, new int[2] {2,2}
            };
            yield return new object[]
            {
                BuildSS(TwoMiss, 2, true),
                new string[2][] { new string[2] { "1", "2" }, new string[2] { "b", null } },
                new string[2][] { new string[2] { "1", "2" }, new string[2] { "b", null } },
                false,
                "Given value () is not a valid character.",
                TwoMissIndex, new uint[4] {1,2, 11,0}, new int[2] {2,2}
            };
            yield return new object[]
            {
                BuildSS(TwoMiss, 2, true),
                new string[2][] { new string[2] { "11", "2" }, new string[2] { "b", "1" } },
                new string[2][] { new string[2] { "11", "2" }, new string[2] { "b", "1" } },
                false,
                "Given value (11) is not a valid character.",
                TwoMissIndex, new uint[4] {0,0, 0,0}, new int[2] {2,0}
            };
            yield return new object[]
            {
                BuildSS(TwoMiss, 2, true),
                new string[2][] { new string[2] { "1", "2" }, new string[2] { "abc", "1" } },
                new string[2][] { new string[2] { "1", "2" }, new string[2] { "abc", "1" } },
                false,
                "Given value (abc) is not a valid character.",
                TwoMissIndex, new uint[4] {1,2, 0,0}, new int[2] {2,2}
            };
            yield return new object[]
            {
                BuildSS(TwoMiss, 2, true),
                new string[2][] { new string[2] { "1", "x" }, new string[2] { "abc", "1" } },
                new string[2][] { new string[2] { "1", "x" }, new string[2] { "abc", "1" } },
                false,
                "Given character (x) is not found in the valid characters list.",
                TwoMissIndex, new uint[4] {1,0, 0,0}, new int[2] {2,0}
            };

            // Valid lists:
            yield return new object[]
            {
                BuildSS(TwoMiss, 2, true),
                new string[2][] { new string[2] { "5", "3" }, new string[2] { "9", "f" } },
                new string[2][] { new string[2] { "5", "3" }, new string[2] { "9", "f" } },
                true, string.Empty,
                TwoMissIndex, new uint[4] {5,3, 9,15}, new int[2] {2,2}
            };
            // The first array is bigger => no swap
            yield return new object[]
            {
                BuildSS(TwoMiss, 2, true),
                new string[2][] { new string[3] { "5", "3", "a" }, new string[2] { "9", "f" } },
                new string[2][] { new string[3] { "5", "3", "a" }, new string[2] { "9", "f" } },
                true, string.Empty,
                TwoMissIndex, new uint[5] {5,3,10, 9,15}, new int[2] {3,2}
            };
            // The second array is bigger => swapped
            yield return new object[]
            {
                BuildSS(TwoMiss, 2, true),
                new string[2][] { new string[2] { "5", "3" }, new string[4] { "9", "f", "0", "a" } },
                new string[2][] { new string[4] { "9", "f", "0", "a" }, new string[2] { "5", "3" } },
                true, string.Empty,
                TwoMissIndex.Reverse().ToArray(), new uint[6] {9,15,0,10, 5,3}, new int[2] {4,2}
            };
            yield return new object[]
            {
                BuildSS("34*c7*a815*9d046b*9ff54a23c4441f1a8a32e87b300cb19211e6bdedec85b3", 4, true),
                new string[4][]
                {
                    new string[3] { "5", "3", "1" },
                    new string[2] { "9", "f" },
                    new string[4] { "f", "0", "5", "a" },
                    new string[3] { "c", "b", "4" }
                },
                new string[4][]
                {
                    new string[4] { "f", "0", "5", "a" },
                    new string[2] { "9", "f" },
                    new string[3] { "5", "3", "1" },
                    new string[3] { "c", "b", "4" }
                },
                true, string.Empty,
                new int[4] {10,5,2,17}, new uint[12] {15,0,5,10, 9,15, 5,3,1, 12,11,4}, new int[4] {4,2,3,3}
            };
        }
        [Theory]
        [MemberData(nameof(GetSetValuesCases))]
        public void SetValuesTest(B16SearchSpace ss, string[][] array, string[][] expArray, bool expected, string expMsg,
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
