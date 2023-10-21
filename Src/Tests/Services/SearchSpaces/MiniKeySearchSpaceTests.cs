// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend;
using FinderOuter.Services.SearchSpaces;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Tests.Services.SearchSpaces
{
    public class MiniKeySearchSpaceTests
    {
        private const string OneMiss = "SzavMBLoXU6kDrqtUVmff*";
        private const string TwoMiss = "Sza*MBLoXU6*DrqtUVmffv";
        private static readonly int[] OneMissIndex = new int[] { 21 };
        private static readonly int[] TwoMissIndex = new int[] { 3, 11 };


        public static IEnumerable<object[]> GetProcessCases()
        {
            yield return new object[]
            {
                "a", 'z', false, $"Invalid missing character. Choose one from {ConstantsFO.MissingSymbols}", 0, null
            };
            yield return new object[] { null, '*', false, "Input can not be null or empty.", 0, null };
            yield return new object[] { string.Empty, '*', false, "Input can not be null or empty.", 0, null };
            yield return new object[]
            {
                "szavMBLoXU6kDrqtUVmffv", '*', false, "Minikey must start with S.", 0, null
            };
            yield return new object[]
            {
                "Sza0MBLoXU6kDrqtUVmffv", '*', false, "Invalid character \"0\" found at index=3.", 0, null
            };
            yield return new object[]
            {
                "Sz*vMBLoXU6kDrqtUVmffvv", '*', false, "Minikey length must be 22 or 26 or 30.", 1, new int[1]
            };
            yield return new object[]
            {
                "SzavMBLoXU6kDrqtUVmffv", '*', true, null, 0, null
            };
            yield return new object[]
            {
                "S*avMBLoXU6kDrqtUVmffv", '*', true, null, 1, new int[1]{1}
            };
            yield return new object[]
            {
                "S*avMB**XU6kD*qtUVm*fv", '*', true, null, 5, new int[5]{1,6,7,13,19}
            };
        }
        [Theory]
        [MemberData(nameof(GetProcessCases))]
        public void ProcessTest(string input, char missChar, bool expB, string expErr, int expMisCount, int[] misIndex)
        {
            MiniKeySearchSpace ss = new();
            bool actualB = ss.Process(input, missChar, out string actualErr);

            Assert.Equal(expB, actualB);
            Assert.Equal(expErr, actualErr);
            Assert.Equal(expMisCount, ss.MissCount);
            Assert.Equal(input, ss.Input);
            Assert.Equal(misIndex, ss.MissingIndexes);
            if (expB && misIndex != null)
            {
                byte[] expPre = new byte[input.Length];
                for (int i = 0; i < expPre.Length; i++)
                {
                    if (!misIndex.Contains(i))
                    {
                        expPre[i] = (byte)input[i];
                    }
                }

                Assert.Equal(expPre, ss.preComputed);
            }
        }


        [Fact]
        public void ProcessNoMissingTest()
        {
            MiniKeySearchSpace ss = new();

            bool b = ss.Process("SzavMBLoXU6kDrqtUVmffv", '*', out _);
            Assert.True(b);
            b = ss.ProcessNoMissing(out string msg);
            Assert.True(b);
            Assert.Contains("Compressed", msg);

            b = ss.Process("SzavMBLoXU6kDrqtUVmffvv", '*', out _);
            Assert.True(b);
            b = ss.ProcessNoMissing(out msg);
            Assert.False(b);
            Assert.Contains("Invalid minikey.", msg);
        }


        private static MiniKeySearchSpace BuildSS(string s, int expMissCount, bool processResult)
        {
            MiniKeySearchSpace ss = new();
            bool b = ss.Process(s, '*', out _);
            Assert.Equal(expMissCount, ss.MissCount);
            Assert.Equal(processResult, b);

            return ss;
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
                BuildSS(TwoMiss, 2, true),
                new string[2][] { new string[2] { "1", "2" }, new string[2] { "b", null } },
                new string[2][] { new string[2] { "1", "2" }, new string[2] { "b", null } },
                false,
                "Given value () is not a valid character.",
                TwoMissIndex, new uint[4] {49,50, 98,0}, new int[2] {2,2}
            };
            yield return new object[]
            {
                BuildSS(TwoMiss, 2, true),
                new string[2][] { new string[2] { "1", "0" }, new string[2] { "a", "1" } },
                new string[2][] { new string[2] { "1", "0" }, new string[2] { "a", "1" } },
                false,
                "Given character (0) is not found in the valid characters list.",
                TwoMissIndex, new uint[4] {49,0, 0,0}, new int[2] {2,0}
            };

            // Valid lists:
            // The second array is bigger => swapped
            yield return new object[]
            {
                BuildSS(TwoMiss, 2, true),
                new string[2][] { new string[2] { "5", "B" }, new string[4] { "i", "D", "2", "x" } },
                new string[2][] { new string[4] { "i", "D", "2", "x" }, new string[2] { "5", "B" } },
                true, string.Empty,
                TwoMissIndex.Reverse().ToArray(), new uint[6] {105,68,50,120, 53,66}, new int[2] {4,2}
            };
        }
        [Theory]
        [MemberData(nameof(GetSetValuesCases))]
        public void SetValuesTest(MiniKeySearchSpace ss, string[][] array, string[][] expArray, bool expected, string expMsg,
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
