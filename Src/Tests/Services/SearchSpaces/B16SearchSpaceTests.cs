// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend;
using FinderOuter.Services.Comparers;
using FinderOuter.Services.SearchSpaces;
using System.Collections.Generic;
using Xunit;

namespace Tests.Services.SearchSpaces
{
    public class B16SearchSpaceTests
    {
        private const string NoMiss = "346c73a81589d046b89ff54a23c4441f1a8a32e87b300cb19211e6bdedec85b3";
        private const string OneMiss = "346c73a81589d046b89ff54a23c4441f1a8a32e87b300cb19211e6bdedec85b*";
        private const string Max = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        private const string Zero = "0000000000000000000000000000000000000000000000000000000000000000";

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
                OneMiss, '*', true, null, 1, new int[] { 63 },
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
    }
}
