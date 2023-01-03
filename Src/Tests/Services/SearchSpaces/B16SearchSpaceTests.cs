// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend;
using FinderOuter.Services.SearchSpaces;
using System.Collections.Generic;
using Xunit;

namespace Tests.Services.SearchSpaces
{
    public class B16SearchSpaceTests
    {
        public static IEnumerable<object[]> GetProcessCases()
        {
            yield return new object[] 
            {
                "a", 'z', false, $"Invalid missing character. Choose one from {ConstantsFO.MissingSymbols}", 0, null 
            };
            yield return new object[] { null, '*', false, "Key can not be null or empty.", 0, null };
            yield return new object[] { string.Empty, '*', false, "Key can not be null or empty.", 0, null };
            yield return new object[] 
            { 
                "a", '*', false, "A Base-16 private key must have 64 characters. Input is missing 63 character(s).", 0, null
            };
            yield return new object[]
            {
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", '*', false,
                "Out of range (invalid) private key.", 0, null
            };
            yield return new object[]
            {
                "346c73a81589d046b89ff54a23c4441f1a8a32e87b300cb19211e6bdedec85b3", '*', true, null, 0, null
            };
            yield return new object[]
            {
                "346c73a81589d046b89ff54a23c4441f1a8a32e87b300cb19211e6bdedec85b*", '*', true, null, 1, new int[] { 63 }
            };
            yield return new object[]
            {
                "346c73a81589d046b89ff54a23c4441f1a8a32e87b300cb19211e6bdedec85*3", '*', true, null, 1, new int[] { 62 }
            };
            yield return new object[]
            {
                "*46c73a81589***6b89ff54a23c444*f**8a32e87b300c*19211e6bdedec8*b3", '*', true, null, 9,
                new int[9] { 0, 12, 13, 14, 30, 32, 33, 46, 61 }
            };
        }
        [Theory]
        [MemberData(nameof(GetProcessCases))]
        public void ProcessTest(string input, char missChar, bool expB, string expErr, int expMisCount, int[] misIndex)
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
            }
        }
    }
}
