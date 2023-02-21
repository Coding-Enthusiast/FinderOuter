// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend;
using FinderOuter.Services.SearchSpaces;
using System;
using System.Collections.Generic;
using System.Linq;
using Xunit;

namespace Tests.Services.SearchSpaces
{
    public class MiniKeySearchSpaceTests
    {
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
    }
}
