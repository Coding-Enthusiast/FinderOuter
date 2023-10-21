// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Services.SearchSpaces;
using System.Numerics;

namespace Tests.Services.SearchSpaces
{
    public class SearchSpaceBaseTests
    {
        public class MockSearchSpace : SearchSpaceBase
        {
            internal void SetPermutationCounts(int[] values) => PermutationCounts = values;
        }



        [Fact]
        public void ConstructorTest()
        {
            MockSearchSpace ss = new();
            Assert.NotNull(ss.PermutationCounts);
        }

        [Fact]
        public void GetTotalTest()
        {
            MockSearchSpace ss = new();
            Assert.Equal(BigInteger.One, ss.GetTotal());

            ss.SetPermutationCounts(new int[3] { 7, 8, 95 });
            BigInteger expected = 7 * 8 * 95;
            Assert.Equal(expected, ss.GetTotal());
        }
    }
}
