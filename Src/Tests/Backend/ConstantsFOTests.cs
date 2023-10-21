// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend;
using System.Linq;

namespace Tests.Backend
{
    public class ConstantsFOTests
    {
        [Fact]
        public void SimilarBase58CharsTest()
        {
            // Make sure each array has no duplicate character
            for (int i = 0; i < ConstantsFO.SimilarBase58Chars.Length; i++)
            {
                for (int j = 0; j < ConstantsFO.SimilarBase58Chars[i].Length; j++)
                {
                    int count = ConstantsFO.SimilarBase58Chars[i].Count(c => c == ConstantsFO.SimilarBase58Chars[i][j]);
                    Assert.Equal(1, count);
                }
            }

            // Make sure each character only exists in one array
            for (int i = 0; i < ConstantsFO.SimilarBase58Chars.Length - 1; i++)
            {
                for (int j = i + 1; j < ConstantsFO.SimilarBase58Chars.Length; j++)
                {
                    foreach (var c in ConstantsFO.SimilarBase58Chars[i])
                    {
                        Assert.DoesNotContain(c, ConstantsFO.SimilarBase58Chars[j]);
                    }
                }
            }
        }
    }
}
