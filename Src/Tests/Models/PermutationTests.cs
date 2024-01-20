// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Models;
using System;

namespace Tests.Models
{
    public class PermutationTests
    {
        [Fact]
        public unsafe void IncrementTest()
        {
            Span<uint> values = new uint[4];
            fixed (uint* pt = values)
            {
                Permutation p = new(3, pt);
                Assert.Equal(3, p.max);

                Helper.ComparePrivateField(p, "index", 0);

                Assert.True(p.Increment());
                Helper.ComparePrivateField(p, "index", 1);

                Assert.True(p.Increment());
                Helper.ComparePrivateField(p, "index", 2);

                Assert.False(p.Increment());
                Helper.ComparePrivateField(p, "index", 0);
            }
        }

        [Fact]
        public unsafe void GetValueTest()
        {
            Span<uint> values = new uint[6] { 0, 1, 2, 3, 4, 5 };
            fixed (uint* pt = &values[1])
            {
                Permutation p = new(3, pt);
                Assert.Equal(3, p.max);

                Assert.Equal(1u, p.GetValue());
                Assert.Equal(1u, p.GetValue()); // Repeated calls doesn't change value

                Assert.True(p.Increment());
                Assert.Equal(2u, p.GetValue());

                Assert.True(p.Increment());
                Assert.Equal(3u, p.GetValue());

                Assert.False(p.Increment());
            }
        }
    }
}
