// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Models;
using System;

namespace Tests.Models
{
    public class PermutationVarTests
    {
        [Fact]
        public unsafe void IncrementTest()
        {
            Span<byte> values = new byte[6];
            Span<int> lens = new int[3] { 3, 1, 2 };
            fixed (byte* pt = values)
            fixed (int* lpt = lens)
            {
                PermutationVar p = new(lens.Length, pt, lpt);
                Assert.Equal(lens.Length, p.max);

                Helper.ComparePrivateField(p, "index", 0);
                Helper.ComparePrivateField(p, "pos", 0);

                Assert.True(p.Increment());
                Helper.ComparePrivateField(p, "index", 1);
                Helper.ComparePrivateField(p, "pos", 3);

                Assert.True(p.Increment());
                Helper.ComparePrivateField(p, "index", 2);
                Helper.ComparePrivateField(p, "pos", 4);

                Assert.False(p.Increment());
                Helper.ComparePrivateField(p, "index", 0);
                Helper.ComparePrivateField(p, "pos", 0);
            }
        }

        [Fact]
        public unsafe void WriteValueTest()
        {
            const int resLen = 6;
            byte[] result = new byte[resLen];
            Span<byte> values = new byte[6] { 1, 2, 3, 4, 5, 6 };
            Span<int> lens = new int[3] { 3, 1, 2 };
            fixed (byte* pt = values, r = result)
            fixed (int* lpt = lens)
            {
                byte* rpt = r;

                PermutationVar p = new(lens.Length, pt, lpt);
                Assert.Equal(lens.Length, p.max);

                int len = p.WriteValue(rpt, resLen);
                Assert.Equal(lens[0], len);
                Assert.Equal(new byte[resLen] { 1, 2, 3, 0, 0, 0 }, result);

                len = p.WriteValue(rpt, resLen); // Repeated calls doesn't change value
                Assert.Equal(lens[0], len);
                Assert.Equal(new byte[resLen] { 1, 2, 3, 0, 0, 0 }, result);

                Assert.True(p.Increment());
                rpt += len;
                len = p.WriteValue(rpt, resLen);
                Assert.Equal(lens[1], len);
                Assert.Equal(new byte[resLen] { 1, 2, 3, 4, 0, 0 }, result);

                Assert.True(p.Increment());
                rpt += len;
                len = p.WriteValue(rpt, resLen);
                Assert.Equal(lens[2], len);
                Assert.Equal(new byte[resLen] { 1, 2, 3, 4, 5, 6 }, result);

                Assert.False(p.Increment());
            }
        }
    }
}
