// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter;
using FinderOuter.Models;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Tests
{
    public class ListHelperTests
    {
        public enum Foo
        {
            [Description("Desc 1")]
            Foo1,
            Foo2,
            [Description("Desc 3")]
            Foo3,
            [Description("Desc 4")]
            Foo4,
        }

        public class EqHelper<T> : IEqualityComparer<T> where T : DescriptiveItem<Foo>
        {
            public bool Equals([AllowNull] T x, [AllowNull] T y)
            {
                if (x is null && y is null)
                {
                    return true;
                }
                else if (x is null || y is null)
                {
                    return false;
                }
                else
                {
                    return x.Value == y.Value && x.Description == y.Description;
                }
            }

            public int GetHashCode([DisallowNull] T obj) => HashCode.Combine(obj?.Value);
        }


        [Fact]
        public void GetAllEnumValuesTest()
        {
            IEnumerable<Foo> actual = ListHelper.GetAllEnumValues<Foo>();
            IEnumerable<Foo> expected = new Foo[] { Foo.Foo1, Foo.Foo2, Foo.Foo3, Foo.Foo4 };
            Assert.Equal(expected, actual);
        }

        [Fact]
        public void GetEnumDescItemsTest()
        {
            IEnumerable<DescriptiveItem<Foo>> actual = ListHelper.GetEnumDescItems<Foo>();
            IEnumerable<DescriptiveItem<Foo>> expected = new DescriptiveItem<Foo>[]
            {
                new DescriptiveItem<Foo>(Foo.Foo1),
                new DescriptiveItem<Foo>(Foo.Foo2),
                new DescriptiveItem<Foo>(Foo.Foo3),
                new DescriptiveItem<Foo>(Foo.Foo4),
            };

            Assert.Equal(expected, actual, new EqHelper<DescriptiveItem<Foo>>());
        }

        [Fact]
        public void GetEnumDescItems_WithExclusion_Test()
        {
            IEnumerable<DescriptiveItem<Foo>> actual = ListHelper.GetEnumDescItems(Foo.Foo2, Foo.Foo4);
            IEnumerable<DescriptiveItem<Foo>> expected = new DescriptiveItem<Foo>[]
            {
                new DescriptiveItem<Foo>(Foo.Foo1),
                new DescriptiveItem<Foo>(Foo.Foo3),
            };

            Assert.Equal(expected, actual, new EqHelper<DescriptiveItem<Foo>>());
        }

        [Fact]
        public void GetEnumDescItems_WithInvalidExclusion_Test()
        {
            IEnumerable<DescriptiveItem<Foo>> actual = ListHelper.GetEnumDescItems((Foo)1000);
            IEnumerable<DescriptiveItem<Foo>> expected = new DescriptiveItem<Foo>[]
            {
                new DescriptiveItem<Foo>(Foo.Foo1),
                new DescriptiveItem<Foo>(Foo.Foo2),
                new DescriptiveItem<Foo>(Foo.Foo3),
                new DescriptiveItem<Foo>(Foo.Foo4),
            };

            Assert.Equal(expected, actual, new EqHelper<DescriptiveItem<Foo>>());
        }
    }
}
