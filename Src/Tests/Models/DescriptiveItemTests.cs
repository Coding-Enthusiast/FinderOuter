// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Models;
using System.ComponentModel;

namespace Tests.Models
{
    public class DescriptiveItemTests
    {
        public enum MockEnum
        {
            [Description("Foo desc.")]
            Foo,
            [Description("Bar desc.")]
            Bar,
            // No desc.
            FooBar
        }

        [Theory]
        [InlineData(MockEnum.Foo, "Foo desc.")]
        [InlineData(MockEnum.Bar, "Bar desc.")]
        [InlineData(MockEnum.FooBar, "FooBar")]
        [InlineData((MockEnum)123, "123")]
        public void ConstructorTest(MockEnum val, string expected)
        {
            DescriptiveItem<MockEnum> item = new(val);

            Assert.Equal(expected, item.Description);
            Assert.Equal(val, item.Value);
        }
    }
}
