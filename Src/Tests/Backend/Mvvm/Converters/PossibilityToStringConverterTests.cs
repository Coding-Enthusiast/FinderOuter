// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend.Mvvm.Converters;
using FinderOuter.Models;

namespace Tests.Backend.Mvvm.Converters
{
    public class PossibilityToStringConverterTests
    {
        [Theory]
        [InlineData(Possibility.Maybe, "?")]
        [InlineData(Possibility.Possible, "✔")]
        [InlineData(Possibility.Impossible, "X")]
        public void ConvertTest(Possibility val, string expected)
        {
            PossibilityToStringConverter conv = new();
            object actual = conv.Convert(val, null, null, null);
            Assert.Equal(expected, actual);
        }
    }
}
