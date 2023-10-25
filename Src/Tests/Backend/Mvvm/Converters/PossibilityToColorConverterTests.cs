// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Avalonia.Media;
using FinderOuter.Backend.Mvvm.Converters;
using FinderOuter.Models;

namespace Tests.Backend.Mvvm.Converters
{
    public class PossibilityToColorConverterTests
    {
        [Fact]
        public void ConvertTest()
        {
            PossibilityToColorConverter conv = new();
            object actual1 = conv.Convert(Possibility.Maybe, null, null, null);
            object actual2 = conv.Convert(Possibility.Possible, null, null, null);
            object actual3 = conv.Convert(Possibility.Impossible, null, null, null);

            Assert.Equal(Brushes.Blue, actual1);
            Assert.Equal(Brushes.Green, actual2);
            Assert.Equal(Brushes.Red, actual3);
        }
    }
}
