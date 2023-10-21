// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Models;

namespace Tests.Models
{
    public class EncodingStateTests
    {
        [Fact]
        public void ConstructorTest()
        {
            EncodingState state = new(EncodingName.Base58);
            Assert.Equal(EncodingName.Base58, state.Name);
            Assert.Equal(Possibility.Maybe, state.Possible);
        }

        [Fact]
        public void PropertyChangedTest()
        {
            EncodingState state = new(EncodingName.Base58);
            Assert.PropertyChanged(state, nameof(state.Possible), () => state.Possible = Possibility.Possible);
        }

        [Theory]
        [InlineData(EncodingName.Base16, "1", Possibility.Impossible)]
        [InlineData(EncodingName.Base16, "12", Possibility.Possible)]
        [InlineData(EncodingName.Base43, "@", Possibility.Impossible)]
        [InlineData(EncodingName.Base43, "12", Possibility.Possible)]
        [InlineData(EncodingName.Base58, "@", Possibility.Impossible)]
        [InlineData(EncodingName.Base58, "12", Possibility.Possible)]
        [InlineData(EncodingName.Base58Check, "@", Possibility.Impossible)]
        [InlineData(EncodingName.Base58Check, "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", Possibility.Possible)]
        [InlineData(EncodingName.Base64, "@", Possibility.Impossible)]
        [InlineData(EncodingName.Base64, "Zm9v", Possibility.Possible)]
        public void SetPossibilityTest(EncodingName name, string input, Possibility expected)
        {
            EncodingState state = new(name);
            state.SetPossibility(input);
            Assert.Equal(expected, state.Possible);
        }
    }
}
