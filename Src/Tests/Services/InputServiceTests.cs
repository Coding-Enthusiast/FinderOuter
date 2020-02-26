// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Services;
using Xunit;

namespace Tests.Services
{
    public class InputServiceTests
    {
        [Theory]
        [InlineData("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")]
        [InlineData("5HueCGU8*MjxEXxiPuD5BDku4MkFqeZyd4dZ*jvhTVqvbTLvyT*")]
        [InlineData("KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617")]
        [InlineData("K%dMAjG^erYan$eui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP9*617")]
        [InlineData("L53fCHmQhbNp1B4JipfBtf*HZH7cAibzG9oK19X(iFzxHgAkz6JK")]
        public void CanBePrivateKeyTest(string key)
        {
            InputService serv = new InputService();
            bool actual = serv.CanBePrivateKey(key);
            Assert.True(actual);
        }

        [Theory]
        [InlineData("")]
        [InlineData("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyT")]
        [InlineData("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyT1234")]
        [InlineData("5HueCGU8*MjxEXxiPuD5BDku4MkFqeZyd4dZ*jvhTVqvbTLvy*")]
        [InlineData("KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP9867")]
        [InlineData("Kw")]
        [InlineData("KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98671234")]
        [InlineData("L53fCHmQhbNp1B4JipfBtfeHZH7cAibzG9oK19XfiFzxHgAkz6J")]
        [InlineData("L53fCHmQhbNp1B4JipfBtfeHZH7cAibzG9oK19XfiFzxHgAkz6JK1")]
        public void CanBePrivateKey_FalseTest(string key)
        {
            InputService serv = new InputService();
            bool actual = serv.CanBePrivateKey(key);
            Assert.False(actual);
        }

        [Theory]
        [InlineData("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", true, "77bff20c60e522dfaa3350c39b030a5d004e839a")]
        [InlineData("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", true, "e8df018c7e326cc253faac7e46cdc51e68542c42")]
        public void IsValidAddressTest(string addr, bool ignore, string expectedHash)
        {
            InputService serv = new InputService();
            bool actual = serv.IsValidAddress(addr, ignore, out byte[] actualHash);
            Assert.True(actual);
            Assert.Equal(Helper.HexToBytes(expectedHash), actualHash);
        }

        [Theory]
        [InlineData(null, true)]
        [InlineData("", true)]
        [InlineData(" ", true)]
        [InlineData("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN1", true)] // Invalid checksum
        [InlineData("1#vBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", true)] // Invalid char
        [InlineData("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", true)] // Valid P2SH address
        [InlineData("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNL1", false)] // Invalid P2SH address (checksum)
        [InlineData("tb1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", true)]
        [InlineData("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5md2", true)]
        public void IsValidAddress_FalseTest(string addr, bool ignore)
        {
            InputService serv = new InputService();
            bool actual = serv.IsValidAddress(addr, ignore, out byte[] actualHash);
            Assert.False(actual);
            Assert.Null(actualHash);
        }
    }
}
