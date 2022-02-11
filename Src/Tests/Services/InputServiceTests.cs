// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Services;
using System.Collections.Generic;
using Xunit;

namespace Tests.Services
{
    public class InputServiceTests
    {
        private const string ValidCompKey = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
        private const string ValidUnCompKey1 = "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617";
        private const string ValidUnCompKey2 = "L53fCHmQhbNp1B4JipfBtfeHZH7cAibzG9oK19XfiFzxHgAkz6JK";

        private const string ValidP2pkhAddr = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
        private const string ValidP2shAddr = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";


        [Theory]
        [InlineData("", "can not be null")]
        [InlineData("SzavMBLoXU6kDrqtUVmffv", "Compressed:")]
        public void CheckMiniKeyTest(string key, string expectedMsg)
        {
            InputService serv = new();
            string actualMsg = serv.CheckMiniKey(key);
            Assert.Contains(expectedMsg, actualMsg);
        }

        [Theory]
        [InlineData("6PRWdmoT1ZursVcr5NiD14p5bHrKVGPG7yeEoEeRb8FVaqYSHnZTLEbYsU", true, "The given BIP-38 string is valid.")]
        [InlineData("6PnZki3vKspApf2zym6Anp2jd5hiZbuaZArPfa2ePcgVf196PLGrQNyVUh", true, "The given BIP-38 string is valid.")]
        [InlineData("6PRWdmoT1ZursVcr5NiD14p5bHrKVGPG7yeEoEeRb8FVaqYSHnZTLEbYs$", false, "The given BIP-38 string contains invalid base-58 characters.")]
        [InlineData("6PRWdmoT1ZursVcr5NiD14p5bHrKVGPG7yeEoEeRb8FVaqYSHnZTLEbYs1", false, "The given BIP-38 string has an invalid checksum.")]
        [InlineData("2DnRqfF9cUPrMxRSAbprPfviNN37TLoH7Zmgq5uS4CcTQymH9nfcFXvXX", false, "The given BIP-38 string has an invalid byte length.")]
        [InlineData("AfEEGJ8HqcGUofEyL7Cr6R73LJbus3tuKFMHEiBmT6X1H8npuj94cMrcai", false, "The given BIP-38 string has invalid starting bytes.")]
        [InlineData("6RMoGm8dMt4BH2WLE6jLYNeF6B4SZ4WHmg6PRggwCQYqJPPwU32uVBH8Be", false, "The given BIP-38 string has invalid starting bytes.")]
        public void CheckBase58Bip38Test(string bip38, bool expected, string expectedMsg)
        {
            InputService serv = new();
            bool actual = serv.CheckBase58Bip38(bip38, out string actualMsg);
            Assert.Equal(expected, actual);
            Assert.Equal(expectedMsg, actualMsg);
        }


        [Theory]
        [InlineData(ValidP2pkhAddr, "The given address is a valid base-58 encoded address used for P2PKH scripts.")]
        [InlineData(ValidP2shAddr, "The given address is a valid base-58 encoded address used for P2SH scripts.")]
        [InlineData("1BvBMSEYstWetqTFn5Au4m4$Fg7xJaNVN2", "The given address contains invalid base-58 characters.")]
        [InlineData("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3", "The given address has an invalid checksum.")]
        [InlineData("12eESoee9vDq6tQtZ6RQfdf3SsHWBQYpd", "The given address byte length is invalid.")]
        [InlineData("34q4KRuJeVGJ79f8jRkexoEnFKP1fRjqp", "The given address starts with an invalid byte.")]
        public void CheckBase58AddressTest(string addr, string expectedMsg)
        {
            InputService serv = new();
            string actualMsg = serv.CheckBase58Address(addr);
            Assert.Equal(expectedMsg, actualMsg);
        }


        [Theory]
        [InlineData(ValidCompKey)]
        [InlineData(ValidUnCompKey1)]
        [InlineData(ValidUnCompKey2)]
        [InlineData("5HueCGU8*MjxEXxiPuD5BDku4MkFqeZyd4dZ*jvhTVqvbTLvyT*")]
        [InlineData("K%dMAjG^erYan$eui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP9*617")]
        [InlineData("L53fCHmQhbNp1B4JipfBtf*HZH7cAibzG9oK19X(iFzxHgAkz6JK")]
        public void CanBePrivateKeyTest(string key)
        {
            InputService serv = new();
            bool actual = serv.CanBePrivateKey(key, out string error);
            Assert.True(actual, error);
            Assert.Null(error);
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
            InputService serv = new();
            bool actual = serv.CanBePrivateKey(key, out _);
            Assert.False(actual);
        }

        [Theory]
        [InlineData(ValidCompKey, '*')]
        [InlineData("5HueCGU8r*jxEXxi*uD5*Dku4MkFqeZyd4dZ1jvhTVqvbTL*yTJ", '*')]
        [InlineData("5HueCG--------------------kFqeZyd4dZ1jvhTVqvbTLvyTJ", '-')]
        [InlineData(ValidUnCompKey1, '*')]
        [InlineData("KwdMAjGmerYanjeui5SHS7J*mpZvVipYvB2LJGU1ZxJwYvP98617", '*')]
        [InlineData(ValidUnCompKey2, '*')]
        [InlineData("L53fCHmQ$$Np1B4JipfBt$eHZH$cAibz$9oK1$XfiFzxHgAkz6$$", '$')]

        [InlineData("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLv", '$')]
        [InlineData("5HueGU8rMjxExPuD5BDku4kFqeZyddZjvhTVvbLvyTJ", '$')]
        [InlineData("KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP9", '$')]
        [InlineData("L53fCHmNp1B4JipfBtfeHZH7cAibzG9oK19XfiFzxHgA", '$')]
        public void CheckIncompletePrivateKeyTest(string key, char missingChar)
        {
            InputService serv = new();
            bool actual = serv.CheckIncompletePrivateKey(key, missingChar, out string error);
            Assert.True(actual, error);
            Assert.Null(error);
        }

        [Theory]
        [InlineData(ValidCompKey, '`', "Invalid missing character. Choose one from")]
        [InlineData(null, '*', "Key can not be null or empty.")]
        [InlineData(" ", '*', "Key can not be null or empty.")]
        [InlineData("5HueCGU8rMjxEXxiPuD5BDk$4MkFqeZyd4dZ1jvhTVqvbTLvyTJ", '*', "Key contains invalid base-58 characters (ignoring the missing char = *).")]
        [InlineData("5HueCGU8rMjxEXx*PuD5BDk$4MkFqeZyd4dZ1jvhTVqvbTLvyTJ", '*', "Key contains invalid base-58 characters (ignoring the missing char = *).")]
        [InlineData("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJO", '*', "Key contains invalid base-58 characters (ignoring the missing char = *).")]
        [InlineData("5HueCGU8*MjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvy", '*', "Invalid key length.")]
        [InlineData("KwdMAjGmerYanjeui**HS7JkmpZvVi*YvB2LGU1*xJwYv*8617", '*', "Invalid key length.")]
        [InlineData("L53f*HHmQhbNp1B4JipfBtfeHZH7cAibzG9oK19XfiFzxHgAkz6JK1", '*', "Invalid key length.")]
        [InlineData("6HueCGU8rMjxEXxiPuD5BDk*4MkFqeZyd4dZ1jvhTVqvbTLvyTJ", '*', "Invalid first character for an uncompressed private key considering length.")]
        [InlineData("LHueCGU8rMjxEXxiPu*5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ", '*', "Invalid first character for an uncompressed private key considering length.")]
        [InlineData("KHueCGU8rMjxEXxiPuD5BDku4MkFqeZy*4dZ1jvhTVqvbTLvyTJ", '*', "Invalid first character for an uncompressed private key considering length.")]
        [InlineData("XwdMAjGmerYanjeui5SHS*JkmpZvVipYvB2LJGU1ZxJwYvP98617", '*', "Invalid first character for a compressed private key considering length.")]
        [InlineData("5wdMAjGmerYanjeui5SH*7JkmpZvVipYvB2LJGU1ZxJwYvP98617", '*', "Invalid first character for a compressed private key considering length.")]

        [InlineData("KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP986171", '*', "Key length is too big.")]
        [InlineData("5wdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617", '*', "Invalid first key character considering its length.")]
        [InlineData("UwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617", '*', "Invalid first key character considering its length.")]
        [InlineData("KHueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ", '*', "Invalid first key character considering its length.")]
        [InlineData("6HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ", '*', "Invalid first key character considering its length.")]
        [InlineData("mwdMAjGmerYanjeui5SHS7Jkm", '*', "The first character of the given private key is not valid.")]
        public void CheckIncompletePrivateKey_FailTest(string key, char missingChar, string expError)
        {
            InputService serv = new();
            bool actual = serv.CheckIncompletePrivateKey(key, missingChar, out string error);
            Assert.False(actual);
            Assert.Contains(expError, error);
        }

        [Theory]
        [InlineData('*', true)]
        [InlineData('-', true)]
        [InlineData('$', true)]
        [InlineData('_', true)]
        [InlineData(' ', false)]
        [InlineData('a', false)]
        [InlineData('B', false)]
        [InlineData('`', false)]
        [InlineData('(', false)]
        public void IsMissingCharValidTest(char c, bool expected)
        {
            InputService serv = new();
            Assert.Equal(expected, serv.IsMissingCharValid(c));
        }

        [Theory]
        [InlineData("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", true, "77bff20c60e522dfaa3350c39b030a5d004e839a")]
        [InlineData("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", true, "e8df018c7e326cc253faac7e46cdc51e68542c42")]
        public void IsValidAddressTest(string addr, bool ignore, string expectedHash)
        {
            InputService serv = new();
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
            InputService serv = new();
            bool actual = serv.IsValidAddress(addr, ignore, out byte[] actualHash);
            Assert.False(actual);
            Assert.Null(actualHash);
        }


        public static IEnumerable<object[]> GetBip38DecodeCases()
        {
            yield return new object[]
            {
                "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
                true,
                Helper.HexToBytes("70e4a0805f15a77efc738f794068d8837c2985a6945f7fe0db3f75dc305eaf7c"),
                Helper.HexToBytes("43be4179"),
                true,
                false,
                false,
                null
            };
            yield return new object[]
            {
                "6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg",
                true,
                Helper.HexToBytes("d357fafb81c71f8375a9a4d0ac02bad5f6c87c4b459fabe34c0c314b33708ec3"),
                Helper.HexToBytes("e957a24a"),
                false,
                false,
                false,
                null
            };
            yield return new object[]
            {
                "Foo",
                false, null, null, false, false, false,
                "Invalid Base-58 encoding."
            };
            yield return new object[]
            {
                "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUe1",
                false, null, null, false, false, false,
                "Invalid Base-58 encoding."
            };
            yield return new object[]
            {
                "142viJrTYHA4TzryiEiuQkYk4Ay5TfpzqW",
                false, null, null, false, false, false,
                "Invalid encrypted bytes length."
            };
            yield return new object[]
            {
                "6Mc5gZg3pNQNMsnHDmZeRfhL1QnC24yBd1VERr3HSnKap5x2wcxYaJivvW",
                false, null, null, false, false, false,
                "Invalid prefix."
            };
            yield return new object[]
            {
                "6Mc5gZg3pNQNMsnHDmZeRfhL1QnC24yBd1VERr3HSnKap5x2wcxYaJivvW",
                false, null, null, false, false, false,
                "Invalid prefix."
            };
            yield return new object[]
            {
                "6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX",
                true,
                Helper.HexToBytes("a50dba6772cb938331a7c4ec3b84deba1749e6be9706cf334fed7df565c0c9fb"),
                Helper.HexToBytes("62b5b722"),
                false,
                true,
                false,
                null
            };
            yield return new object[]
            {
                "6PfLGnQs6VZnrNpmVKfjotbnQuaJK4KZoPFrAjx1JMJUa1Ft8gnf5WxfKd",
                true,
                Helper.HexToBytes("67010a95734189066214de0ae75c4e2b99b224951e2654eb8c3e3c6ee5373fe3"),
                Helper.HexToBytes("059a5481"),
                false,
                true,
                false,
                null
            };
            yield return new object[]
            {
                "6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1j",
                true,
                Helper.HexToBytes("4fca5a974040f00169b14acff7bf5b659d43f73f9274631308ee405700fc8585"),
                Helper.HexToBytes("bb458cef"),
                false,
                true,
                true,
                null
            };
            yield return new object[]
            {
                "6PgGWtx25kUg8QWvwuJAgorN6k9FbE25rv5dMRwu5SKMnfpfVe5mar2ngH",
                true,
                Helper.HexToBytes("c40ea76fc501a001fb67c883b966b6ff3c39b90264cbdc3b762d55182866c44c"),
                Helper.HexToBytes("494af136"),
                false,
                true,
                true,
                null
            };
            yield return new object[]
            {
                "6PnTB7C3RDmPZsp4LraT77XU8NuiS5grF9iJG6iGu9RXhS6HAB122cEz81",
                true,
                Helper.HexToBytes("aaf901dd48a9d6e6b75a213d7fe68f351061f87c5cab133bb6ec3bce6bb35acd"),
                Helper.HexToBytes("7b95f71f"),
                true,
                true,
                false,
                null
            };
        }
        [Theory]
        [MemberData(nameof(GetBip38DecodeCases))]
        public void TryDecodeBip38Test(string bip38, bool expValid, byte[] expData, byte[] expSalt,
                                       bool expComp, bool expEC, bool expLot, string expErr)
        {
            InputService serv = new();
            bool actualValid = serv.TryDecodeBip38(bip38, out byte[] data, out byte[] salt,
                out bool isComp, out bool isEC, out bool hasLot, out string error);

            Assert.Equal(expValid, actualValid);
            Assert.Equal(expData, data);
            Assert.Equal(expSalt, salt);
            Assert.Equal(expComp, isComp);
            Assert.Equal(expEC, isEC);
            Assert.Equal(expLot, hasLot);
            Assert.Equal(expErr, error);
        }
    }
}
