// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend;
using FinderOuter.Models;
using FinderOuter.Services;
using FinderOuter.Services.Comparers;
using System;
using System.Collections.Generic;

namespace Tests.Services
{
    public class InputServiceTests
    {
        internal const string ValidCompKey = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";
        internal const string ValidUnCompKey1 = "KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617";
        internal const string ValidUnCompKey2 = "L53fCHmQhbNp1B4JipfBtfeHZH7cAibzG9oK19XfiFzxHgAkz6JK";

        internal const string ValidP2pkhAddr = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
        internal const string ValidP2shAddr = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";

        internal const string ValidPubHexComp = "030b3ad1cea48c61bdcff356675d92010290cdc2e04e1c9e68b6a01d3cec746c17";
        internal const string ValidPubHexUncomp = "040b3ad1cea48c61bdcff356675d92010290cdc2e04e1c9e68b6a01d3cec746c17b95aedf5242b50b5c82147697351941032602332d5cc81531eec98a9b8f9c7cd";


        [Theory]
        [InlineData(CompareInputType.AddrComp, ValidP2pkhAddr, true, typeof(PrvToAddrCompComparer))]
        [InlineData(CompareInputType.AddrComp, "", false, typeof(PrvToAddrCompComparer))]
        [InlineData(CompareInputType.AddrComp, ValidP2shAddr, false, typeof(PrvToAddrCompComparer))]
        [InlineData(CompareInputType.AddrUnComp, ValidP2pkhAddr, true, typeof(PrvToAddrUncompComparer))]
        [InlineData(CompareInputType.AddrUnComp, "", false, typeof(PrvToAddrUncompComparer))]
        [InlineData(CompareInputType.AddrUnComp, ValidP2shAddr, false, typeof(PrvToAddrUncompComparer))]
        [InlineData(CompareInputType.AddrBoth, ValidP2pkhAddr, true, typeof(PrvToAddrBothComparer))]
        [InlineData(CompareInputType.AddrBoth, ValidP2shAddr, false, typeof(PrvToAddrBothComparer))]
        [InlineData(CompareInputType.AddrBoth, "", false, typeof(PrvToAddrBothComparer))]
        [InlineData(CompareInputType.AddrNested, ValidP2shAddr, true, typeof(PrvToAddrNestedComparer))]
        [InlineData(CompareInputType.AddrNested, ValidP2pkhAddr, false, typeof(PrvToAddrNestedComparer))]
        [InlineData(CompareInputType.AddrNested, "", false, typeof(PrvToAddrNestedComparer))]
        [InlineData(CompareInputType.PrivateKey, ValidCompKey, true, typeof(PrvToPrvComparer))]
        [InlineData(CompareInputType.PrivateKey, ValidUnCompKey1, true, typeof(PrvToPrvComparer))]
        [InlineData(CompareInputType.PrivateKey, ValidUnCompKey2, true, typeof(PrvToPrvComparer))]
        [InlineData(CompareInputType.PrivateKey, "", false, typeof(PrvToPrvComparer))]
        [InlineData(CompareInputType.PrivateKey, ValidP2pkhAddr, false, typeof(PrvToPrvComparer))]
        [InlineData(CompareInputType.Pubkey, ValidPubHexComp, true, typeof(PrvToPubComparer))]
        [InlineData(CompareInputType.Pubkey, ValidPubHexUncomp, true, typeof(PrvToPubComparer))]
        [InlineData(CompareInputType.Pubkey, ValidP2pkhAddr, false, typeof(PrvToPubComparer))]
        public void TryGetCompareServiceTest(CompareInputType t, string input, bool expB, Type expType)
        {
            bool actualB = InputService.TryGetCompareService(t, input, out ICompareService actual);
            Assert.Equal(expB, actualB);
            Assert.IsType(expType, actual);
        }

        [Fact]
        public void TryGetCompareService_NullTest()
        {
            bool actualB = InputService.TryGetCompareService((CompareInputType)1000, "", out ICompareService actualComp);
            Assert.False(actualB);
            Assert.Null(actualComp);
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
            Assert.Equal(expected, InputService.IsMissingCharValid(c));
        }

        public static IEnumerable<object[]> GetCheckCharsCases()
        {
            yield return new object[] { "abc", "abcde", '*', true, "" };
            yield return new object[] { "ab1", "abcde", '*', false, "Invalid character \"1\" found at index=2." };
            yield return new object[] { "fabcde", "abcde", '*', false, "Invalid character \"f\" found at index=0." };
            yield return new object[]
            {
                "faAcde", "abcde", '*', false,
                $"Invalid character \"f\" found at index=0.{Environment.NewLine}Invalid character \"A\" found at index=2."
            };
            yield return new object[] { "a*b", "abcde", '?', false, "Invalid character \"*\" found at index=1." };
            yield return new object[] { " ", "abcde", '*', false, "Invalid character \" \" found at index=0." };
            yield return new object[] { "a ", "abcde", '*', false, "Invalid character \" \" found at index=1." };
            yield return new object[] { "a*b", "abcde", '*', true, "" };
            yield return new object[] { "***", "abcde", '*', true, "" };
            yield return new object[] { "ab", "abcde", null, true, "" };
            yield return new object[] { "ab*", "abcde", null, false, "Invalid character \"*\" found at index=2." };
        }
        [Theory]
        [MemberData(nameof(GetCheckCharsCases))]
        public void CheckCharsTest(string input, string charSet, char? ignore, bool expected, string expErr)
        {
            bool actual = InputService.CheckChars(input, charSet, ignore, out string error);
            Assert.Equal(expected, actual);
            Assert.Equal(expErr, error);
        }


        public static IEnumerable<object[]> GetKeyInRangeCases()
        {
            yield return new object[] { null, false };
            yield return new object[] { new byte[32], false };
            yield return new object[]
            {
                Helper.HexToBytes("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), false
            };
            yield return new object[]
            {
                Helper.HexToBytes("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"), false // N
            };
            yield return new object[]
            {
                Helper.HexToBytes("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"), true // N-1
            };
        }
        [Theory]
        [MemberData(nameof(GetKeyInRangeCases))]
        public void IsPrivateKeyInRange(byte[] key, bool expected)
        {
            bool actual = InputService.IsPrivateKeyInRange(key);
            Assert.Equal(expected, actual);
        }


        public static IEnumerable<object[]> GetBase16KeyCases()
        {
            yield return new object[]
            {
                "0591b71f000d4c4b8060c7b3d2488b619db074d603cdbddcf13809de5a529473",
                '*',
                true,
                "Given key is valid."
            };
            yield return new object[]
            {
                "0591b71f000d4c4b8060c7b3d2488b619db074d603cdbddcf13809de5a529473",
                'x',
                false,
                $"Invalid missing character. Choose one from {ConstantsFO.MissingSymbols}"
            };
            yield return new object[]
            {
                "0591b71f000d4c4b8060c7b3d2488b619db074d603cdbddcf13809de5a5294734",
                '*',
                false,
                "A Base-16 private key must have 64 characters. Input has 1 extra character(s)."
            };
            yield return new object[]
            {
                "0591b71f000d4c4b8060c7b3d2488b619db074d603cdbddcf13809de5a5294",
                '*',
                false,
                "A Base-16 private key must have 64 characters. Input is missing 2 character(s)."
            };
            yield return new object[]
            {
                "*591b71f000d4c4b8060c7b3d248*b6*9db*74d6*3cdb*dcf13809de5a5*947*",
                '*',
                true,
                "Given key is valid."
            };
            yield return new object[]
            {
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                '*',
                false,
                "Out of range (invalid) private key."
            };
            yield return new object[]
            {
                // N
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
                '*',
                false,
                "Out of range (invalid) private key."
            };
            yield return new object[]
            {
                // N-1
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
                '*',
                true,
                "Given key is valid."
            };
            yield return new object[]
            {
                // N-1 but incrementing the missing char (last char) will lead to overflow
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd036414*",
                '*',
                false,
                "The given key is an edge case that can overflow."
            };
        }
        [Theory]
        [MemberData(nameof(GetBase16KeyCases))]
        public void IsValidBase16KeyTest(string key, char c, bool expB, string expectedMsg)
        {
            bool actB = InputService.IsValidBase16Key(key, c, out string actualMsg);
            Assert.Equal(expB, actB);
            Assert.Equal(expectedMsg, actualMsg);
        }


        [Theory]
        [InlineData("", false, "can not be null")]
        [InlineData("SzavMBLoXU6kDrqtUVmffv", true, "Compressed:")]
        public void IsValidMinikeyTest(string key, bool expected, string expectedMsg)
        {
            bool actual = InputService.IsValidMinikey(key, out string actualMsg);
            Assert.Equal(expected, actual);
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
        public void IsValidBase58Bip38Test(string bip38, bool expected, string expectedMsg)
        {
            bool actual = InputService.IsValidBase58Bip38(bip38, out string actualMsg);
            Assert.Equal(expected, actual);
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
            bool actual = InputService.CanBePrivateKey(key, out string error);
            Assert.True(actual, error);
            Assert.Null(error);
        }

        [Theory]
        [InlineData(ValidP2pkhAddr, true, "The given address is a valid base-58 encoded address used for P2PKH scripts.")]
        [InlineData(ValidP2shAddr, true, "The given address is a valid base-58 encoded address used for P2SH scripts.")]
        [InlineData("1BvBMSEYstWetqTFn5Au4m4$Fg7xJaNVN2", false, "The given address contains invalid base-58 characters.")]
        [InlineData("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3", false, "The given address has an invalid checksum.")]
        [InlineData("12eESoee9vDq6tQtZ6RQfdf3SsHWBQYpd", false, "The given address byte length is invalid.")]
        [InlineData("34q4KRuJeVGJ79f8jRkexoEnFKP1fRjqp", false, "The given address starts with an invalid byte.")]
        public void IsValidBase58AddressTest(string addr, bool expB, string expectedMsg)
        {
            bool actB = InputService.IsValidBase58Address(addr, out string actualMsg);
            Assert.Equal(expB, actB);
            Assert.Equal(expectedMsg, actualMsg);
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
            bool actual = InputService.CanBePrivateKey(key, out _);
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
            bool actual = InputService.CheckIncompletePrivateKey(key, missingChar, out string error);
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
            bool actual = InputService.CheckIncompletePrivateKey(key, missingChar, out string error);
            Assert.False(actual);
            Assert.Contains(expError, error);
        }



        [Theory]
        [InlineData("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", true, "77bff20c60e522dfaa3350c39b030a5d004e839a")]
        [InlineData("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", true, "e8df018c7e326cc253faac7e46cdc51e68542c42")]
        public void IsValidAddressTest(string addr, bool ignore, string expectedHash)
        {
            bool actual = InputService.IsValidAddress(addr, ignore, out byte[] actualHash);
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
            bool actual = InputService.IsValidAddress(addr, ignore, out byte[] actualHash);
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
            bool actualValid = InputService.TryDecodeBip38(bip38, out byte[] data, out byte[] salt,
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
