// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Models;
using FinderOuter.ViewModels;
using System;
using System.Collections.Generic;

namespace Tests.ViewModels
{
    public class MissingEncodingViewModelTests
    {
        [Fact]
        public void ConstructorTest()
        {
            MissingEncodingViewModel vm = new();
            Assert.NotEmpty(vm.EncodingList);
            Assert.NotNull(vm.FindCommand);
            Assert.NotNull(vm.DecodeCommand);
        }

        [Fact]
        public void PropertyChangedTest()
        {
            MissingEncodingViewModel vm = new();
            Assert.PropertyChanged(vm, nameof(vm.Text), () => vm.Text = "foo");
        }

        [Fact]
        public void SetTextTest()
        {
            MissingEncodingViewModel vm = new();
            foreach (var item in vm.EncodingList)
            {
                item.Possible = Possibility.Possible;
            }
            vm.Text = "foo";
            foreach (var item in vm.EncodingList)
            {
                Assert.Equal(Possibility.Maybe, item.Possible);
            }
        }

        [Fact]
        public void FindTest()
        {
            MissingEncodingViewModel vm = new()
            {
                Text = "foo"
            };
            foreach (var item in vm.EncodingList)
            {
                Assert.Equal(Possibility.Maybe, item.Possible);
            }

            vm.Find();

            foreach (var item in vm.EncodingList)
            {
                Assert.NotEqual(Possibility.Maybe, item.Possible);
            }
        }


        public static IEnumerable<object[]> GetDecodeCases()
        {
            yield return new object[] { null, EncodingName.Base16, "Input can not be null or empty." };
            yield return new object[] { string.Empty, EncodingName.Base16, "Input can not be null or empty." };
            yield return new object[]
            {
                "a", (EncodingName)1000,
                $"Input has 1 character.{Environment.NewLine}Decoder threw an exception: The method or operation is not implemented."
            };

            // Base-16
            yield return new object[]
            {
                "a", EncodingName.Base16,
                $"Input has 1 character.{Environment.NewLine}Input length is invalid for Base-16 encoding (has to be divisible by 2)."
            };
            yield return new object[]
            {
                "0xa", EncodingName.Base16,
                $"Input has 3 characters.{Environment.NewLine}Input length is invalid for Base-16 encoding (has to be divisible by 2)."
            };
            yield return new object[]
            {
                "az", EncodingName.Base16,
                $"Input has 2 characters.{Environment.NewLine}Invalid character \"z\" found at index=1."
            };
            yield return new object[]
            {
                "abcd", EncodingName.Base16,
                $"Input has 4 characters.{Environment.NewLine}Decoded data has 2 bytes.{Environment.NewLine}Data in Base-16: 0xabcd"
            };

            // Base-43
            yield return new object[]
            {
                "AB%", EncodingName.Base43,
                $"Input has 3 characters.{Environment.NewLine}Invalid character \"%\" found at index=2."
            };
            yield return new object[]
            {
                "AB$", EncodingName.Base43,
                $"Input has 3 characters.{Environment.NewLine}Decoded data has 2 bytes.{Environment.NewLine}Data in Base-16: 0x4a37"
            };

            // Base-58
            yield return new object[]
            {
                "AB$", EncodingName.Base58,
                $"Input has 3 characters.{Environment.NewLine}Invalid character \"$\" found at index=2."
            };
            yield return new object[]
            {
                "5VB", EncodingName.Base58,
                $"Input has 3 characters.{Environment.NewLine}Decoded data has 2 bytes.{Environment.NewLine}Data in Base-16: 0x3af2"
            };

            // Base-58 with checksum
            yield return new object[]
            {
                "AB$", EncodingName.Base58Check,
                $"Input has 3 characters.{Environment.NewLine}Invalid character \"$\" found at index=2."
            };
            yield return new object[]
            {
                "35MVubpb1", EncodingName.Base58Check,
                $"Input has 9 characters.{Environment.NewLine}Input has an invalid checksum. Decoding without checksum validation." +
                $"{Environment.NewLine}Decoded data has 6 bytes.{Environment.NewLine}Data in Base-16: 0xf1b00dbf9860"
            };
            yield return new object[]
            {
                "35MVubpbT", EncodingName.Base58Check,
                $"Input has 9 characters.{Environment.NewLine}Decoded data has 2 bytes.{Environment.NewLine}Data in Base-16: 0xf1b0"
            };

            // Base-64
            yield return new object[]
            {
                "E^Q=", EncodingName.Base64,
                $"Input has 4 characters.{Environment.NewLine}Decoder threw an exception: The input is not a valid Base-64 string as it contains a non-base 64 character, more than two padding characters, or an illegal character among the padding characters."
            };
            yield return new object[]
            {
                "EjQ=", EncodingName.Base64,
                $"Input has 4 characters.{Environment.NewLine}Decoded data has 2 bytes.{Environment.NewLine}Data in Base-16: 0x1234"
            };
        }
        [Theory]
        [MemberData(nameof(GetDecodeCases))]
        public void DecodeTest(string text, EncodingName enc, string expectedMsg)
        {
            var vm = new MissingEncodingViewModel()
            {
                Text = text
            };

            vm.Decode(enc);

            Assert.Equal(expectedMsg, vm.Result.Message);
        }
    }
}
