// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend;
using FinderOuter.Models;
using FinderOuter.Services;
using System;
using System.Text;

namespace Tests.Services
{
    public class PasswordServiceTests
    {
        [Theory]
        [InlineData(PasswordType.None, false, null, "At least one password character type has to be selected.")]
        [InlineData((PasswordType)262144, false, null, "Password character type is not defined (this is a bug).")]
        [InlineData(PasswordType.LowerCase, true, ConstantsFO.LowerCase, null)]
        [InlineData(PasswordType.LowerCase | PasswordType.Numbers, true, ConstantsFO.LowerCase + ConstantsFO.Numbers, null)]
        public void TryGetAllValues_Enum(PasswordType type, bool expSuccess, string vals, string expError)
        {
            byte[] expValues = vals is null ? Array.Empty<byte>() : Encoding.UTF8.GetBytes(vals);

            PasswordService service = new();
            bool success = service.TryGetAllValues(type, out byte[] actualValues, out string actualError);

            Assert.Equal(expSuccess, success);
            Assert.Equal(expValues, actualValues);
            Assert.Equal(expError, actualError);
        }


        [Theory]
        [InlineData(null, false, "Please enter at least 1 possible character.")]
        [InlineData("", false, "Please enter at least 1 possible character.")]
        [InlineData("aa", false, "Remove the duplicate character(s) from possible password characters.")]
        [InlineData("1mfj1kf", false, "Remove the duplicate character(s) from possible password characters.")]
        [InlineData("abc", true, null)]
        [InlineData("a1%5f", true, null)]
        public void TryGetAllValues_Custom(string custom, bool expSuccess, string expError)
        {
            byte[] expValues = expSuccess ? Encoding.UTF8.GetBytes(custom) : null;

            PasswordService service = new();
            bool success = service.TryGetAllValues(custom, out byte[] actualValues, out string actualError);

            Assert.Equal(expSuccess, success);
            Assert.Equal(expValues, actualValues);
            Assert.Equal(expError, actualError);
        }
    }
}
