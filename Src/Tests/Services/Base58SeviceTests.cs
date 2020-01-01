// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Models;
using FinderOuter.Services;
using Xunit;

namespace Tests.Services
{
    public class Base58SeviceTests
    {
        [Theory]
        [InlineData(' ', false)]
        [InlineData('a', false)]
        [InlineData('1', false)]
        [InlineData('(', false)] // There is a limited set of accepted symbols defined by Contants
        [InlineData('-', true)]
        public void IsMissingCharValidTest(char c, bool expected)
        {
            Base58Sevice serv = new Base58Sevice(new Report());
            bool actual = serv.IsMissingCharValid(c);
            Assert.Equal(expected, actual);
        }


        [Theory]
        [InlineData(null, false)]
        [InlineData("", false)]
        [InlineData(" ", false)]
        [InlineData("O", false)]
        [InlineData("12O3", false)]
        [InlineData("123$", false)]
        [InlineData("1*I3", false)]
        [InlineData("123", true)]
        [InlineData("12*3", true)]
        public void IsInputValidValidTest(string key, bool expected)
        {
            Base58Sevice serv = new Base58Sevice(new Report());
            bool actual = serv.IsInputValid(key, '*');
            Assert.Equal(expected, actual);
        }

    }
}
