// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Models;
using System;
using Xunit;

namespace Tests.Models
{
    public class SettingsTests
    {
        [Fact]
        public void ConstructorTest()
        {
            Settings settings = new();

            Assert.Equal(Environment.ProcessorCount, settings.MaxCoreCount);
            Assert.Equal(1, settings.CoreCount);

            if (Environment.ProcessorCount == 1)
            {
                Assert.True(settings.IsMax);
            }
            else
            {
                Assert.False(settings.IsMax);
                settings.CoreCount = 1000;
                Assert.True(settings.IsMax);
            }
        }

        [Fact]
        public void PropertyChangedTest()
        {
            Settings settings = new();
            Assert.PropertyChanged(settings, nameof(settings.CoreCount), () => settings.CoreCount = 2);
        }

        [Fact]
        public void CoreCountChangeTest()
        {
            Settings settings = new();

            settings.CoreCount = 2;
            Assert.Equal(2, settings.CoreCount);

            settings.CoreCount = 0;
            Assert.Equal(1, settings.CoreCount);

            settings.CoreCount = -1;
            Assert.Equal(1, settings.CoreCount);

            settings.CoreCount = 10000;
            Assert.Equal(10000, settings.CoreCount);
        }
    }
}
