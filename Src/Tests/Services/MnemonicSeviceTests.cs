// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using Autarkysoft.Bitcoin.ImprovementProposals;
using FinderOuter.Services;
using System;
using System.Text;

namespace Tests.Services
{
    public class MnemonicSeviceTests
    {
        [Fact]
        public void SpaceByteCostTest()
        {
            byte[] expected = Encoding.UTF8.GetBytes(" ");
            Assert.Single(expected);
            Assert.Equal(MnemonicSevice.SpaceByte, expected[0]);
        }

        [Fact]
        public void TrySetWordListTest()
        {
            Array wls = Enum.GetValues(typeof(BIP0039.WordLists));
            byte[] space = Encoding.UTF8.GetBytes(" ");
            Assert.Single(space);

            foreach (BIP0039.WordLists item in wls)
            {
                bool b = MnemonicSevice.TrySetWordList(item, out string[] words, out int actualMaxWordLen);
                Assert.True(b);
                Assert.Equal(2048, words.Length);

                string bigSeed = string.Join(" ", words);
                int expectedMaxWordLen = 0;
                FastStream stream = new(37831);
                for (int i = 0; i < words.Length; i++)
                {
                    byte[] wordBa = Encoding.UTF8.GetBytes(words[i]);
                    stream.Write(wordBa);
                    if (expectedMaxWordLen < wordBa.Length)
                    {
                        expectedMaxWordLen = wordBa.Length;
                    }
                    if (i != 2047)
                    {
                        stream.Write(space);
                    }
                }

                byte[] actual = stream.ToByteArray();
                byte[] expected = Encoding.UTF8.GetBytes(bigSeed);

                Assert.Equal(expected, actual);
                Assert.Equal(expectedMaxWordLen, actualMaxWordLen);
            }
        }

        [Fact]
        public void GetSeedMaxByteSizeTest()
        {
            int actual = MnemonicSevice.GetSeedMaxByteSize(12, 3);
            Assert.Equal(47, actual);

            actual = MnemonicSevice.GetSeedMaxByteSize(12, 8);
            Assert.Equal(107, actual);

            actual = MnemonicSevice.GetSeedMaxByteSize(24, 33);
            Assert.Equal(815, actual);
        }
    }
}
