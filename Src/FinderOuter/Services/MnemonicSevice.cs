// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend.Cryptography.Hashing;
using FinderOuter.Models;
using System;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;

namespace FinderOuter.Services
{
    public enum WordLists
    {
        English,
        ChineseSimplified,
        ChineseTraditional,
        French,
        Italian,
        Japanese,
        Korean,
        Spanish
    }
    public enum MnemonicTypes
    {
        BIP39,
        Electrum,
    }

    public class MnemonicSevice : ServiceBase
    {
        public MnemonicSevice(Report rep) : base(rep)
        {
        }



        private readonly Sha256 hash = new Sha256();
        private readonly int[] allowedWordLengths = { 12, 15, 18, 21, 24 };
        private uint[] wordIndexes;
        private string[] allWords;



        private bool TrySetWordList(WordLists wl)
        {
            string fPath = $"FinderOuter.Backend.ImprovementProposals.BIP0039WordLists.{wl.ToString()}.txt";
            Assembly asm = Assembly.GetExecutingAssembly();
            using (Stream stream = asm.GetManifestResourceStream(fPath))
            {
                if (stream != null)
                {
                    using StreamReader reader = new StreamReader(stream);
                    allWords = reader.ReadToEnd().Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
                }
                else
                {
                    return Fail($"Could not find {wl.ToString()} word list among resources."); ;
                }
            }

            return true;
        }


        private bool TrySetEntropy(string mnemonic, MnemonicTypes mnType)
        {
            if (string.IsNullOrWhiteSpace(mnemonic))
            {
                return Fail("Mnemonic can not be null or empty.");
            }

            return Fail("Not yet implemented.");
        }




        public async Task<bool> FindPath(string mnemonic, string extra, MnemonicTypes mnType, WordLists wl, string passPhrase)
        {
            InitReport();

            if (!TrySetEntropy(mnemonic, mnType) && !TrySetWordList(wl))
            {
                return false;
            }
            if (string.IsNullOrWhiteSpace(extra))
            {
                return Fail("Additioan info can not be null or empty.");
            }
            else
            {
                
            }

            return Fail("Not yet implemented");
        }

    }
}
