// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Models;
using ReactiveUI;
using System;
using System.Linq;

namespace FinderOuter.ViewModels
{
    public class KnowledgeBaseViewModel : VmWithSizeBase
    {
        public KnowledgeBaseViewModel()
        {
            Width = 850;
            Height = 500;

            KBList = ListHelper.GetEnumDescKB().ToArray();
        }

        public KnowledgeBaseViewModel(KB kb) : this()
        {
            int i = Array.FindIndex(KBList, x => x.Value == kb);
            if (i >= 0 && i < KBList.Length)
            {
                // Note that using FirstOrDefault only sets SelectedKB and doesn't affect ListBox
                SelectedKB = KBList.ElementAt(i);
            }
        }



        public DescriptiveKB[] KBList { get; }

        private DescriptiveKB _selKb;
        public DescriptiveKB SelectedKB
        {
            get => _selKb;
            set
            {
                if (_selKb != value)
                {
                    this.RaiseAndSetIfChanged(ref _selKb, value);
                    if (value is not null)
                    {
                        Title = value.Description;
                        Description = BuildDescription(value.Value);
                    }
                    else
                    {
                        Title = Description = string.Empty;
                    }
                }
            }
        }

        private string _title;
        public string Title
        {
            get => _title;
            set => this.RaiseAndSetIfChanged(ref _title, value);
        }

        private string _desc;
        public string Description
        {
            get => _desc;
            set => this.RaiseAndSetIfChanged(ref _desc, value);
        }



        private static string BuildDescription(KB kb)
        {
            // Information here are mostly taken from https://en.bitcoin.it/wiki/
            return kb switch
            {
                KB.Bitcoin =>
                "Bitcoin is an innovative currency created in 2008 by Satoshi Nakamoto. This decentralized digital currency " +
                "relies on its peer-to-peer network without the need for intermediaries. Transactions are verified by peers " +
                "in this network running a software known as full node and are recorded in a public distributed ledger called " +
                $"the blockchain.{Environment.NewLine}" +
                "You can find out more about bitcoin at https://bitcoin.org/",

                KB.PrivateKey =>
                "A private key is a secret piece of data that allows bitcoins to be spent. It is a number that is selected " +
                "from an enormous range. This range is defined by the elliptic curve that bitcoin uses. " +
                "Since bitcoin's curve (secp256k1) size is 256 bit, the bitcoin private keys are 256 bits and when decoded " +
                $"they are always 32 bytes long.{Environment.NewLine}" +
                "Private keys are usually encoded using Base-58 encoding with a checksum. The result is also known as " +
                $"Wallet Import Format or WIF for short.{Environment.NewLine}" +
                $"Private keys can also be encoded using Base-16 (hexadecimal) or Base-64.{Environment.NewLine}" +
                $"Here is an example private key:{Environment.NewLine}" +
                $"Base-58: L53fCHmQhbNp1B4JipfBtfeHZH7cAibzG9oK19XfiFzxHgAkz6JK{Environment.NewLine}" +
                $"Base-16: E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262{Environment.NewLine}" +
                $"Base-64: 6Yc9ecbYfcD7ald4YzOJ9EUyEzA9ph8gvWf8IzqjMmI=",

                KB.Bip32Path =>
                "Derivation path or address path defines where in the hierarchical tree is the address located so it can be " +
                "computed from the seed. They consist of numbers that are separated with a slash (/) and start with the letter " +
                "\"m\". Each number can have a modifier indicating whether the hardened value is used. It can be apostrophe (') " +
                $"or the letter \"h\". For example m/44'/0'/0'/0/0{Environment.NewLine}" +
                $"Keep in mind that each number is an index that starts from 0, meaning the first address is /0 and second " +
                $"one is at /1 and third one is at /2 and so on.",

                KB.DamagedInput =>
                $"There are 2 types of damged key recovery{Environment.NewLine}" +
                $"1) Missing parts at known positions:{Environment.NewLine}" +
                $"All options support this type, the position of all missing parts must be known so the length of the input " +
                $"is checked and invalid lengths are rejected. In this case simply enter any available parts and replace each " +
                $"missing part with a special missing character (can be changed). Example:{Environment.NewLine}" +
                $"Mnemonic: ozone drill grab fiber curtain * pudding thank cruise * eight picnic{Environment.NewLine}" +
                $"Mini private key: SzavMBLoXU6kDr*tUV*ffv{Environment.NewLine}{Environment.NewLine}" +
                $"2) Missing parts at unknown posistions:{Environment.NewLine}" +
                $"Only some options support this (read recovery option's description for details) and the number of missing " +
                $"parts allowed is limited. {Environment.NewLine}" +
                $"In this case since the position of the missing part is not known the length check is ignored but the input " +
                $"must not contain any special missing character at any position. Example:" +
                $"WIF missing 3 chars: L53fCHmQhbNp1B4JipfBtfeHZHcAibzG9oK9XfiFzxHAkz6JK",

                KB.ExtraInput =>
                "When recovering something such as a damaged key or mnemonic, the code has to substitute the missing parts " +
                "with all possible values and check the validity of each permutation. Usually there is a checksum that helps " +
                "eliminate invalid permutations enough to end up with only 1 or a very small number of results. But sometimes " +
                "due to small size of the checksum (eg. mnemonics) or lack of checksum (eg. Base-16 private key) the number " +
                "of possibly valid permutations is very large so they have to be checked against something else." +
                $"{Environment.NewLine}" +
                "The extra input for comparison can be the corresponding public key, the derived address, etc.",

                KB.ExtraInputTypes =>
                "The supported extra input types (for comparison) are: Addresses (P2PKH, P2SH, P2WPKH), public keys and private " +
                $"keys. With private key being the fastest and address the slowest.{Environment.NewLine}" +
                "During recovery the goal is to reduce the steps that must be taken as much as possible. For example using a " +
                "child private key when recovering a mnemonic would eliminate many additional expensive operations and can " +
                $"considerably improve the speed.{Environment.NewLine}" +
                $"The additional steps are generally like this:{Environment.NewLine}" +
                $"* Private key: no additional step (eg. mnemonic -> child private key -> compare){Environment.NewLine}" +
                $"* Public key: an expensive EC point multiplication (eg. mnemonic -> child private key -> (additional step) " +
                $"-> compare){Environment.NewLine}" +
                $"* Address: an expensive EC point multiplication + SHA256 hash + RIPEMD160 hash{Environment.NewLine}" +
                $"* Wrapped SegWit address: an expensive EC point multiplication + SHA256 hash + RIPEMD160 hash + SHA256 hash " +
                $"+ RIPEMD160 hash",

                KB.AlphanumericPass =>
                "This password recovery mode is used when the user only knows the type of characters used in the password. " +
                "The following are some examples with character types used in each case: " +
                $"{Environment.NewLine}" +
                $"vfdrG    upper case and lower case letters{Environment.NewLine}" +
                $"J9pS9    upper case and lower case letters and numbers{Environment.NewLine}" +
                $"64287    numbers{Environment.NewLine}" +
                $"Q c_5    upper case and lower case letters and numbers and symbols and space{Environment.NewLine}",

                KB.CustomCharPass =>
                "This password recovery mode is used when the user wants to limit the number of possible characters used " +
                "in the password to a smaller number compared to the default all possible chars. The following are some " +
                "examples, the left side is the actual password and the right side is the set of characters defined by user " +
                $"for search:{Environment.NewLine}" +
                $"b+akg+    abcdefghijkl+-={Environment.NewLine}" +
                $"CE2022    CEce012{Environment.NewLine}",

                KB.ThreadCount =>
                $"Settings can be used to define the number of threads that FinderOuter is going to use for parallelism." +
                $"{Environment.NewLine}" +
                $"This is useful for setting a lower number of threads to keep some CPU power open for other works. But this will " +
                $"obviously slow down the recovery process.{Environment.NewLine}" +
                $"By default the maximum value is chosen that is based on number of logical processors; if it is not the correct " +
                $"value the override button can be used to increase it. Keep in mind that increasing it to a value bigger than the " +
                $"maximum number of available threads could negatively affect speed.{Environment.NewLine}" +
                $"This value can not be changed after the recovery process starts.",

                _ => string.Empty,
            };
        }
    }
}
