// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.ImprovementProposals;
using FinderOuter.Models;
using FinderOuter.Services;
using ReactiveUI;
using System;
using System.Collections.Generic;
using System.Linq;

namespace FinderOuter.ViewModels
{
    public class MissingMnemonicViewModel : OptionVmBase
    {
        public MissingMnemonicViewModel()
        {
            WordListsList = ListHelper.GetAllEnumValues<BIP0039.WordLists>().ToArray();
            MnemonicTypesList = ListHelper.GetAllEnumValues<MnemonicTypes>().ToArray();
            InputTypeList = ListHelper.GetEnumDescItems<InputType>().ToArray();
            SelectedInputType = InputTypeList.First();
            MnService = new MnemonicSevice(Result);

            IObservable<bool> isFindEnabled = this.WhenAnyValue(
                x => x.Mnemonic,
                x => x.AdditionalInfo,
                x => x.KeyPath,
                x => x.Result.CurrentState,
                (mn, extra, path, state) =>
                            !string.IsNullOrEmpty(mn) &&
                            !string.IsNullOrEmpty(extra) &&
                            !string.IsNullOrEmpty(path) &&
                            state != State.Working);

            FindCommand = ReactiveCommand.Create(Find, isFindEnabled);

            HasExample = true;
            IObservable<bool> isExampleVisible = this.WhenAnyValue(
                x => x.Result.CurrentState, 
                (state) => state != State.Working && HasExample);
            ExampleCommand = ReactiveCommand.Create(Example, isExampleVisible);
        }



        public override string OptionName => "Missing Mnemonic";
        public override string Description => $"This option is useful for recovering mnemonics (seed phrases) that are missing " +
            $"some words. Enter words that are known and replace the missing ones with the symbol defined by " +
            $"{nameof(MissingChar)} parameter.{Environment.NewLine}" +
            $"The passphrase box is for the optional passphrase used by BIP-39. Leave empty if it wasn't used.{Environment.NewLine}" +
            $"The additional info box is for entering either an address, a public or private key from the child keys derived " +
            $"from this mnemonic.{Environment.NewLine}" +
            $"The key index is the zero-based index of the entered key/address (first address is 0, second is 1,...)" +
            $"{Environment.NewLine}" +
            $"The path is the BIP-32 defined path of the child extended key (eg. m/44'/0'/0')";

        public MnemonicSevice MnService { get; }

        public IEnumerable<BIP0039.WordLists> WordListsList { get; }

        private BIP0039.WordLists _selWordLst;
        public BIP0039.WordLists SelectedWordListType
        {
            get => _selWordLst;
            set => this.RaiseAndSetIfChanged(ref _selWordLst, value);
        }

        public IEnumerable<MnemonicTypes> MnemonicTypesList { get; }

        private MnemonicTypes _selMnT;
        public MnemonicTypes SelectedMnemonicType
        {
            get => _selMnT;
            set => this.RaiseAndSetIfChanged(ref _selMnT, value);
        }

        public IEnumerable<DescriptiveItem<InputType>> InputTypeList { get; }

        private DescriptiveItem<InputType> _inT;
        public DescriptiveItem<InputType> SelectedInputType
        {
            get => _inT;
            set => this.RaiseAndSetIfChanged(ref _inT, value);
        }

        private string _mnemonic;
        public string Mnemonic
        {
            get => _mnemonic;
            set => this.RaiseAndSetIfChanged(ref _mnemonic, value);
        }

        private char _mis = '*';
        public char MissingChar
        {
            get => _mis;
            set => this.RaiseAndSetIfChanged(ref _mis, value);
        }

        private string _additional;
        public string AdditionalInfo
        {
            get => _additional;
            set => this.RaiseAndSetIfChanged(ref _additional, value);
        }

        private string _pass;
        public string PassPhrase
        {
            get => _pass;
            set => this.RaiseAndSetIfChanged(ref _pass, value);
        }

        private string _path;
        public string KeyPath
        {
            get => _path;
            set => this.RaiseAndSetIfChanged(ref _path, value);
        }

        private uint _ki = 0;
        public uint KeyIndex
        {
            get => _ki;
            set => this.RaiseAndSetIfChanged(ref _ki, value);
        }


        public override void Find()
        {
            _ = MnService.FindMissing(Mnemonic, MissingChar, PassPhrase, AdditionalInfo, SelectedInputType.Value, KeyPath, KeyIndex,
                                      SelectedMnemonicType, SelectedWordListType);
        }

        private int exampleIndex;
        public void Example()
        {
            int total = 4;

            switch (exampleIndex)
            {
                case 0:
                    Mnemonic = "ozone drill grab fiber curtain * pudding thank cruise elder eight picnic";
                    SelectedWordListType = BIP0039.WordLists.English;
                    SelectedMnemonicType = MnemonicTypes.BIP39;
                    PassPhrase = "AnExamplePassPhrase";
                    MissingChar = '*';
                    AdditionalInfo = "1FCptKjDovTGKYz2vLGVtswGqwgp6JmfyN";
                    SelectedInputType = InputTypeList.First();
                    KeyPath = "m/44'/0'/0'/0/";
                    KeyIndex = 0;

                    Result.Message = $"This is example 1 out of {total} taken from BIP-39 test vectors.{Environment.NewLine}" +
                                     $"It is missing one word (grace) and it should take ~1 second to find it." +
                                     $"{Environment.NewLine}It creates the following addresses:{Environment.NewLine}" +
                                     $"{Environment.NewLine}" +
                                     $"{Environment.NewLine}" +
                                     $"{Environment.NewLine}" +
                                     $"{Environment.NewLine}";
                    break;
                case 1:
                    Mnemonic = "ozone - grab fiber curtain grace pudding thank - elder eight picnic";
                    SelectedWordListType = BIP0039.WordLists.English;
                    SelectedMnemonicType = MnemonicTypes.BIP39;
                    PassPhrase = "$4f9Asf*vX#4bX@7";
                    MissingChar = '-';
                    AdditionalInfo = "bc1ql5swedpywx3kjq4grv9qmlngapdf6xumv7f2ew";
                    SelectedInputType = InputTypeList.First();
                    KeyPath = "m/84'/0'/0'/0";
                    KeyIndex = 4;

                    Result.Message = $"This is example 2 out of {total} taken from BIP-39 test vectors.{Environment.NewLine}" +
                                     $"It is missing two word (drill, cruise) and it should take ~1 hour to find them." +
                                     $"{Environment.NewLine}This example shows how to use a different missing char, " +
                                     $"input type, path, key index.{Environment.NewLine}" +
                                     $"It creates the following addresses:{Environment.NewLine}" +
                                     $"m/84'/0'/0'/0/0: bc1q4tkug9kdjdwqsytku6kjqmh8l5ack7r807y6xw{Environment.NewLine}" +
                                     $"m/84'/0'/0'/0/1: bc1q2jd2nm87up6v52tx5dmlph60z4exwlm0z2ljms{Environment.NewLine}" +
                                     $"m/84'/0'/0'/0/2: bc1q9wc94vnv795ldevgggevry0evgz2n50tz9g3y0{Environment.NewLine}" +
                                     $"m/84'/0'/0'/0/3: bc1qfwlp044ca3ynpk2pvq69dv9huyfq5qy5nn32j2{Environment.NewLine}" +
                                     $"m/84'/0'/0'/0/4: bc1ql5swedpywx3kjq4grv9qmlngapdf6xumv7f2ew{Environment.NewLine}";
                    break;
                case 2:
                    Mnemonic = "avide sardine séjour docteur tétine soluble nautique raisin toucher notoire linéaire lièvre tenir demeurer talonner civil * fabuleux pizza diminuer gagner oisillon trafic imposer";
                    SelectedWordListType = BIP0039.WordLists.French;
                    SelectedMnemonicType = MnemonicTypes.BIP39;
                    PassPhrase = "";
                    MissingChar = '*';
                    AdditionalInfo = "L3YAaUUnQHMJLT63AntZBZ2Yda7rYeW784mfaaC48SpQJyqA2gTs";
                    SelectedInputType = InputTypeList.ToArray()[5];
                    KeyPath = "m/0/";
                    KeyIndex = 2;

                    Result.Message = $"This is example 3 out of {total} with a random mnemonic.{Environment.NewLine}" +
                                     $"It is missing one word (lézard) and it should take ~1 second to find it." +
                                     $"{Environment.NewLine}This example shows how to use a different language and " +
                                     $"input type.{Environment.NewLine}" +
                                     $"It creates the following keys:{Environment.NewLine}" +
        $"m/0/0: 3L5EM1AiF95RBTuZkEMCEeE4eHoRRbc7Sd: L1ac6reGcRagt1oSRUwPJzY6mNMBHAzbB8sfz6LJ8fCBwxzXD6v2{Environment.NewLine}" +
        $"m/0/1: 3LvkAVV5Y4BQT7XFoMPXkxAQm4TFxQgdBP: L4S7X4KFCHakg12YZ2d2wft7oXVKfGomuWh4b9y3ombXz9aiZ29B{Environment.NewLine}" +
        $"m/0/2: 32tpfpxY5KG7Bdqf8m8cthoVcyALjvBk5z: L3YAaUUnQHMJLT63AntZBZ2Yda7rYeW784mfaaC48SpQJyqA2gTs{Environment.NewLine}";
                    break;
                case 3:
                    Mnemonic = "avide sardine séjour docteur tétine soluble nautique raisin toucher notoire linéaire lièvre tenir demeurer talonner civil * fabuleux pizza diminuer gagner oisillon trafic imposer";
                    SelectedWordListType = BIP0039.WordLists.French;
                    SelectedMnemonicType = MnemonicTypes.BIP39;
                    PassPhrase = "";
                    MissingChar = '*';
                    AdditionalInfo = "32tpfpxY5KG7Bdqf8m8cthoVcyALjvBk5z";
                    SelectedInputType = InputTypeList.ToArray()[3];
                    KeyPath = "m/0/";
                    KeyIndex = 2;

                    Result.Message = $"This is example 4 out of {total} with a random mnemonic.{Environment.NewLine}" +
                                     $"It is missing one word (lézard) and it should take ~1 second to find it." +
                                     $"{Environment.NewLine}This example shows how to use a different language and " +
                                     $"input type (nested SegWit address or P2SH-P2WPKH).{Environment.NewLine}" +
                                     $"It creates the following keys:{Environment.NewLine}" +
        $"m/0/0: 3L5EM1AiF95RBTuZkEMCEeE4eHoRRbc7Sd: L1ac6reGcRagt1oSRUwPJzY6mNMBHAzbB8sfz6LJ8fCBwxzXD6v2{Environment.NewLine}" +
        $"m/0/1: 3LvkAVV5Y4BQT7XFoMPXkxAQm4TFxQgdBP: L4S7X4KFCHakg12YZ2d2wft7oXVKfGomuWh4b9y3ombXz9aiZ29B{Environment.NewLine}" +
        $"m/0/2: 32tpfpxY5KG7Bdqf8m8cthoVcyALjvBk5z: L3YAaUUnQHMJLT63AntZBZ2Yda7rYeW784mfaaC48SpQJyqA2gTs{Environment.NewLine}";
                    break;

                default:
                    Result.Message = "Invalid example index was given (this is a bug).";
                    break;
            }

            exampleIndex++;
            if (exampleIndex >= total)
            {
                exampleIndex = 0;
            }
        }
    }
}
