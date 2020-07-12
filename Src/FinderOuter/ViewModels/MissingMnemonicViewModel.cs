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

            ExampleCommand = ReactiveCommand.Create(Example);
            HasExample = true;
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
            int total = 1;

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
                                     $"It is missing one word (grace) and it should take ~1 second to find it.";
                    break;
                default:
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
