// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.ImprovementProposals;
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
            WordListsList = Enum.GetValues(typeof(BIP0039.WordLists)).Cast<BIP0039.WordLists>();
            MnemonicTypesList = new MnemonicTypes[] { MnemonicTypes.BIP39 };
            InputTypeList = Enum.GetValues(typeof(MnemonicSevice.InputType)).Cast<MnemonicSevice.InputType>();
            MnService = new MnemonicSevice(Result);

            IObservable<bool> isFindEnabled = this.WhenAnyValue(
                x => x.Mnemonic,
                x => x.Result.CurrentState, (mn, state) =>
                            !string.IsNullOrEmpty(mn) &&
                            state != Models.State.Working);

            FindCommand = ReactiveCommand.Create(Find, isFindEnabled);
        }



        public override string OptionName => "Missing Mnemonic";
        public override string Description => "Helps you recover mnemonic (seed phrases) that are missing some words.";

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

        public IEnumerable<MnemonicSevice.InputType> InputTypeList { get; }

        private MnemonicSevice.InputType _inT;
        public MnemonicSevice.InputType SelectedInputType
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
            _ = MnService.FindMissing(Mnemonic, MissingChar, PassPhrase, AdditionalInfo, SelectedInputType, KeyPath, KeyIndex,
                                      SelectedMnemonicType, SelectedWordListType);
        }
    }
}
