// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

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
            WordListsList = Enum.GetValues(typeof(WordLists)).Cast<WordLists>();
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

        public IEnumerable<WordLists> WordListsList { get; }
        public IEnumerable<MnemonicTypes> MnemonicTypesList { get; }

        private MnemonicTypes _selMnT;
        public MnemonicTypes SelectedMnemonicType
        {
            get => _selMnT;
            set => this.RaiseAndSetIfChanged(ref _selMnT, value);
        }

        private WordLists _selWordLst;
        public WordLists SelectedWordListType
        {
            get => _selWordLst;
            set => this.RaiseAndSetIfChanged(ref _selWordLst, value);
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


        public override void Find()
        {
            _ = MnService.FindMissing(Mnemonic, MissingChar, SelectedMnemonicType, SelectedWordListType);
        }
    }
}
