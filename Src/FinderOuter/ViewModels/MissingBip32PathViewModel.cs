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
    public class MissingBip32PathViewModel : OptionVmBase
    {
        public MissingBip32PathViewModel()
        {
            WordListsList = Enum.GetValues(typeof(BIP0039.WordLists)).Cast<BIP0039.WordLists>();

            IObservable<bool> isFindEnabled = this.WhenAnyValue(
                x => x.Mnemonic,
                x => x.AdditionalInfo,
                x => x.Result.CurrentState,
                (mn, input, state) => !string.IsNullOrEmpty(mn) && !string.IsNullOrEmpty(input) && state != State.Working);
            FindCommand = ReactiveCommand.Create(Find, isFindEnabled);

            MnemonicTypesList = Enum.GetValues(typeof(MnemonicTypes)).Cast<MnemonicTypes>();

            MnService = new MnemonicSevice(Result);
        }



        public override string OptionName => "Find BIP32 path";
        public override string Description => "This part helps you find your BIP32 path if you have you mnemonic (seed phrase)" +
            "but don't know the path.";


        public MnemonicSevice MnService { get; }

        public IEnumerable<BIP0039.WordLists> WordListsList { get; }
        public IEnumerable<MnemonicTypes> MnemonicTypesList { get; }


        private MnemonicTypes _selMnemonic;
        public MnemonicTypes SelectedMnemonicType
        {
            get => _selMnemonic;
            set => this.RaiseAndSetIfChanged(ref _selMnemonic, value);
        }

        private BIP0039.WordLists _selWordLst;
        public BIP0039.WordLists SelectedWordListType
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
            _ = MnService.FindPath(Mnemonic, AdditionalInfo, SelectedMnemonicType, SelectedWordListType, PassPhrase);
        }
    }
}
