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
            InputTypeList = ListHelper.GetEnumDescItems<Bip32PathService.SeedType>().ToArray();
            WordListsList = Enum.GetValues(typeof(BIP0039.WordLists)).Cast<BIP0039.WordLists>();
            ExtraInputTypeList = ListHelper.GetEnumDescItems<InputType>().ToArray();

            SelectedInputType = InputTypeList.First();
            SelectedExtraInputType = ExtraInputTypeList.First();

            IObservable<bool> isFindEnabled = this.WhenAnyValue(
                x => x.Input,
                x => x.ExtraInput,
                x => x.Result.CurrentState,
                (input1, input2, state) => !string.IsNullOrEmpty(input1) && !string.IsNullOrEmpty(input2) && state != State.Working);
            FindCommand = ReactiveCommand.Create(Find, isFindEnabled);

            this.WhenAnyValue(x => x.SelectedInputType)
                .Subscribe(x => IsMnemonic =
                           x.Value == Bip32PathService.SeedType.BIP39 || x.Value == Bip32PathService.SeedType.Electrum);

            PathService = new Bip32PathService(Result);
        }



        public override string OptionName => "Find BIP32 path";
        public override string Description => "This part helps you find your BIP32 path if you have you mnemonic (seed phrase)" +
            "but don't know the path.";


        public Bip32PathService PathService { get; }

        public IEnumerable<DescriptiveItem<Bip32PathService.SeedType>> InputTypeList { get; }
        public IEnumerable<BIP0039.WordLists> WordListsList { get; }
        public IEnumerable<DescriptiveItem<InputType>> ExtraInputTypeList { get; }


        private DescriptiveItem<Bip32PathService.SeedType> _selInType;
        public DescriptiveItem<Bip32PathService.SeedType> SelectedInputType
        {
            get => _selInType;
            set => this.RaiseAndSetIfChanged(ref _selInType, value);
        }

        private DescriptiveItem<InputType> _selExtraInType;
        public DescriptiveItem<InputType> SelectedExtraInputType
        {
            get => _selExtraInType;
            set => this.RaiseAndSetIfChanged(ref _selExtraInType, value);
        }

        private BIP0039.WordLists _selWordLst;
        public BIP0039.WordLists SelectedWordListType
        {
            get => _selWordLst;
            set => this.RaiseAndSetIfChanged(ref _selWordLst, value);
        }

        private bool _isMn;
        public bool IsMnemonic
        {
            get => _isMn;
            set => this.RaiseAndSetIfChanged(ref _isMn, value);
        }

        private string _input;
        public string Input
        {
            get => _input;
            set
            {
                if (value != _input)
                {
                    this.RaiseAndSetIfChanged(ref _input, value);
                    // Guess type
                    value = value.Trim();
                    // TODO: next Bitcoin.Net version should fix the issue of not supporting ypub and zpub!
                    if (value.StartsWith("xprv"))
                    {
                        SelectedInputType = InputTypeList.ElementAt(2);
                    }
                    else if (value.StartsWith("xpub"))
                    {
                        SelectedInputType = InputTypeList.ElementAt(3);
                    }
                    else if (value.Contains(" ") &&
                             SelectedInputType.Value != Bip32PathService.SeedType.BIP39 &&
                             SelectedInputType.Value != Bip32PathService.SeedType.Electrum)
                    {
                        SelectedInputType = InputTypeList.ElementAt(0);
                    }
                }

            }
        }

        private string _additional;
        public string ExtraInput
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
            PathService.FindPath(Input, SelectedInputType.Value, SelectedWordListType, PassPhrase,
                                 ExtraInput, SelectedExtraInputType.Value);
        }
    }
}
