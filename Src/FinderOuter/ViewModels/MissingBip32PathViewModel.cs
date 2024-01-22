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
using System.Diagnostics;
using System.Linq;

namespace FinderOuter.ViewModels
{
    public class MissingBip32PathViewModel : OptionVmBase
    {
        public MissingBip32PathViewModel()
        {
            InputTypeList = ListHelper.GetEnumDescItems<Bip32PathService.SeedType>().ToArray();
            WordListsList = Enum.GetValues(typeof(BIP0039.WordLists)).Cast<BIP0039.WordLists>();
            CompareInputTypeList = ListHelper.GetEnumDescItems(CompareInputType.PrivateKey).ToArray();

            SelectedInputType = InputTypeList.First();
            SelectedCompareInputType = CompareInputTypeList.First();

            IObservable<bool> isFindEnabled = this.WhenAnyValue(
                x => x.XKey,
                x => x.CompareInput,
                x => x.Result.CurrentState,
                (s1, s2, state) => !string.IsNullOrEmpty(s1) && !string.IsNullOrEmpty(s2) && state != State.Working);
            FindCommand = ReactiveCommand.Create(Find, isFindEnabled);

            this.WhenAnyValue(x => x.SelectedInputType)
                .Subscribe(x => IsMnemonic =
                           x.Value == Bip32PathService.SeedType.BIP39 || x.Value == Bip32PathService.SeedType.Electrum);

            PathService = new Bip32PathService(Result);

            IObservable<bool> isExampleVisible = this.WhenAnyValue(x => x.Result.CurrentState, (state) => state != State.Working);
            ExampleCommand = ReactiveCommand.Create(Example, isExampleVisible);

            SetExamples(GetExampleData());
        }



        public override string OptionName => "Missing BIP32 path";
        public override string Description => "This option is useful to find BIP32 path if you have you mnemonic (seed phrase), " +
            "or extended private or public key and at least a child key but don't know the path used to derive that key.";


        public Bip32PathService PathService { get; }

        public IEnumerable<DescriptiveItem<Bip32PathService.SeedType>> InputTypeList { get; }
        public IEnumerable<BIP0039.WordLists> WordListsList { get; }

        private DescriptiveItem<Bip32PathService.SeedType> _selInType;
        public DescriptiveItem<Bip32PathService.SeedType> SelectedInputType
        {
            get => _selInType;
            set => this.RaiseAndSetIfChanged(ref _selInType, value);
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

        private string _xk = string.Empty;
        public string XKey
        {
            get => _xk;
            set
            {
                if (value != _xk)
                {
                    this.RaiseAndSetIfChanged(ref _xk, value);
                    if (!string.IsNullOrEmpty(value))
                    {
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
        }

        private string _pass = string.Empty;
        public string PassPhrase
        {
            get => _pass;
            set => this.RaiseAndSetIfChanged(ref _pass, value);
        }

        private uint _count = 1;
        public uint Count
        {
            get => _count;
            set
            {
                if (value > 0)
                {
                    this.RaiseAndSetIfChanged(ref _count, value);
                }
            }
        }


        public override void Find()
        {
            PathService.FindPath(XKey, SelectedInputType.Value, SelectedWordListType, PassPhrase,
                                 CompareInput, SelectedCompareInputType.Value, Count);
        }

        public void Example()
        {
            object[] ex = GetNextExample();

            XKey = (string)ex[0];

            int temp1 = (int)ex[1];
            Debug.Assert(temp1 < InputTypeList.Count());
            SelectedInputType = InputTypeList.ElementAt(temp1);

            int temp2 = (int)ex[2];
            Debug.Assert(temp2 < WordListsList.Count());
            SelectedWordListType = WordListsList.ElementAt(temp2);

            PassPhrase = (string)ex[3];
            CompareInput = (string)ex[4];

            int temp3 = (int)ex[5];
            Debug.Assert(temp3 < CompareInputTypeList.Count());
            SelectedCompareInputType = CompareInputTypeList.ElementAt(temp3);

            Count = (uint)ex[6];

            Result.Message = $"Example {exampleIndex} of {totalExampleCount}. Source: {(string)ex[7]}";
        }

        private ExampleData GetExampleData()
        {
            return new ExampleData<string, int, int, string, string, int, uint, string>()
            {
                {
                    "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
                    0, // InputType
                    0, // WordList
                    "OptionalPass",
                    "3PVjFJ6JwwimmgiZ5s6Br7uErhu85BaAnm",
                    3, // ExtraInputType
                    10, // Count
                    $"BIP-39 test vectors.{Environment.NewLine}" +
                    $"This is the 5th address at m/49'/0'/0'/0/4"
                },
                {
                    "wild father tree among universe such mobile favorite target dynamic credit identify",
                    1, // InputType
                    0, // WordList
                    "",
                    "bc1q4794m2uuw9jmjszmplfj4wvvr5j272fpnx2cse",
                    0, // ExtraInputType
                    10, // Count
                    $"Electrum test vectors.{Environment.NewLine}" +
                    $"This is the 1th address at m/0'/0/0"
                },
                {
                    "xprv9s21ZrQH143K32pyy7vM3WySNfaFryw2BxypMX6jVQtaR7MDw4EHFR2XoZkB12SzodbmMHYg24nuvrUH32mSoYGJFp7aPoahhcRkNnHAf6r",
                    2, // InputType
                    0, // WordList
                    "",
                    "03d9a7513dbd4115d5630c530acf0ce4dffbcb5cf026cce241e3a93f09304bbb1b",
                    4, // ExtraInputType
                    10, // Count
                    $"random.{Environment.NewLine}" +
                    $"This is the 6th address at m/44'/0'/0'/0/5"
                },
            };
        }
    }
}
