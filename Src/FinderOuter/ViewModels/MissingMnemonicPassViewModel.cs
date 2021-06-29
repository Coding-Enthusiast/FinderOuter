// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.ImprovementProposals;
using FinderOuter.Backend;
using FinderOuter.Models;
using FinderOuter.Services;
using ReactiveUI;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace FinderOuter.ViewModels
{
    public class MissingMnemonicPassViewModel : OptionVmBase
    {
        public MissingMnemonicPassViewModel()
        {
            WordListsList = ListHelper.GetAllEnumValues<BIP0039.WordLists>().ToArray();
            MnemonicTypesList = ListHelper.GetAllEnumValues<MnemonicTypes>().ToArray();
            InputTypeList = ListHelper.GetEnumDescItems<InputType>().ToArray();
            SelectedInputType = InputTypeList.First();
            MnService = new MnemonicExtensionService(Result);

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

            SetExamples(GetExampleData());
        }



        public override string OptionName => "Missing Mnemonic Pass";
        public override string Description => "This option can recover missing mnemonic passphrases also known as extra " +
            "or extension words. Enter the full mnemonic, a child key for comparisson and the full path of that key. " +
            "The path is the full BIP-32 defined path of the child key including the key's index (eg. m/44'/0'/0'/0)." +
            $"{Environment.NewLine}" +
            $"the only available case for now is when you don't know any characters of the passphrase. Enter its exact " +
            $"length and select the type of characters that were used in the passphrase. And finally click Find.";


        public MnemonicExtensionService MnService { get; }
        public IEnumerable<BIP0039.WordLists> WordListsList { get; }
        public IEnumerable<MnemonicTypes> MnemonicTypesList { get; }
        public IEnumerable<DescriptiveItem<InputType>> InputTypeList { get; }

        private MnemonicTypes _selMnT;
        public MnemonicTypes SelectedMnemonicType
        {
            get => _selMnT;
            set => this.RaiseAndSetIfChanged(ref _selMnT, value);
        }

        private BIP0039.WordLists _selWordLst;
        public BIP0039.WordLists SelectedWordListType
        {
            get => _selWordLst;
            set => this.RaiseAndSetIfChanged(ref _selWordLst, value);
        }

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

        private int _passLen;
        public int PassLength
        {
            get => _passLen;
            set
            {
                if (value < 1)
                {
                    value = 1;
                }

                this.RaiseAndSetIfChanged(ref _passLen, value);
            }
        }

        private string _additional;
        public string AdditionalInfo
        {
            get => _additional;
            set => this.RaiseAndSetIfChanged(ref _additional, value);
        }

        private string _path;
        public string KeyPath
        {
            get => _path;
            set => this.RaiseAndSetIfChanged(ref _path, value);
        }

        private bool _isUpper;
        public bool IsUpperCase
        {
            get => _isUpper;
            set => this.RaiseAndSetIfChanged(ref _isUpper, value);
        }

        private bool _isLower;
        public bool IsLowerCase
        {
            get => _isLower;
            set => this.RaiseAndSetIfChanged(ref _isLower, value);
        }

        private bool _isNum;
        public bool IsNumber
        {
            get => _isNum;
            set => this.RaiseAndSetIfChanged(ref _isNum, value);
        }

        private bool _isSymbol;
        public bool IsSymbol
        {
            get => _isSymbol;
            set => this.RaiseAndSetIfChanged(ref _isSymbol, value);
        }

        public string AllSymbols => $"Symbols ({ConstantsFO.AllSymbols})";


        public PasswordType PassType
        {
            get
            {
                PasswordType result = PasswordType.None;
                if (IsUpperCase)
                {
                    result |= PasswordType.UpperCase;
                }
                if (IsLowerCase)
                {
                    result |= PasswordType.LowerCase;
                }
                if (IsNumber)
                {
                    result |= PasswordType.Numbers;
                }
                if (IsSymbol)
                {
                    result |= PasswordType.Symbols;
                }

                return result;
            }
        }



        public override void Find()
        {
            MnService.Find(Mnemonic, SelectedMnemonicType, SelectedWordListType,
                           AdditionalInfo, SelectedInputType.Value, KeyPath, PassLength, PassType);
        }


        public void Example()
        {
            object[] ex = GetNextExample();

            Mnemonic = (string)ex[0];

            int temp1 = (int)ex[1];
            Debug.Assert(temp1 < MnemonicTypesList.Count());
            SelectedMnemonicType = MnemonicTypesList.ElementAt(temp1);

            int temp2 = (int)ex[2];
            Debug.Assert(temp2 < WordListsList.Count());
            SelectedWordListType = WordListsList.ElementAt(temp2);

            int temp3 = (int)ex[3];
            Debug.Assert(temp3 < InputTypeList.Count());
            SelectedInputType = InputTypeList.ElementAt(temp3);

            AdditionalInfo = (string)ex[4];
            KeyPath = (string)ex[5];
            PassLength = (int)ex[6];
            PasswordType flag = (PasswordType)(ulong)ex[7];

            IsUpperCase = flag.HasFlag(PasswordType.UpperCase);
            IsLowerCase = flag.HasFlag(PasswordType.LowerCase);
            IsNumber = flag.HasFlag(PasswordType.Numbers);
            IsSymbol = flag.HasFlag(PasswordType.Symbols);

            Result.Message = $"Example {exampleIndex} of {totalExampleCount}. Source: {(string)ex[8]}";
        }

        private ExampleData GetExampleData()
        {
            return new ExampleData<string, int, int, int, string, string, int, ulong, string>()
            {
                {
                    "uphold cotton arch always museum hidden tent grape spot winter impose height curtain awake retire",
                    0, // MnemonicType
                    0, // WordList,
                    0, // InputType
                    "1K2gAgfcs3oBb2hpa6XodakQJm1my9KuZg",
                    "m/0'/0",
                    3, // Pass length
                    2, // Pass type flag
                    $"Random.{Environment.NewLine}" +
                    $"This example is a BIP39 mnemonic with a simple passphrase using only lower case letters (kqe)." +
                    $"{Environment.NewLine}" +
                    $"Estimated time: <10 sec"
                },
                {
                    "uphold cotton arch always museum hidden tent grape spot winter impose height curtain awake retire",
                    0, // MnemonicType
                    0, // WordList,
                    0, // InputType
                    "19h1BJtUS7KxZaKd1dBejeZirG9bvwfSu7",
                    "m/0'/0",
                    3, // Pass length
                    12, // Pass type flag
                    $"Random.{Environment.NewLine}" +
                    $"This example is a BIP39 mnemonic with a simple passphrase using numbers and symbols (3+[)." +
                    $"{Environment.NewLine}" +
                    $"Estimated time: <10 sec"
                },
            };
        }
    }
}
