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
        // Makes designer happy!
        public MissingMnemonicPassViewModel() : this(new Settings())
        {
        }

        public MissingMnemonicPassViewModel(Settings settings)
        {
            Result.Settings = settings;
            WordListsList = ListHelper.GetAllEnumValues<BIP0039.WordLists>().ToArray();
            MnemonicTypesList = ListHelper.GetAllEnumValues<MnemonicTypes>().ToArray();
            CompareInputTypeList = ListHelper.GetEnumDescItems<CompareInputType>().ToArray();
            SelectedCompareInputType = CompareInputTypeList.First();
            MnService = new MnemonicExtensionService(Result);
            PassRecoveryModeList = ListHelper.GetEnumDescItems<PassRecoveryMode>().ToArray();
            SelectedPassRecoveryMode = PassRecoveryModeList.First();

            IObservable<bool> isFindEnabled = this.WhenAnyValue(
                x => x.Input,
                x => x.CompareInput,
                x => x.KeyPath,
                x => x.Result.CurrentState,
                (mn, extra, path, state) =>
                            !string.IsNullOrEmpty(mn) &&
                            !string.IsNullOrEmpty(extra) &&
                            !string.IsNullOrEmpty(path) &&
                            state != State.Working);

            FindCommand = ReactiveCommand.Create(Find, isFindEnabled);

            this.WhenAnyValue(x => x.SelectedPassRecoveryMode.Value)
                .Subscribe(x => IsCheckBoxVisible = x == PassRecoveryMode.Alphanumeric);

            IObservable<bool> isExampleVisible = this.WhenAnyValue(x => x.Result.CurrentState, (state) => state != State.Working);
            ExampleCommand = ReactiveCommand.Create(Example, isExampleVisible);

            SetExamples(GetExampleData());
        }



        public override string OptionName => "Missing Mnemonic Pass";
        public override string Description => "This option can recover missing mnemonic passphrases also known as extra " +
            "or extension words. Enter the mnemonic, a child key or address for comparisson and the full path of that key. " +
            "The path is the full BIP-32 defined path of the child key including the key's index (eg. m/44'/0'/0'/0)." +
            $"{Environment.NewLine}" +
            $"Choose a recovery mode and enter the required information. Finally click Find button.";


        public MnemonicExtensionService MnService { get; }
        public IPasswordService PassService { get; set; } = new PasswordService();
        public IEnumerable<BIP0039.WordLists> WordListsList { get; }
        public IEnumerable<MnemonicTypes> MnemonicTypesList { get; }
        public IEnumerable<DescriptiveItem<PassRecoveryMode>> PassRecoveryModeList { get; }

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

        private DescriptiveItem<PassRecoveryMode> _recMode;
        public DescriptiveItem<PassRecoveryMode> SelectedPassRecoveryMode
        {
            get => _recMode;
            set => this.RaiseAndSetIfChanged(ref _recMode, value);
        }

        private bool _isChkVisible;
        public bool IsCheckBoxVisible
        {
            get => _isChkVisible;
            set => this.RaiseAndSetIfChanged(ref _isChkVisible, value);
        }

        private int _passLen = 1;
        public int PassLength
        {
            get => _passLen;
            set
            {
                if (value < 1)
                    value = 1;

                this.RaiseAndSetIfChanged(ref _passLen, value);
            }
        }

        private string _customChars;
        public string CustomChars
        {
            get => _customChars;
            set => this.RaiseAndSetIfChanged(ref _customChars, value);
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

        private bool _useSpace;
        public bool UseSpace
        {
            get => _useSpace;
            set => this.RaiseAndSetIfChanged(ref _useSpace, value);
        }

        public static string AllSymbols => $"Symbols ({ConstantsFO.AllSymbols})";


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
                if (UseSpace)
                {
                    result |= PasswordType.Space;
                }

                return result;
            }
        }



        public override void Find()
        {
            byte[] allValues = null;
            string error = null;
            bool success = SelectedPassRecoveryMode.Value switch
            {
                PassRecoveryMode.Alphanumeric => PassService.TryGetAllValues(PassType, out allValues, out error),
                PassRecoveryMode.CustomChars => PassService.TryGetAllValues(CustomChars, out allValues, out error),
                _ => false,
            };

            if (success)
            {
                MnService.Find(Input, SelectedMnemonicType, SelectedWordListType,
                               CompareInput, SelectedCompareInputType.Value, KeyPath, PassLength, allValues);
            }
            else
            {
                Result.Init();
                Result.Fail(error);
            }
        }


        public void Example()
        {
            object[] ex = GetNextExample();

            Input = (string)ex[0];

            int temp1 = (int)ex[1];
            Debug.Assert(temp1 < MnemonicTypesList.Count());
            SelectedMnemonicType = MnemonicTypesList.ElementAt(temp1);

            int temp2 = (int)ex[2];
            Debug.Assert(temp2 < WordListsList.Count());
            SelectedWordListType = WordListsList.ElementAt(temp2);

            int temp3 = (int)ex[3];
            Debug.Assert(temp3 < CompareInputTypeList.Count());
            SelectedCompareInputType = CompareInputTypeList.ElementAt(temp3);

            CompareInput = (string)ex[4];
            KeyPath = (string)ex[5];

            int temp4 = (int)ex[6];
            Debug.Assert(temp4 < PassRecoveryModeList.Count());
            SelectedPassRecoveryMode = PassRecoveryModeList.ElementAt(temp4);

            PassLength = (int)ex[7];
            PasswordType flag = (PasswordType)(ulong)ex[8];
            IsUpperCase = flag.HasFlag(PasswordType.UpperCase);
            IsLowerCase = flag.HasFlag(PasswordType.LowerCase);
            IsNumber = flag.HasFlag(PasswordType.Numbers);
            IsSymbol = flag.HasFlag(PasswordType.Symbols);

            CustomChars = (string)ex[9];

            Result.Message = $"Example {exampleIndex} of {totalExampleCount}. Source: {(string)ex[10]}";
        }

        private ExampleData GetExampleData()
        {
            return new ExampleData<string, int, int, int, string, string, int, int, ulong, string, string>()
            {
                {
                    "uphold cotton arch always museum hidden tent grape spot winter impose height curtain awake retire",//0
                    0, // 1. MnemonicType
                    0, // 2. WordList,
                    0, // 3. InputType
                    "1K2gAgfcs3oBb2hpa6XodakQJm1my9KuZg", // 4
                    "m/0'/0", // 5 
                    0, // 6. Recovery mode
                    3, // 7. Pass length
                    2, // 8. Pass type flag
                    "", // 9.
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
                    0, // Recovery mode
                    3, // Pass length
                    12, // Pass type flag
                    "",
                    $"Random.{Environment.NewLine}" +
                    $"This example is a BIP39 mnemonic with a simple passphrase using numbers and symbols (3+[)." +
                    $"{Environment.NewLine}" +
                    $"Estimated time: <20 sec"
                },
                {
                    "armed dolphin saddle virus day journey high ladder glide age prosper harbor daughter aisle debris",
                    0, // MnemonicType
                    0, // WordList,
                    4, // InputType
                    "02b1839ba74861e906c080a9a7256bf64b944b6869ce6252c4f9c33ed677ef95b7",
                    "m/84'/0'/0'/0/0",
                    1, // Recovery mode
                    4, // Pass length
                    0, // Pass type flag
                    "ABCabc+-=uUyY",
                    $"Random.{Environment.NewLine}" +
                    $"This example is a BIP39 mnemonic with a longer and more complicated passphrase using upper/lowe-case " +
                    $"characters, numbers and symbols (y+uB). But since the possible characters are defined and limited, " +
                    $"it can be recovered a lot faster." +
                    $"{Environment.NewLine}" +
                    $"Estimated time: <30 sec"
                },
            };
        }
    }
}
