// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend;
using FinderOuter.Models;
using FinderOuter.Services;
using FinderOuter.Services.SearchSpaces;
using ReactiveUI;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;

namespace FinderOuter.ViewModels
{
    public class MissingBip38PassViewModel : OptionVmBase
    {
        public MissingBip38PassViewModel()
        {
            Bip38Service = new(Result);
            CompareInputTypeList = ListHelper.GetEnumDescItems(new CompareInputType[] { CompareInputType.PrivateKey }).ToArray();
            SelectedCompareInputType = CompareInputTypeList.First();
            PassRecoveryModeList = ListHelper.GetEnumDescItems<PassRecoveryMode>().ToArray();
            SelectedPassRecoveryMode = PassRecoveryModeList.First();

            IObservable<bool> isFindEnabled = this.WhenAnyValue(
                x => x.Bip38,
                x => x.CompareString,
                x => x.Result.CurrentState,
                (mn, extra, state) =>
                            !string.IsNullOrEmpty(mn) &&
                            !string.IsNullOrEmpty(extra) &&
                            state != State.Working);

            FindCommand = ReactiveCommand.Create(Find, isFindEnabled);

            this.WhenAnyValue(x => x.SelectedPassRecoveryMode)
                .Subscribe(x => PassLenToolTip = $"Number of {(x.Value == PassRecoveryMode.Alphanumeric ? "character" : "word")}s in the passphrase");
            this.WhenAnyValue(x => x.SelectedPassRecoveryMode)
                .Subscribe(x => IsCharMode = x.Value == PassRecoveryMode.Alphanumeric);

            HasExample = true;
            IObservable<bool> isExampleVisible = this.WhenAnyValue(
                x => x.Result.CurrentState,
                (state) => state != State.Working && HasExample);
            ExampleCommand = ReactiveCommand.Create(Example, isExampleVisible);

            SetExamples(GetExampleData());

            IObservable<bool> canAdd = this.WhenAnyValue(x => x.IsProcessed, (b) => b == true);

            StartCommand = ReactiveCommand.Create(Start, isFindEnabled);
            AddCommand = ReactiveCommand.Create(Add, isFindEnabled);
            AddAllCommand = ReactiveCommand.Create(AddAll, canAdd);
            AddLowerCommand = ReactiveCommand.Create(AddLower, canAdd);
            AddUpperCommand = ReactiveCommand.Create(AddUpper, canAdd);
            AddNumberCommand = ReactiveCommand.Create(AddNumber, canAdd);
            AddSymbolCommand = ReactiveCommand.Create(AddSymbol, canAdd);
        }


        public override string OptionName => "Missing BIP38 pass";
        public override string Description => $"This option can recover BIP-38 encryption password.{Environment.NewLine}" +
            $"Note that since BIP-38 algorithm is designed to be very expensive, hence this option is very slow at recovering " +
            $"passwords. Don't expect more than 3 or 4 checks per second per thread (the more CPU/cores you have the faster " +
            $"it will be).";

        private string _passLenTip;
        public string PassLenToolTip
        {
            get => _passLenTip;
            set => this.RaiseAndSetIfChanged(ref _passLenTip, value);
        }

        private readonly PasswordSearchSpace searchSpace = new();

        public Bip38Service Bip38Service { get; }
        public IPasswordService PassService { get; set; } = new PasswordService();
        public IEnumerable<DescriptiveItem<PassRecoveryMode>> PassRecoveryModeList { get; }

        private DescriptiveItem<PassRecoveryMode> _recMode;
        public DescriptiveItem<PassRecoveryMode> SelectedPassRecoveryMode
        {
            get => _recMode;
            set => this.RaiseAndSetIfChanged(ref _recMode, value);
        }

        private bool _isCMode;
        public bool IsCharMode
        {
            get => _isCMode;
            set => this.RaiseAndSetIfChanged(ref _isCMode, value);
        }


        private string _bip38;
        public string Bip38
        {
            get => _bip38;
            set => this.RaiseAndSetIfChanged(ref _bip38, value);
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

        private string _comp;
        public string CompareString
        {
            get => _comp;
            set => this.RaiseAndSetIfChanged(ref _comp, value);
        }

        private string _fPath;
        public string FilePath
        {
            get => _fPath;
            set => this.RaiseAndSetIfChanged(ref _fPath, value);
        }


        public static string AllSymbols => $"Symbols ({ConstantsFO.AllSymbols})";


        private void Start()
        {
            isChanged = false;
            Index = 0;
            Max = 0;
            IsProcessed = searchSpace.Process(PassLength, out string error);

            if (IsProcessed)
            {
                allItems = new ObservableCollection<string>[searchSpace.MissCount];
                for (int i = 0; i < allItems.Length; i++)
                {
                    allItems[i] = new();
                }
                Max = allItems.Length;
                Index = Max == 0 ? 0 : 1;
            }
            else
            {
                Result.AddMessage(error);
            }
        }

        private void AddToList(IEnumerable<string> items)
        {
            foreach (string item in items)
            {
                if (!CurrentItems.Contains(item))
                {
                    CurrentItems.Add(item);
                }
            }
        }

        public IReactiveCommand AddAllCommand { get; }
        private void AddAll()
        {
            AddToList(searchSpace.AllWords);
        }

        public IReactiveCommand AddCommand { get; }
        private void Add()
        {
            if (!string.IsNullOrEmpty(ToAdd))
            {
                if (!CurrentItems.Contains(ToAdd))
                {
                    CurrentItems.Add(ToAdd);
                }
            }
        }

        public IReactiveCommand AddLowerCommand { get; }
        private void AddLower()
        {
            AddToList(ConstantsFO.LowerCase.ToCharArray().Cast<string>());
        }

        public IReactiveCommand AddUpperCommand { get; }
        private void AddUpper()
        {
            AddToList(ConstantsFO.UpperCase.ToCharArray().Cast<string>());
        }

        public IReactiveCommand AddNumberCommand { get; }
        private void AddNumber()
        {
            AddToList(ConstantsFO.Numbers.ToCharArray().Cast<string>());
        }

        public IReactiveCommand AddSymbolCommand { get; }
        private void AddSymbol()
        {
            AddToList(ConstantsFO.AllSymbols.ToCharArray().Cast<string>());
        }


        public override async void Find()
        {
            if (isChanged && IsProcessed)
            {
                MessageBoxResult res = await WinMan.ShowMessageBox(MessageBoxType.YesNo, ConstantsFO.ChangedMessage);
                if (res == MessageBoxResult.Yes)
                {
                    IsProcessed = false;
                }
                else
                {
                    ResetSearchSpace();
                    return;
                }
            }

            if (!IsProcessed)
            {
                Start();
                foreach (ObservableCollection<string> item in allItems)
                {
                    foreach (string word in searchSpace.AllWords)
                    {
                        item.Add(word);
                    }
                }
            }

            if (IsProcessed)
            {
                if (searchSpace.SetValues(allItems.Select(x => x.ToArray()).ToArray()))
                {
                    //Bip38Service.Find(Bip38, CompareString, SelectedCompareInputType.Value, PassLength, allValues);
                    ResetSearchSpace();
                }
                else
                {
                    Result.AddMessage("Something went wrong when instantiating SearchSpace.");
                }
            }
        }


        public void Example()
        {
            object[] ex = GetNextExample();

            Bip38 = (string)ex[0];

            int temp = (int)ex[1];
            Debug.Assert(temp < CompareInputTypeList.Count());
            SelectedCompareInputType = CompareInputTypeList.ElementAt(temp);

            CompareString = (string)ex[2];
            PassLength = (int)ex[3];

            temp = (int)ex[4];
            Debug.Assert(temp < PassRecoveryModeList.Count());
            SelectedPassRecoveryMode = PassRecoveryModeList.ElementAt(temp);

            //CustomChars = (string)ex[5];

            //PasswordType flag = (PasswordType)(ulong)ex[6];
            //IsUpperCase = flag.HasFlag(PasswordType.UpperCase);
            //IsLowerCase = flag.HasFlag(PasswordType.LowerCase);
            //IsNumber = flag.HasFlag(PasswordType.Numbers);
            //IsSymbol = flag.HasFlag(PasswordType.Symbols);

            Result.Message = $"Example {exampleIndex} of {totalExampleCount}. Source: {(string)ex[7]}";
        }

        private ExampleData GetExampleData()
        {
            return new ExampleData<string, int, string, int, int, string, ulong, string>()
            {
                {
                    "6PRSR1GPq9Y7a6cCDwR2EshQGHXF4tWqGKHy2uU3qwRpcw4zZA4zz7GT1W",
                    1, // InputType
                    "1PSuGX1gXt8iu7gftMVsLg66EVuA1fRDz2",
                    2, // Pass length
                    0, // Recovery mode
                    "",
                    2, // Pass type flag
                    $"Random.{Environment.NewLine}" +
                    $"This example is a BIP38 with a very simple password using only lower case letters (ab)." +
                    $"{Environment.NewLine}" +
                    $"Estimated time: <1 sec"
                },
                {
                    "6PRKDN49yuCFZ5gzPq4iGY7Av9FZ1YEXXpgsDXTsXEMjZoUVMLtzXBxw5Q",
                    1, // InputType
                    "13TQwKK5vsxziCKJucwhATRqi23ogkAh66",
                    4, // Pass length
                    1, // Recovery mode
                    "!jRrSs",
                    0, // Pass type flag
                    $"Random.{Environment.NewLine}" +
                    $"This example is a BIP38 with a longer password using lower and upper case letters and symbols (j!RS). " +
                    $"But we know the possible characters used in the password so the recovery is a lot faster." +
                    $"{Environment.NewLine}" +
                    $"Estimated time: ~20 sec"
                },
            };
        }
    }
}
