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
        // Makes designer happy!
        public MissingBip38PassViewModel() : this(new Settings())
        {
        }

        public MissingBip38PassViewModel(Settings settings)
        {
            Result.Settings = settings;
            Bip38Service = new(Result);
            CompareInputTypeList = ListHelper.GetEnumDescItems(new CompareInputType[] { CompareInputType.PrivateKey }).ToArray();
            SelectedCompareInputType = CompareInputTypeList.First();

            IObservable<bool> isFindEnabled = this.WhenAnyValue(
                x => x.Input,
                x => x.CompareInput,
                x => x.Result.CurrentState,
                (mn, extra, state) =>
                            !string.IsNullOrEmpty(mn) &&
                            !string.IsNullOrEmpty(extra) &&
                            state != State.Working);

            FindCommand = ReactiveCommand.Create(Find, isFindEnabled);

            IObservable<bool> isExampleEnable = this.WhenAnyValue(x => x.Result.CurrentState, (state) => state != State.Working);
            ExampleCommand = ReactiveCommand.Create(Example, isExampleEnable);

            SetExamples(GetExampleData());

            IObservable<bool> canAdd = this.WhenAnyValue(x => x.IsProcessed, (b) => b == true);

            StartCommand = ReactiveCommand.Create(Start, isFindEnabled);
            AddCommand = ReactiveCommand.Create(Add, canAdd);
            AddAllCommand = ReactiveCommand.Create(AddAll, canAdd);
            AddLowerCommand = ReactiveCommand.Create(AddLower, canAdd);
            AddUpperCommand = ReactiveCommand.Create(AddUpper, canAdd);
            AddNumberCommand = ReactiveCommand.Create(AddNumber, canAdd);
            AddSymbolCommand = ReactiveCommand.Create(AddSymbol, canAdd);

            CopyCommand = ReactiveCommand.Create(Copy, isFindEnabled);
        }


        public override string OptionName => "Missing BIP38 pass";
        public override string Description => $"This option can recover BIP-38 encryption password.{Environment.NewLine}" +
            $"Note that since BIP-38 algorithm is designed to be very expensive, hence this option is very slow at recovering " +
            $"passwords. Don't expect more than 3 or 4 checks per second per thread (the more CPU/cores you have the faster " +
            $"it will be).";

        public static string PassLenToolTip => "Number of words in the passphrase.";

        private readonly PasswordSearchSpace searchSpace = new();

        public Bip38Service Bip38Service { get; }
        public IFileManager FileMan { get; set; } = new FileManager();


        private int _passLen = 1;
        public int PassLength
        {
            get => _passLen;
            set
            {
                if (value < 1)
                    value = 1;

                if (value != _passLen)
                {
                    this.RaiseAndSetIfChanged(ref _passLen, value);
                    isChanged = true;
                }
            }
        }


        private string _ores;
        public string OpenResult
        {
            get => _ores;
            set => this.RaiseAndSetIfChanged(ref _ores, value);
        }

        public async void Open()
        {
            string[] res = await FileMan.OpenAsync();
            OpenResult = $"Number of items:{Environment.NewLine}{res.Length:n0}";
            searchSpace.AllWords = res;
            isChanged = true;
        }

        private void Start()
        {
            InitSearchSpace();
            IsProcessed = searchSpace.Process(Input, PassLength, out string error);
            FinishSearchSpace(searchSpace.PasswordLength, error);
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
            if (searchSpace.AllWords is not null && searchSpace.AllWords.Length != 0)
            {
                AddToList(searchSpace.AllWords);
            }
            else
            {
                Result.AddMessage("No password list is defined yet. Use the \"Open\" button to set it.");
            }
        }

        public IReactiveCommand AddCommand { get; }
        private void Add()
        {
            // TODO: should we add a warning about extra spaces here?
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
            AddToList(ConstantsFO.LowerCase.ToCharArray().Select(c => c.ToString()));
        }

        public IReactiveCommand AddUpperCommand { get; }
        private void AddUpper()
        {
            AddToList(ConstantsFO.UpperCase.ToCharArray().Select(c => c.ToString()));
        }

        public IReactiveCommand AddNumberCommand { get; }
        private void AddNumber()
        {
            AddToList(ConstantsFO.Numbers.ToCharArray().Select(c => c.ToString()));
        }

        public IReactiveCommand AddSymbolCommand { get; }
        private void AddSymbol()
        {
            AddToList(ConstantsFO.AllSymbols.ToCharArray().Select(c => c.ToString()));
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
                if (searchSpace.AllWords is null || searchSpace.AllWords.Length == 0)
                {
                    Result.AddMessage("No password list is defined yet. Use the \"Open\" button to set it.");
                    return;
                }
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
                if (searchSpace.SetValues(allItems.Select(x => x.ToArray()).ToArray(), out string error))
                {
                    Bip38Service.Find(searchSpace, CompareInput, SelectedCompareInputType.Value);
                    ResetSearchSpace();
                }
                else
                {
                    Result.AddMessage(error);
                }
            }
        }


        public void Example()
        {
            object[] ex = GetNextExample();

            Input = (string)ex[0];

            int temp = (int)ex[1];
            Debug.Assert(temp < CompareInputTypeList.Count());
            SelectedCompareInputType = CompareInputTypeList.ElementAt(temp);

            CompareInput = (string)ex[2];
            PassLength = (int)ex[3];

            Start();

            Debug.Assert(allItems.Length == PassLength);
            string[][] items = (string[][])ex[4];
            for (int i = 0; i < items.Length; i++)
            {
                foreach (var item in items[i])
                {
                    allItems[i].Add(item);
                }
            }

            Result.Message = $"Example {exampleIndex} of {totalExampleCount}. Source: {(string)ex[5]}";
        }

        private ExampleData GetExampleData()
        {
            return new ExampleData<string, int, string, int, string[][], string>()
            {
                {
                    "6PYXYyDuJtuDRYfnth2qqcEP9G9TdqvK8qJC2PAoyFTi7rvCdzcmeq4Y5a",
                    0, // CompareInputType
                    "1MNcUQ2XeU2cA9z9HdbqkDMrB1c1WPgKn4",
                    3, // Pass length
                    new string[3][]
                    {
                        new string[3] { "FinderOuter", "Finderouter", "finderouter" },
                        new string[5] { "was", "Is", "is", "!", "@" },
                        new string[4] { "fast", "quick", "Fast", "Awesome" }
                    },
                    $"Random.{Environment.NewLine}" +
                    $"This example is a BIP38 encrypted key with a 3-word passphrase (FinderOuterIsFast). " +
                    $"You can see how a possible list of words for each word is set." +
                    $"{Environment.NewLine}" +
                    $"Estimated time: <3 sec"
                },
                {
                    "6PnSz7B4XnPQUTBrUanV8kruDCnAegfMzFnpiKuv121zURVRyjWbbwyMKL",
                    1, // CompareInputType
                    "13rpixbWp9QngeEvgysmwcXCdWuM94t2CQ",
                    4, // Pass length
                    new string[4][]
                    {
                        new string[4] { "2", "4", "6", "8" },
                        new string[5] { "?", "!", ".", "@", "$" },
                        new string[6] { "A", "r", "b", "c", "x", "T" },
                        new string[2] { "H", "I" }
                    },
                    $"Random.{Environment.NewLine}" +
                    $"This example is a BIP38 encrypted key with a 4-character passphrase (8?rH). " +
                    $"You can see how a possible list of characters for each part is set." +
                    $"{Environment.NewLine}" +
                    $"Estimated time: <3 sec"
                },
            };
        }
    }
}
