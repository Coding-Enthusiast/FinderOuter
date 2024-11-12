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
    public class CorePassViewModel : OptionVmBase
    {
        // Makes designer happy!
        public CorePassViewModel() : this(new Settings())
        {
        }

        public CorePassViewModel(Settings settings)
        {
            Result.Settings = settings;
            Service = new(Result);

            IObservable<bool> isFindEnabled = this.WhenAnyValue(
                x => x.Input,
                x => x.Result.CurrentState,
                (mn, state) =>
                            !string.IsNullOrEmpty(mn) &&
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


        public override string OptionName => "Bitcoin Core wallet pass";
        public override string Description => $"This option can recover bitcoin core wallet.dat encryption password." +
            $"{Environment.NewLine}";

        public static string PassLenToolTip => "Number of words in the passphrase.";

        private readonly CorePassSearchSpace searchSpace = new();

        public CorePassService Service { get; }
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
                    ToAdd = string.Empty;
                }
                else
                {
                    Result.AddMessage($"\"{ToAdd}\" is already in the list.");
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
                    Service.Find(searchSpace);
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
            PassLength = (int)ex[1];

            Start();

            Debug.Assert(allItems.Length == PassLength);
            string[][] items = (string[][])ex[2];
            for (int i = 0; i < items.Length; i++)
            {
                foreach (var item in items[i])
                {
                    allItems[i].Add(item);
                }
            }

            Result.Message = $"Example {exampleIndex} of {totalExampleCount}. Source: {(string)ex[3]}";
        }

        private ExampleData GetExampleData()
        {
            return new ExampleData<string, int, string[][], string>()
            {
                {
                    "43000130ac71182a748152bb788fb9deb11f2f5a55f5e848d66586747cc000826d4c0c350032153d50cbf924a2ac1dc5f6279436089ca0271b64c0e66f00000000c6fe040000",
                    2, // Pass length
                    new string[2][]
                    {
                        new string[5] { "master", "M@ster", "Master", "MaStEr", "m@ster" },
                        new string[4] { "exploder", "ExPlOreR", "Expl0der", "Exploder" },
                    },
                    $"Taken from https://bitcointalk.org/index.php?topic=5511431.msg64607294#msg64607294{Environment.NewLine}" +
                    $"This is a random encryption key with a 2 word passphrase (MasterExploder). " +
                    $"You can see how a possible list of words for each word is set." +
                    $"{Environment.NewLine}" +
                    $"Estimated time: ~1 sec"
                },
            };
        }
    }
}
