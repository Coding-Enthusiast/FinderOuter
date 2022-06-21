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
    public class MissingBase16ViewModel : OptionVmBase
    {
        public MissingBase16ViewModel()
        {
            // Don't move this line, service must be instantiated here
            b16Service = new Base16Sevice(Result);
            InputService inServ = new();
            searchSpace = new();

            IObservable<bool> isFindEnabled = this.WhenAnyValue(
                x => x.Input,
                x => x.Result.CurrentState, (b58, state) =>
                            !string.IsNullOrEmpty(b58) &&
                            state != State.Working);

            FindCommand = ReactiveCommand.Create(Find, isFindEnabled);
            CompareInputTypeList = ListHelper.GetEnumDescItems(CompareInputType.PrivateKey).ToArray();
            SelectedCompareInputType = CompareInputTypeList.First();

            HasExample = true;
            IObservable<bool> isExampleVisible = this.WhenAnyValue(
                x => x.Result.CurrentState,
                (state) => state != State.Working);
            ExampleCommand = ReactiveCommand.Create(Example, isExampleVisible);

            SetExamples(GetExampleData());

            IObservable<bool> canAdd = this.WhenAnyValue(x => x.IsProcessed, (b) => b == true);

            StartCommand = ReactiveCommand.Create(Start, isFindEnabled);
            AddAllCommand = ReactiveCommand.Create(AddAll, canAdd);
            AddNumberCommand = ReactiveCommand.Create(AddNumber, canAdd);
            AddExactCommand = ReactiveCommand.Create(AddExact, canAdd);
        }



        public override string OptionName => "Missing Base16";
        public override string Description => $"Helps you recover missing Base-16 (hexadecimal) characters in private keys. " +
            $"Since unlike WIF (Base-58) this format has no checksum, all combinations with any character is correct. " +
            $"This is why the code has to check each combination against the additional data which can be an address or a " +
            $"public key.{Environment.NewLine}" +
            $"Enter the base-16 string and replace its missing characters with the symbol defined by missing character " +
            $"parameter and press Find.";


        private readonly Base16Sevice b16Service;
        private readonly B16SearchSpace searchSpace;


        private string _input;
        public string Input
        {
            get => _input;
            set => this.RaiseAndSetIfChanged(ref _input, value);
        }

        private string _input2;
        public string AdditionalInput
        {
            get => _input2;
            set => this.RaiseAndSetIfChanged(ref _input2, value);
        }


        private void Start()
        {
            isChanged = false;
            Index = 0;
            Max = 0;
            IsProcessed = searchSpace.Process(Input, SelectedMissingChar, out string error);

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


        private void AddToList(IEnumerable<char> items)
        {
            foreach (char item in items)
            {
                if (!CurrentItems.Contains(item.ToString()))
                {
                    CurrentItems.Add(item.ToString());
                }
            }
        }

        public IReactiveCommand AddAllCommand { get; }
        private void AddAll()
        {
            AddToList(searchSpace.AllChars);
        }

        public IReactiveCommand AddNumberCommand { get; }
        private void AddNumber()
        {
            AddToList(searchSpace.AllChars.Where(c => char.IsDigit(c)));
        }


        public IReactiveCommand AddExactCommand { get; }
        private void AddExact()
        {
            if (!string.IsNullOrEmpty(ToAdd) && ToAdd.Length == 1 && searchSpace.AllChars.Contains(ToAdd[0]))
            {
                if (!CurrentItems.Contains(ToAdd))
                {
                    CurrentItems.Add(ToAdd);
                }
            }
            else
            {
                Result.AddMessage($"The entered character ({ToAdd}) is not found in Base-58 character list.");
            }
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
                    foreach (char c in searchSpace.AllChars)
                    {
                        item.Add(c.ToString());
                    }
                }
            }

            if (IsProcessed)
            {
                if (searchSpace.SetValues(allItems.Select(x => x.ToArray()).Reverse().ToArray()))
                {
                    b16Service.Find(searchSpace, AdditionalInput, SelectedCompareInputType.Value);
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

            Input = (string)ex[0];
            SelectedMissingChar = MissingChars[(int)ex[1]];
            AdditionalInput = (string)ex[2];
            int temp = (int)ex[3];
            Debug.Assert(temp < CompareInputTypeList.Count());
            SelectedCompareInputType = CompareInputTypeList.ElementAt(temp);
            Result.Message = $"Example {exampleIndex} of {totalExampleCount}. Source: {(string)ex[4]}";
        }

        private ExampleData GetExampleData()
        {
            return new ExampleData<string, int, string, int, string>()
            {
                {
                    "0c28fca386c7a227600b2fe50b7cae11ec86d3b*1fbe471be89827e19d72aa1d",
                    Array.IndexOf(MissingChars, '*'),
                    "1LoVGDgRs9hTfTNJNuXKSpywcbdvwRXpmK",
                    0,
                    $"bitcoin wiki.{Environment.NewLine}" +
                    $"This example is missing one character (f).{Environment.NewLine}" +
                    $"Estimated time: <1 sec"
                },
                {
                    "0c28fca386c7a227600?2fe50b7cae11ec?6d3b?1fbe?71be8?827e19d72aa1d",
                    Array.IndexOf(MissingChars, '?'),
                    "1LoVGDgRs9hTfTNJNuXKSpywcbdvwRXpmK",
                    2,
                    $"bitcoin wiki.{Environment.NewLine}" +
                    $"This example is missing 5 character (b, 8, f, 4, 9).{Environment.NewLine}" +
                    $"Note the usage of a different missing character and input type here.{Environment.NewLine}" +
                    $"Also note the multi-thread usage (parallelism).{Environment.NewLine}" +
                    $"Estimated time: <30 sec"
                },
                {
                    "8e812436a0e3323166e1f0e8ba79e19e217b2c4a53c9*0d4cca0cfb1078979df",
                    Array.IndexOf(MissingChars, '*'),
                    "04a5bb3b28466f578e6e93fbfd5f75cee1ae86033aa4bbea690e3312c087181eb366f9a1d1d6a437a9bf9fc65ec853b9fd60fa322be3997c47144eb20da658b3d1",
                    4,
                    $"https://developers.tron.network/docs/account. {Environment.NewLine}" +
                    $"This example is missing one character (7).{Environment.NewLine}" +
                    $"Note the usage of a different input type here.{Environment.NewLine}" +
                    $"This example also shows that FinderOuter can potentially be used for any altcoin " +
                    $"that uses the same cryptography algorithms as bitcoin.{Environment.NewLine}" +
                    $"In this example Tron uses the same Elliptic Curve as bitcoin but different " +
                    $"hash algorithms, ergo the public key can be used as the extra input but not addresses{Environment.NewLine}" +
                    $"Estimated time: <1 sec"
                },
            };
        }
    }
}
