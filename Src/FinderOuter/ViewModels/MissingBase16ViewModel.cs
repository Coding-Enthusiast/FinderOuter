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
        // Makes designer happy!
        public MissingBase16ViewModel() : this(new Settings())
        {
        }

        public MissingBase16ViewModel(Settings settings)
        {
            Result.Settings = settings;
            b16Service = new Base16Sevice(Result);
            searchSpace = new();

            IObservable<bool> isFindEnabled = this.WhenAnyValue(
                x => x.Input,
                x => x.Result.CurrentState,
                (b16, state) => !string.IsNullOrEmpty(b16) && state != State.Working);

            FindCommand = ReactiveCommand.Create(Find, isFindEnabled);
            CompareInputTypeList = ListHelper.GetEnumDescItems(CompareInputType.PrivateKey).ToArray();
            SelectedCompareInputType = CompareInputTypeList.First();

            IObservable<bool> isExampleEnabled = this.WhenAnyValue(x => x.Result.CurrentState, (state) => state != State.Working);
            ExampleCommand = ReactiveCommand.Create(Example, isExampleEnabled);

            SetExamples(GetExampleData());

            IObservable<bool> canAdd = this.WhenAnyValue(x => x.IsProcessed, (b) => b == true);
            IObservable<bool> canAddExact = this.WhenAnyValue(
                x => x.IsProcessed, x => x.ToAdd,
                (b, s) => b == true && !string.IsNullOrEmpty(s));

            StartCommand = ReactiveCommand.Create(Start, isFindEnabled);
            AddAllCommand = ReactiveCommand.Create(AddAll, canAdd);
            AddNumbersCommand = ReactiveCommand.Create(AddNumbers, canAdd);
            AddLetersCommand = ReactiveCommand.Create(AddLeters, canAdd);
            AddExactCommand = ReactiveCommand.Create(AddExact, canAddExact);

            CopyCommand = ReactiveCommand.Create(Copy, isFindEnabled);
        }



        public override string OptionName => "Missing Base16";
        public override string Description => $"This option is useful for recovering Base-16 (hexadecimal) private keys " +
            $"with missing characters at known positions.{Environment.NewLine}" +
            $"Enter the 64-digit long Base-16 encoded private key below and replace its missing character(s) with the " +
            $"symbol defined by missing character drop-box then click Find.{Environment.NewLine}" +
            $"This recovery option requires the address or public key derived from this private key " +
            $"to compare each permutation with.";


        private readonly Base16Sevice b16Service;
        private readonly B16SearchSpace searchSpace;


        private void Start()
        {
            InitSearchSpace();
            IsProcessed = searchSpace.Process(Input, SelectedMissingChar, out string error);
            FinishSearchSpace(searchSpace.MissCount, error);
        }


        private void AddToList(IEnumerable<char> items)
        {
            if (items is null || CurrentItems is null)
            {
                return;
            }

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
            AddToList(B16SearchSpace.AllChars);
        }

        public IReactiveCommand AddNumbersCommand { get; }
        private void AddNumbers()
        {
            AddToList(B16SearchSpace.AllChars.Where(c => char.IsDigit(c)));
        }

        public IReactiveCommand AddLetersCommand { get; }
        private void AddLeters()
        {
            AddToList(B16SearchSpace.AllChars.Where(c => char.IsLetter(c)));
        }


        public IReactiveCommand AddExactCommand { get; }
        private void AddExact()
        {
            if (ToAdd is not null)
            {
                ToAdd = ToAdd.Trim().ToLowerInvariant();
                if (!string.IsNullOrEmpty(ToAdd) && ToAdd.Length == 1 && B16SearchSpace.AllChars.Contains(ToAdd[0]))
                {
                    if (!CurrentItems.Contains(ToAdd))
                    {
                        CurrentItems.Add(ToAdd);
                    }
                    ToAdd = string.Empty;
                }
                else
                {
                    Result.AddMessage($"The entered character ({ToAdd}) is not a valid Base-16 character.");
                }
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
                    foreach (char c in B16SearchSpace.AllChars)
                    {
                        item.Add(c.ToString());
                    }
                }
            }

            if (IsProcessed)
            {
                if (searchSpace.SetValues(allItems.Select(x => x.ToArray()).ToArray(), out string error))
                {
                    b16Service.Find(searchSpace, CompareInput, SelectedCompareInputType.Value);
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
            SelectedMissingChar = MissingChars[(int)ex[1]];
            CompareInput = (string)ex[2];
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
