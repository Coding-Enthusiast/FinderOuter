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
    public class MissingMiniPrivateKeyViewModel : OptionVmBase
    {
        // Makes designer happy!
        public MissingMiniPrivateKeyViewModel() : this(new Settings())
        {
        }

        public MissingMiniPrivateKeyViewModel(Settings settings)
        {
            Result.Settings = settings;
            // Don't move this line, service must be instantiated here
            miniService = new MiniKeyService(Result);
            searchSpace = new();

            IObservable<bool> isFindEnabled = this.WhenAnyValue(
                x => x.Input,
                x => x.CompareInput,
                x => x.Result.CurrentState, (miniKey, addr, state) =>
                            !string.IsNullOrEmpty(miniKey) &&
                            !string.IsNullOrEmpty(addr) &&
                            state != State.Working);

            FindCommand = ReactiveCommand.Create(Find, isFindEnabled);

            IObservable<bool> isExampleVisible = this.WhenAnyValue(x => x.Result.CurrentState, (state) => state != State.Working);
            ExampleCommand = ReactiveCommand.Create(Example, isExampleVisible);

            CompareInputTypeList = ListHelper.GetEnumDescItems(CompareInputType.PrivateKey).ToArray();
            SelectedCompareInputType = CompareInputTypeList.First();

            SetExamples(GetExampleData());

            IObservable<bool> canAdd = this.WhenAnyValue(x => x.IsProcessed, (b) => b == true);

            StartCommand = ReactiveCommand.Create(Start, isFindEnabled);
            AddAllCommand = ReactiveCommand.Create(AddAll, canAdd);
            AddLowerCommand = ReactiveCommand.Create(AddLower, canAdd);
            AddUpperCommand = ReactiveCommand.Create(AddUpper, canAdd);
            AddNumberCommand = ReactiveCommand.Create(AddNumber, canAdd);
            AddExactCommand = ReactiveCommand.Create(AddExact, canAdd);
            AddSimilarCommand = ReactiveCommand.Create(AddSimilar, canAdd);

            CopyCommand = ReactiveCommand.Create(Copy, isFindEnabled);
        }

        public override string OptionName => "Missing mini private key";

        public override string Description =>
            $"This option can recover missing characters in a mini private key." +
            $"{Environment.NewLine}" +
            $"Enter the mini key (22 or 26 or 30 characters long starting with S) in first box while replacing its missing " +
            $"characters with the specified missing character and enter the " +
            $"corresponding address in second box and click Find button.";


        private readonly MiniKeyService miniService;
        private readonly MiniKeySearchSpace searchSpace;

        private void Start()
        {
            InitSearchSpace();
            IsProcessed = searchSpace.Process(Input, SelectedMissingChar, out string error);
            FinishSearchSpace(searchSpace.MissCount, error);
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
            AddToList(MiniKeySearchSpace.AllChars);
        }

        public IReactiveCommand AddLowerCommand { get; }
        private void AddLower()
        {
            AddToList(MiniKeySearchSpace.AllChars.Where(c => char.IsLower(c)));
        }

        public IReactiveCommand AddUpperCommand { get; }
        private void AddUpper()
        {
            AddToList(MiniKeySearchSpace.AllChars.Where(c => char.IsUpper(c)));
        }

        public IReactiveCommand AddNumberCommand { get; }
        private void AddNumber()
        {
            AddToList(MiniKeySearchSpace.AllChars.Where(c => char.IsDigit(c)));
        }

        public IReactiveCommand AddSimilarCommand { get; }
        private void AddSimilar()
        {
            ToAdd = ToAdd.Trim();
            if (!string.IsNullOrEmpty(ToAdd) && ToAdd.Length == 1)
            {
                // Characters outside of Base58 charset are accepted here
                if (!ConstantsFO.LowerCase.Contains(ToAdd.ToLower()) && !ConstantsFO.Numbers.Contains(ToAdd))
                {
                    Result.AddMessage("Invalid character (only letters and numbers are accepted).");
                }
                else
                {
                    char c = ToAdd[0];
                    for (int i = 0; i < ConstantsFO.SimilarBase58Chars.Length; i++)
                    {
                        if (ConstantsFO.SimilarBase58Chars[i].Contains(c))
                        {
                            foreach (char item in ConstantsFO.SimilarBase58Chars[i])
                            {
                                if (ConstantsFO.Base58Chars.Contains(item) && !CurrentItems.Contains(item.ToString()))
                                {
                                    CurrentItems.Add(item.ToString());
                                }
                            }
                        }
                    }
                }
            }
            else
            {
                Result.AddMessage($"The entered character ({ToAdd}) can not be a Base-58 character.");
            }
        }

        public IReactiveCommand AddExactCommand { get; }
        private void AddExact()
        {
            ToAdd = ToAdd.Trim();
            if (!string.IsNullOrEmpty(ToAdd) && ToAdd.Length == 1 && MiniKeySearchSpace.AllChars.Contains(ToAdd[0]))
            {
                if (!CurrentItems.Contains(ToAdd))
                {
                    CurrentItems.Add(ToAdd);
                }
            }
            else
            {
                Result.AddMessage($"The entered character ({ToAdd}) is not a valid Base-58 character.");
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
                    foreach (char c in MiniKeySearchSpace.AllChars)
                    {
                        item.Add(c.ToString());
                    }
                }
            }

            if (IsProcessed)
            {
                if (searchSpace.SetValues(allItems.Select(x => x.ToArray()).ToArray(), out string error))
                {
                    miniService.Find(searchSpace, CompareInput, SelectedCompareInputType.Value);
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
                    "SzavMBLoXU6kDr*tUV*ffv",
                    Array.IndexOf(MissingChars, '*'),
                    "19GuvDvMMUZ8vq84wT79fvnvhMd5MnfTkR",
                    0,
                    $"bitcoin wiki.{Environment.NewLine}" +
                    $"This example is a 22 digit long mini-key and is missing 2 (q, m).{Environment.NewLine}" +
                    $"Estimated time: <1 sec"
                },
                {
                    "SzavMBLoXU6kDrqtUVmf--",
                    Array.IndexOf(MissingChars, '-'),
                    "02588D202AFCC1EE4AB5254C7847EC25B9A135BBDA0F2BC69EE1A714749FD77DC9",
                    4,
                    $"bitcoin wiki.{Environment.NewLine}" +
                    $"This example is a 22 digit long mini-key and is missing 2 (f, v).{Environment.NewLine}" +
                    $"Note the usage of a different missing character and extra input type (pubkey).{Environment.NewLine}" +
                    $"Estimated time: <1 sec"
                },
                {
                    "S6c56bnXQiB*k9mqS*E7ykVQ7Nzr*y",
                    Array.IndexOf(MissingChars, '*'),
                    "1CciesT23BNionJeXrbxmjc7ywfiyM4oLW",
                    1,
                    $"bitcoin wiki.{Environment.NewLine}" +
                    $"This example is a 30 digit long mini-key missing 3 (j, Y, R).{Environment.NewLine}" +
                    $"Note the usage of a different extra input type (address using uncompressed pubkey).{Environment.NewLine}" +
                    $"Estimated time: <10 sec"
                },
                {
                    "SzavMBLo*U6*D**tU*mffv",
                    Array.IndexOf(MissingChars, '*'),
                    "02588D202AFCC1EE4AB5254C7847EC25B9A135BBDA0F2BC69EE1A714749FD77DC9",
                    4,
                    $"bitcoin wiki.{Environment.NewLine}" +
                    $"This example is missing 5 characters (X, k, r, q, V).{Environment.NewLine}" +
                    $"Note the multi-thread usage (parallelism).{Environment.NewLine}" +
                    $"Estimated time: <1 min"
                }
            };
        }
    }
}
