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
    public class MissingBase58ViewModel : OptionVmBase
    {
        // Makes designer happy!
        public MissingBase58ViewModel() : this(new Settings())
        {
        }

        public MissingBase58ViewModel(Settings settings)
        {
            Result.Settings = settings;
            // Don't move this line, service must be instantiated here
            b58Service = new Base58Service(Result);
            searchSpace = new();

            IObservable<bool> isFindEnabled = this.WhenAnyValue(
                x => x.Input,
                x => x.SelectedMissingChar,
                x => x.Result.CurrentState,
                (b58, c, state) =>
                            !string.IsNullOrEmpty(b58) &&
                            InputService.IsMissingCharValid(c) &&
                            state != State.Working);

            FindCommand = ReactiveCommand.Create(Find, isFindEnabled);
            InputTypeList = ListHelper.GetAllEnumValues<Base58Type>();
            CompareInputTypeList = ListHelper.GetEnumDescItems(CompareInputType.PrivateKey).ToArray();
            SelectedCompareInputType = CompareInputTypeList.First();

            IObservable<bool> isExampleVisible = this.WhenAnyValue(x => x.Result.CurrentState, (state) => state != State.Working);
            ExampleCommand = ReactiveCommand.Create(Example, isExampleVisible);

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



        public override string OptionName => "Missing Base58";
        public override string Description => $"If you have a base-58 encoded string with a checksum such as private key WIFs " +
            $"(full list can be found under Input type dropdown) that is missing some characters at known locations " +
            $"(eg. a damaged paper wallet) you can use this option to recover it.{Environment.NewLine}" +
            $"Enter the base-58 string below and replace its missing characters with the symbol " +
            $"defined by MissingChar symbol and press Find.{Environment.NewLine}" +
            $"Exception: if you have a WIF private key missing up to 3 characters and you don't know the position of those " +
            $"characters, there is no need to use MissingChar symbol anymore, just enter the characters you have " +
            $"and press find.";


        private readonly Base58Service b58Service;
        private readonly B58SearchSpace searchSpace;


        public IEnumerable<Base58Type> InputTypeList { get; private set; }

        private Base58Type _selInpT;
        public Base58Type SelectedInputType
        {
            get => _selInpT;
            set
            {
                if (value != _selInpT)
                {
                    this.RaiseAndSetIfChanged(ref _selInpT, value);
                    isChanged = true;
                }
            }
        }

        private void Start()
        {
            InitSearchSpace();
            IsProcessed = searchSpace.Process(Input, SelectedMissingChar, SelectedInputType, out string error);
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
            AddToList(B58SearchSpace.AllChars);
        }

        public IReactiveCommand AddLowerCommand { get; }
        private void AddLower()
        {
            AddToList(B58SearchSpace.AllChars.Where(c => char.IsLower(c)));
        }

        public IReactiveCommand AddUpperCommand { get; }
        private void AddUpper()
        {
            AddToList(B58SearchSpace.AllChars.Where(c => char.IsUpper(c)));
        }

        public IReactiveCommand AddNumberCommand { get; }
        private void AddNumber()
        {
            AddToList(B58SearchSpace.AllChars.Where(c => char.IsDigit(c)));
        }

        public IReactiveCommand AddSimilarCommand { get; }
        private void AddSimilar()
        {
            ToAdd = ToAdd?.Trim();
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
                    ToAdd = string.Empty;
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
            ToAdd = ToAdd?.Trim();
            if (!string.IsNullOrEmpty(ToAdd) && ToAdd.Length == 1 && B58SearchSpace.AllChars.Contains(ToAdd[0]))
            {
                if (!CurrentItems.Contains(ToAdd))
                {
                    CurrentItems.Add(ToAdd);
                }
                ToAdd = string.Empty;
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
                    foreach (char c in B58SearchSpace.AllChars)
                    {
                        item.Add(c.ToString());
                    }
                }
            }

            if (IsProcessed)
            {
                if (searchSpace.SetValues(allItems.Select(x => x.ToArray()).Reverse().ToArray(), out string error))
                {
                    b58Service.Find(searchSpace, CompareInput, SelectedCompareInputType.Value);
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

            int temp1 = (int)ex[2];
            Debug.Assert(temp1 < InputTypeList.Count());
            SelectedInputType = InputTypeList.ElementAt(temp1);

            CompareInput = (string)ex[3];

            int temp2 = (int)ex[4];
            Debug.Assert(temp2 < CompareInputTypeList.Count());
            SelectedCompareInputType = CompareInputTypeList.ElementAt(temp2);

            Result.Message = $"Example {exampleIndex} of {totalExampleCount}. Source: {(string)ex[5]}";
        }

        private ExampleData GetExampleData()
        {
            return new ExampleData<string, int, int, string, int, string>()
            {
                {
                    "5Kb8kLf9zgWQn*gidDA76*zPL6TsZZY36h**MssSzNydYXYB9KF",
                    Array.IndexOf(MissingChars, '*'),
                    0,
                    null,
                    0,
                    $"bitcoin wiki.{Environment.NewLine}" +
                    $"This example is an uncompressed private key missing 4 character (o, M, W, X).{Environment.NewLine}" +
                    $"Estimated time: <1 sec to find, <5 sec to check all"
                },
                {
                    "L53fCHmQh??p1B4JipfBtfeHZH7cAib?G9oK19?fiFzxHgAkz6JK",
                    Array.IndexOf(MissingChars, '?'),
                    0,
                    null,
                    0,
                    $"bitcoin wiki.{Environment.NewLine}" +
                    $"This example is a compressed private key missing 4 character (b, N, z, X).{Environment.NewLine}" +
                    $"Note the usage of a different missing character.{Environment.NewLine}" +
                    $"Estimated time: <1 sec to find, <1 sec to check all"
                },
                {
                    "5JBK1WUuytf9HURTCwCVmKghDUgqEs3NRa1dsKja4FgRBQ*****",
                    Array.IndexOf(MissingChars, '*'),
                    0,
                    null,
                    0,
                    $"random key{Environment.NewLine}" +
                    $"This example is an uncompressed private key missing 5 character (N, G, c, a, A).{Environment.NewLine}" +
                    $"Note that since these characters are all missing from the end, FinderOuter automatically chooses " +
                    $"an optimized algorithm that only checks 1 key instead of 656,356,768 greatly increasing the speed." +
                    $"{Environment.NewLine}" +
                    $"Also note that this case doesn't need any additional input to check against since it only checks " +
                    $"one key.{Environment.NewLine}" +
                    $"Estimated time: <1 sec"
                },
                {
                    "KxpWVF8Cr71MZi2vfgDjxdUCW5CovBsTZShoj7gtuMny********",
                    Array.IndexOf(MissingChars, '*'),
                    0,
                    "1DjPqd6oBjii7PQh7JY1yAmPpHEHPWcaF3",
                    0,
                    $"random key{Environment.NewLine}" +
                    $"This example is a compressed private key missing 8 character (i,i,V,j,k,V,e,v).{Environment.NewLine}" +
                    $"Note that since these characters are all missing from the end, FinderOuter automatically chooses " +
                    $"an optimized algorithm that only checks 117 keys instead of 128 trillion (128,063,081,718,016) " +
                    $"greatly increasing the speed.{Environment.NewLine}" +
                    $"Also note that this optimized method requires an additional input (the corresponding public key or " +
                    $"address) to check each result against it and only return the correct key.{Environment.NewLine}" +
                    $"Estimated time: <1 sec"
                },
                {
                    "KxpWVF8Cr71MZi2vfgDjxdUCW5CovBsTZShoj7gtu***********",
                    Array.IndexOf(MissingChars, '*'),
                    0,
                    "1DjPqd6oBjii7PQh7JY1yAmPpHEHPWcaF3",
                    0,
                    $"random key{Environment.NewLine}" +
                    $"This is the same as previous example but they key is missing 11 characters.{Environment.NewLine}" +
                    $"Instead of checking 24 quadrillion keys, FinderOuter only checks 22 million.{Environment.NewLine}" +
                    $"Note the usage of multi-threading (parallelism){Environment.NewLine}" +
                    $"Estimated time: <2 min"
                },
                {
                    "5Kb8kLf9zgWQn*gidDA76*zPL6TsZZY36h**MssSzNy*YXYB9KF",
                    Array.IndexOf(MissingChars, '*'),
                    0,
                    null,
                    0,
                    $"bitcoin wiki{Environment.NewLine}" +
                    $"This example is an uncompressed private key missing 5 character (o, M, W, X, d).{Environment.NewLine}" +
                    $"Note the multi-thread usage (parallelism).{Environment.NewLine}" +
                    $"Also note that sometimes FinderOuter can find more than one valid base58, in this case 3." +
                    $"{Environment.NewLine}" +
                    $"Estimated time: <3 min"
                },
                {
                    "L53fCHmQhbNp1B4JipfBtfe**H7cA*bzG9o*19XfiF*xHgAkz6JK",
                    Array.IndexOf(MissingChars, '*'),
                    0,
                    null,
                    0,
                    $"bitcoin wiki{Environment.NewLine}" +
                    $"This example is a compressed private key missing 5 character (H, Z, i, K, z).{Environment.NewLine}" +
                    $"Note the multi-thread usage (parallelism).{Environment.NewLine}" +
                    $"Estimated time: <3 sec to find, <30 sec to check all"
                },
                //{
                //    "L53fCHmQhbNp1B4JipfBtfeHZHcAibzG9oK9XfiFzxHAkz6JK",
                //    Array.IndexOf(MissingChars, '*'),
                //    0,
                //    null,
                //    0,
                //    $"bitcoin wiki{Environment.NewLine}" +
                //    $"This example is a compressed private key missing 3 character at unknown positions.{Environment.NewLine}" +
                //    $"Note that this is a special case and it uses multi-thread (parallelism).{Environment.NewLine}" +
                //    $"Estimated time: <2 min to find, <3.5 min to check all"
                //},
                {
                    "142viJrTYHA4TzryiEiuQkYk4Ay5Tfp***",
                    Array.IndexOf(MissingChars, '*'),
                    1,
                    null,
                    0,
                    $"Bitcoin.Net test vectors{Environment.NewLine}" +
                    $"This example is a P2PKH address missing 3 character (z, q, W).{Environment.NewLine}" +
                    $"Estimated time: <1 sec"
                },
                {
                    "39vipRmsscHCg**T7FHfq*UmCoNZ*oCygq",
                    Array.IndexOf(MissingChars, '*'),
                    1,
                    null,
                    0,
                    $"Bitcoin.Net test vectors{Environment.NewLine}" +
                    $"This example is a P2SH address missing 4 character (3, s, S, r).{Environment.NewLine}" +
                    $"Estimated time: <6 sec"
                },
                {
                    "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s*DGhwP4*5o44cvXdoY7sRzhtp**o",
                    Array.IndexOf(MissingChars, '*'),
                    2,
                    null,
                    0,
                    $"BIP-38 test vectors{Environment.NewLine}" +
                    $"This example is a BIP-38 encrypted private key missing 4 character (6, J, U, e).{Environment.NewLine}" +
                    $"Estimated time: <3 sec to find, <6 second to check all"
                },
                {
                    "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5**DGhwP4*5o44cvXdoY7sRzhtp**o",
                    Array.IndexOf(MissingChars, '*'),
                    2,
                    null,
                    0,
                    $"BIP-38 test vectors{Environment.NewLine}" +
                    $"This example is a BIP-38 encrypted private key missing 5 character (s, 6, J, U, e).{Environment.NewLine}" +
                    $"Note the multi-thread usage (parallelism).{Environment.NewLine}" +
                    $"Estimated time: <1 min to find, <3 min to check all"
                },
            };
        }
    }
}
