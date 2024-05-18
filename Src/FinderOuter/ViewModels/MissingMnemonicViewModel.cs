// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using Autarkysoft.Bitcoin.ImprovementProposals;
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
    public class MissingMnemonicViewModel : OptionVmBase
    {
        /// <summary>
        /// Make designer happy!
        /// </summary>
        public MissingMnemonicViewModel() : this(new Settings())
        {
        }

        public MissingMnemonicViewModel(Settings settings)
        {
            Result.Settings = settings;
            WordListsList = ListHelper.GetAllEnumValues<BIP0039.WordLists>().ToArray();
            MnemonicTypesList = ListHelper.GetAllEnumValues<MnemonicTypes>().ToArray();
            ElectrumMnemonicTypesList = ListHelper.GetAllEnumValues<ElectrumMnemonic.MnemonicType>().ToArray();
            CompareInputTypeList = ListHelper.GetEnumDescItems<CompareInputType>().ToArray();
            SelectedCompareInputType = CompareInputTypeList.First();
            MnService = new MnemonicSevice(Result);

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

            IObservable<bool> isExampleVisible = this.WhenAnyValue(x => x.Result.CurrentState, (state) => state != State.Working);
            ExampleCommand = ReactiveCommand.Create(Example, isExampleVisible);

            this.WhenAnyValue(x => x.SelectedMnemonicType).Subscribe(x => IsElectrumTypesVisible = x == MnemonicTypes.Electrum);

            SetExamples(GetExampleData());

            IObservable<bool> canAdd = this.WhenAnyValue(x => x.IsProcessed, (b) => b == true);

            StartCommand = ReactiveCommand.Create(Start, isFindEnabled);
            AddAllCommand = ReactiveCommand.Create(AddAll, canAdd);
            AddExactCommand = ReactiveCommand.Create(AddExact, canAdd);
            AddSimilarCommand = ReactiveCommand.Create(AddSimilar, canAdd);
            AddStartCommand = ReactiveCommand.Create(AddStart, canAdd);
            AddEndCommand = ReactiveCommand.Create(AddEnd, canAdd);
            AddContainCommand = ReactiveCommand.Create(AddContain, canAdd);

            CopyCommand = ReactiveCommand.Create(Copy, isFindEnabled);
        }


        public override string OptionName => "Missing Mnemonic";
        public override string Description => $"This option is useful for recovering mnemonics (seed phrases) that are " +
            $"missing some words. It supports both BIP39 and Electrum standards.{Environment.NewLine}" +
            $"Enter words that are known and replace the missing ones with the symbol defined by " +
            $"{nameof(SelectedMissingChar)} parameter.{Environment.NewLine}" +
            $"Note that the path is the full BIP-32 defined key/address path not the parent master key path and each " +
            $"number is a zero-based index (first address is 0, second is 1,...). Example: m/44'/0'/0'/0";


        private readonly MnemonicSearchSpace searchSpace = new();

        private string[] _wl;
        /// <summary>
        /// Used by AutoCompleteBox in UI
        /// </summary>
        public string[] WordList
        {
            get => _wl;
            set => this.RaiseAndSetIfChanged(ref _wl, value);
        }

        public MnemonicSevice MnService { get; }

        public IEnumerable<BIP0039.WordLists> WordListsList { get; }

        private BIP0039.WordLists _selWordLst;
        public BIP0039.WordLists SelectedWordListType
        {
            get => _selWordLst;
            set => this.RaiseAndSetIfChanged(ref _selWordLst, value);
        }

        public IEnumerable<MnemonicTypes> MnemonicTypesList { get; }
        public IEnumerable<ElectrumMnemonic.MnemonicType> ElectrumMnemonicTypesList { get; }

        private MnemonicTypes _selMnT;
        public MnemonicTypes SelectedMnemonicType
        {
            get => _selMnT;
            set => this.RaiseAndSetIfChanged(ref _selMnT, value);
        }

        private ElectrumMnemonic.MnemonicType _selElecMnT;
        public ElectrumMnemonic.MnemonicType SelectedElectrumMnType
        {
            get => _selElecMnT;
            set
            {
                this.RaiseAndSetIfChanged(ref _selElecMnT, value);
                KeyPath = MnemonicSevice.GetElectrumPath(value);
            }
        }

        private bool _isElecTVisible;
        public bool IsElectrumTypesVisible
        {
            get => _isElecTVisible;
            set => this.RaiseAndSetIfChanged(ref _isElecTVisible, value);
        }

        private string _pass;
        public string PassPhrase
        {
            get => _pass;
            set => this.RaiseAndSetIfChanged(ref _pass, value);
        }

        private string _path;
        public string KeyPath
        {
            get => _path;
            set => this.RaiseAndSetIfChanged(ref _path, value);
        }


        public void Start()
        {
            InitSearchSpace();
            IsProcessed = searchSpace.Process(Input, SelectedMissingChar, SelectedMnemonicType, SelectedWordListType, SelectedElectrumMnType, out string error);
            FinishSearchSpace(searchSpace.MissCount, error);
            if (IsProcessed)
            {
                WordList = searchSpace.allWords;
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
        public void AddAll()
        {
            AddToList(searchSpace.allWords);
        }

        public IReactiveCommand AddSimilarCommand { get; }
        public void AddSimilar()
        {
            ToAdd = ToAdd?.Trim().ToLowerInvariant();
            if (string.IsNullOrWhiteSpace(ToAdd))
            {
                Result.AddMessage("Word to add can not be null or empty.");
            }
            else
            {
                int threshold = 2;
                AddToList(searchSpace.allWords.Where(w => w.LevenshteinDistance(ToAdd) < threshold));
                ToAdd = string.Empty;
            }
        }

        public IReactiveCommand AddExactCommand { get; }
        public void AddExact()
        {
            ToAdd = ToAdd?.Trim().ToLowerInvariant();
            if (!string.IsNullOrEmpty(ToAdd) && searchSpace.allWords.Contains(ToAdd))
            {
                if (!CurrentItems.Contains(ToAdd))
                {
                    CurrentItems.Add(ToAdd);
                }
                ToAdd = string.Empty;
            }
            else
            {
                Result.AddMessage($"The entered word ({ToAdd}) is not found in selected word-list.");
            }
        }

        public IReactiveCommand AddStartCommand { get; }
        public void AddStart()
        {
            ToAdd = ToAdd?.Trim().ToLowerInvariant();
            if (!string.IsNullOrWhiteSpace(ToAdd))
            {
                AddToList(searchSpace.allWords.Where(x => x.StartsWith(ToAdd)));
                ToAdd = string.Empty;
            }
            else
            {
                Result.AddMessage("Word to add can not be null or empty.");
            }
        }

        public IReactiveCommand AddEndCommand { get; }
        public void AddEnd()
        {
            ToAdd = ToAdd?.Trim().ToLowerInvariant();
            if (!string.IsNullOrWhiteSpace(ToAdd))
            {
                AddToList(searchSpace.allWords.Where(x => x.EndsWith(ToAdd)));
                ToAdd = string.Empty;
            }
            else
            {
                Result.AddMessage("Word to add can not be null or empty.");
            }
        }

        public IReactiveCommand AddContainCommand { get; }
        public void AddContain()
        {
            ToAdd = ToAdd?.Trim().ToLowerInvariant();
            if (!string.IsNullOrWhiteSpace(ToAdd))
            {
                AddToList(searchSpace.allWords.Where(x => x.Contains(ToAdd)));
                ToAdd = string.Empty;
            }
            else
            {
                Result.AddMessage("Word to add can not be null or empty.");
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
                    foreach (string word in searchSpace.allWords)
                    {
                        item.Add(word);
                    }
                }
            }

            if (IsProcessed)
            {
                if (searchSpace.SetValues(allItems.Select(x => x.ToArray()).ToArray(), out string error))
                {
                    MnService.FindMissing(searchSpace, PassPhrase, KeyPath, CompareInput, SelectedCompareInputType.Value);
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
            Debug.Assert(temp1 < WordListsList.Count());
            SelectedWordListType = WordListsList.ElementAt(temp1);

            int temp2 = (int)ex[3];
            Debug.Assert(temp2 < MnemonicTypesList.Count());
            SelectedMnemonicType = MnemonicTypesList.ElementAt(temp2);

            int temp3 = (int)ex[4];
            Debug.Assert(temp3 < ElectrumMnemonicTypesList.Count());
            SelectedElectrumMnType = ElectrumMnemonicTypesList.ElementAt(temp3);

            PassPhrase = (string)ex[5];
            KeyPath = (string)ex[6];
            CompareInput = (string)ex[7];

            int temp4 = (int)ex[8];
            Debug.Assert(temp4 < CompareInputTypeList.Count());
            SelectedCompareInputType = CompareInputTypeList.ElementAt(temp4);

            Result.Message = $"Example {exampleIndex} of {totalExampleCount}. Source: {(string)ex[9]}";
        }

        private ExampleData GetExampleData()
        {
            return new ExampleData<string, int, int, int, int, string, string, string, int, string>()
            {
                {
                    "ozone drill grab fiber curtain * pudding thank cruise elder eight picnic",
                    Array.IndexOf(MissingChars, '*'),
                    0, // WordList
                    0, // MnemonicType
                    0, // Electrum mnemonic type
                    "AnExamplePassPhrase",
                    "m/44'/0'/0'/0/0",
                    "1FCptKjDovTGKYz2vLGVtswGqwgp6JmfyN",
                    0,
                    $"BIP-39 test vectors.{Environment.NewLine}" +
                    $"This example is missing one word (grace).{Environment.NewLine}" +
                    $"It is using a BIP-44 specified path (m/44'/0'/0'/0) and we have the first non-hardened address " +
                    $"from the list of addresses it can produce (in a zero based index system it is address 0) so the " +
                    $"full path will be m/44'/0'/0'/0/0.{Environment.NewLine}" +
                    $"It also has an optional passphrase.{Environment.NewLine}" +
                    $"The following addresses with their private keys are derived from it:{Environment.NewLine}" +
                    $"m/44'/0'/0'/0/0: 1FCptKjDovTGKYz2vLGVtswGqwgp6JmfyN Kybku8EdkM3ndLU6gnWhATyn67WUsRqJENZT5xKttPDFbMrPFcBn{Environment.NewLine}" +
                    $"m/44'/0'/0'/0/1: 1Ga41FCgn5f196Bp5aQVijN61rHwE8asUk L21gjCRzGPd9rQFi7wgryCaH4EjqDYpJqq6bux9Db9PmbvXV5wVy{Environment.NewLine}" +
                    $"m/44'/0'/0'/0/2: 142FTStohZfzH563BL35gCX11CNBg8HDfv Kwy7EuvNH2E178irnBJMxFjytCSMkAupXHZiRtcgGSiBTPJy5gUt{Environment.NewLine}" +
                    $"Estimated time: <1 sec"
                },
                {
                    "ozone drill grab fiber curtain * pudding thank cruise elder eight picnic",
                    Array.IndexOf(MissingChars, '*'),
                    0, // WordList
                    0, // MnemonicType
                    0, // Electrum mnemonic type
                    "AnExamplePassPhrase",
                    "m/44'/0'/0'/0/2",
                    "Kwy7EuvNH2E178irnBJMxFjytCSMkAupXHZiRtcgGSiBTPJy5gUt",
                    5,
                    $"BIP-39 test vectors.{Environment.NewLine}" +
                    $"This example is missing one word (grace).{Environment.NewLine}" +
                    $"Same as previous example but we have the 3rd private key (at index=2) instead, so the path is " +
                    $"m/44'/0'/0'/0/2 this time.{Environment.NewLine}" +
                    $"The following addresses with their private keys are derived from it:{Environment.NewLine}" +
                    $"m/44'/0'/0'/0/0: 1FCptKjDovTGKYz2vLGVtswGqwgp6JmfyN Kybku8EdkM3ndLU6gnWhATyn67WUsRqJENZT5xKttPDFbMrPFcBn{Environment.NewLine}" +
                    $"m/44'/0'/0'/0/1: 1Ga41FCgn5f196Bp5aQVijN61rHwE8asUk L21gjCRzGPd9rQFi7wgryCaH4EjqDYpJqq6bux9Db9PmbvXV5wVy{Environment.NewLine}" +
                    $"m/44'/0'/0'/0/2: 142FTStohZfzH563BL35gCX11CNBg8HDfv Kwy7EuvNH2E178irnBJMxFjytCSMkAupXHZiRtcgGSiBTPJy5gUt{Environment.NewLine}" +
                    $"Estimated time: <1 sec"
                },
                {
                    "avide sardine séjour docteur tétine soluble nautique raisin toucher notoire linéaire lièvre tenir demeurer talonner civil - fabuleux pizza diminuer gagner oisillon trafic imposer",
                    Array.IndexOf(MissingChars, '-'),
                    3, // WordList
                    0, // MnemonicType
                    0, // Electrum mnemonic type
                    "",
                    "m/0/0",
                    "3L5EM1AiF95RBTuZkEMCEeE4eHoRRbc7Sd",
                    3,
                    $"random.{Environment.NewLine}" +
                    $"This example is missing one word (lézard).{Environment.NewLine}" +
                    $"Note the usage of a different language (French), different derivation path (BIP-141 m/0), different " +
                    $"missing character type and different extra input type (nested SegWit address also known as P2SH-P2WPKH)." +
                    $"{Environment.NewLine}" +
                    $"The following addresses are derived from it:{Environment.NewLine}" +
                    $"m/0/0: 3L5EM1AiF95RBTuZkEMCEeE4eHoRRbc7Sd{Environment.NewLine}" +
                    $"m/0/1: 3LvkAVV5Y4BQT7XFoMPXkxAQm4TFxQgdBP{Environment.NewLine}" +
                    $"m/0/2: 32tpfpxY5KG7Bdqf8m8cthoVcyALjvBk5z{Environment.NewLine}" +
                    $"Estimated time: <1 sec"
                },
                {
                    "panda eyebrow bullet gorilla call smoke muffin * mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner * ghost inside",
                    Array.IndexOf(MissingChars, '*'),
                    0, // WordList
                    0, // MnemonicType
                    0, // Electrum mnemonic type
                    "$4f9Asf*vX#4bX@7",
                    "m/84'/0'/0'/0/4",
                    "bc1qzqm9vplw0fkk7t9dka82quer95e77levpppmj9",
                    0,
                    $"BIP-39 test vectors.{Environment.NewLine}" +
                    $"This example is missing two words (taste, drive).{Environment.NewLine}" +
                    $"Note the usage of a different word length (24), different derivation path (BIP-84 m/84'/0'/0'/0) and " +
                    $"different extra input type (5th bech32 address at index 4).{Environment.NewLine}" +
                    $"Also note the multi-thread usage (parallelism).{Environment.NewLine}" +
                    $"The following addresses are derived from it:{Environment.NewLine}" +
                    $"m/84'/0'/0'/0/0: bc1qdw0n7ausyak5xeng2e524v0sfwpt0dh8e785pr{Environment.NewLine}" +
                    $"m/84'/0'/0'/0/1: bc1q9qhpj3vmgfxxvmf8wm9m67a99l0uqm922nwp8p{Environment.NewLine}" +
                    $"m/84'/0'/0'/0/2: bc1qkfaq84rdaevpzz3hy04gnmfm76qm3kqdhp5p3r{Environment.NewLine}" +
                    $"m/84'/0'/0'/0/3: bc1qjdx97svvkqxkvs7g3402ksyd80fk4l9ddlvje2{Environment.NewLine}" +
                    $"m/84'/0'/0'/0/4: bc1qzqm9vplw0fkk7t9dka82quer95e77levpppmj9{Environment.NewLine}" +
                    $"Estimated time: <10 sec"
                },
                {
                    "wild father tree among universe such mobile favorite target dynamic * identify",
                    Array.IndexOf(MissingChars, '*'),
                    0, // WordList
                    1, // MnemonicType
                    2, // Electrum mnemonic type
                    null,
                    "m/0'/0/0",
                    "bc1q4794m2uuw9jmjszmplfj4wvvr5j272fpnx2cse",
                    0,
                    $"Electrum test vectors.{Environment.NewLine}" +
                    $"This example is missing 1 word (credit).{Environment.NewLine}" +
                    $"Note the usage of Electrum mnemonic type which mandates selecting an Electrum mnemonic type " +
                    $"(SegWit here).{Environment.NewLine}" +
                    $"Estimated time: <1 sec"
                },
                {
                    "wild father tree among universe such * favorite target dynamic * identify",
                    Array.IndexOf(MissingChars, '*'),
                    0, // WordList
                    1, // MnemonicType
                    2, // Electrum mnemonic type
                    null,
                    "m/0'/0/0",
                    "bc1q4794m2uuw9jmjszmplfj4wvvr5j272fpnx2cse",
                    0,
                    $"Electrum test vectors.{Environment.NewLine}" +
                    $"This example is missing 2 words (mobile, credit).{Environment.NewLine}" +
                    $"Note the multi-thread usage (parallelism).{Environment.NewLine}" +
                    $"Estimated time: <1 sec"
                },
            };
        }
    }
}
