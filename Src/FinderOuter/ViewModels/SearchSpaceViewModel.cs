// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.ImprovementProposals;
using ReactiveUI;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;

namespace FinderOuter.ViewModels
{
    public class SearchSpaceViewModel : VmWithSizeBase
    {
        public SearchSpaceViewModel()
        {
            Width = 800;
            Height = 350;

            IObservable<bool> isNextEnabled = this.WhenAnyValue(x => x.Index, x => x.Max, (i, max) => i < max);
            IObservable<bool> isPrevEnabled = this.WhenAnyValue(x => x.Index, x => x.Max, (i, max) => i > 1);

            NextCommand = ReactiveCommand.Create(Next, isNextEnabled);
            PreviousCommand = ReactiveCommand.Create(Previous, isPrevEnabled);
        }


        private string _input;
        public string Input
        {
            get => _input;
            set => this.RaiseAndSetIfChanged(ref _input, value);
        }

        private string _state = "0/0";
        public string State
        {
            get => _state;
            set => this.RaiseAndSetIfChanged(ref _state, value);
        }

        private string _err;
        public string Error
        {
            get => _err;
            set => this.RaiseAndSetIfChanged(ref _err, value);
        }

        private int _index;
        public int Index
        {
            get => _index;
            private set
            {
                if (_index != value)
                {
                    this.RaiseAndSetIfChanged(ref _index, value);
                    CurrentItems = result[value - 1];
                    State = $"{value}/{Max}";
                }
            }
        }

        private int _max;
        public int Max
        {
            get => _max;
            private set => this.RaiseAndSetIfChanged(ref _max, value);
        }


        private string _custom;
        public string CustomWord
        {
            get => _custom;
            set => this.RaiseAndSetIfChanged(ref _custom, value);
        }

        private string _start;
        public string StartChars
        {
            get => _start;
            set => this.RaiseAndSetIfChanged(ref _start, value);
        }

        private string _end;
        public string EndChars
        {
            get => _end;
            set => this.RaiseAndSetIfChanged(ref _end, value);
        }

        private string _contain;
        public string ContainChars
        {
            get => _contain;
            set => this.RaiseAndSetIfChanged(ref _contain, value);
        }

        private ObservableCollection<string> _items;
        public ObservableCollection<string> CurrentItems
        {
            get => _items;
            private set => this.RaiseAndSetIfChanged(ref _items, value);
        }

        private ObservableCollection<string>[] result;

        public void Start()
        {
            if (string.IsNullOrWhiteSpace(Input))
            {
                Error = "Enter something first.";
            }
            else if (string.IsNullOrWhiteSpace(Input))
            {
                Error = "Mnemonic can not be null or empty.";
            }
            else
            {
                // TODO: get W.L. as variable
                string[] allWords = BIP0039.GetAllWords(BIP0039.WordLists.English);
                string[] words = Input.Split(new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                if (!new[] { 12, 15, 18, 21, 24 }.Contains(words.Length))
                {
                    Error = "Invalid mnemonic length.";
                    return;
                }

                string missCharStr = new(new char[] { '*' });
                bool invalidWord = false;
                for (int i = 0; i < words.Length; i++)
                {
                    if (words[i] != missCharStr && !allWords.Contains(words[i]))
                    {
                        invalidWord = true;
                        Error += $"Given mnemonic contains invalid word at index {i} ({words[i]}).";
                    }
                }
                if (invalidWord)
                {
                    return;
                }

                int missCount = words.Count(s => s == missCharStr);
                result = new ObservableCollection<string>[missCount];
                for (int i = 0; i < result.Length; i++)
                {
                    result[i] = new();
                }
                Max = result.Length;
                Index = 1;
            }
        }


        public IReactiveCommand NextCommand { get; }
        public void Next()
        {
            Index++;
        }

        public IReactiveCommand PreviousCommand { get; }
        public void Previous()
        {
            Index--;
        }

        private void Add(IEnumerable<string> items)
        {
            foreach (var item in items)
            {
                if (!CurrentItems.Contains(item))
                {
                    CurrentItems.Add(item);
                }
            }
        }

        public void ClearAll()
        {
            CurrentItems.Clear();
        }

        public void AddAll()
        {
            Add(BIP0039.GetAllWords(BIP0039.WordLists.English));
        }

        public void AddCustom()
        {
            CurrentItems.Add(CustomWord);
        }

        public void AddStart()
        {
            Add(BIP0039.GetAllWords(BIP0039.WordLists.English).Where(x => x.StartsWith(StartChars)));
        }

        public void AddEnd()
        {
            Add(BIP0039.GetAllWords(BIP0039.WordLists.English).Where(x => x.EndsWith(EndChars)));
        }

        public void AddContain()
        {
            Add(BIP0039.GetAllWords(BIP0039.WordLists.English).Where(x => x.Contains(ContainChars)));
        }

    }
}
