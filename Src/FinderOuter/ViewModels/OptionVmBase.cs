// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend;
using FinderOuter.Models;
using FinderOuter.Services;
using ReactiveUI;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;

namespace FinderOuter.ViewModels
{
    /// <summary>
    /// Base (abstract) class for view models that are supposed to be shown in the list of "options" in main window.
    /// </summary>
    public abstract class OptionVmBase : ViewModelBase
    {
        public OptionVmBase()
        {
            WinMan = new WindowManager();
            MissingChars = ConstantsFO.MissingSymbols.ToCharArray();
            SelectedMissingChar = MissingChars[0];

            IObservable<bool> isNextEnabled = this.WhenAnyValue(x => x.Index, x => x.Max, x => x.IsProcessed,
                                                                (i, max, b) => b && i < max);
            IObservable<bool> isPrevEnabled = this.WhenAnyValue(x => x.Index, x => x.Max, x => x.IsProcessed,
                                                                (i, max, b) => b && i > 1);
            IObservable<bool> canRemove = this.WhenAnyValue(x => x.SelectedItem, (s) => !string.IsNullOrEmpty(s));
            IObservable<bool> canAdd = this.WhenAnyValue(x => x.IsProcessed, (b) => b == true);

            NextCommand = ReactiveCommand.Create(Next, isNextEnabled);
            PreviousCommand = ReactiveCommand.Create(Previous, isPrevEnabled);
            RemoveSelectedCommand = ReactiveCommand.Create(RemoveSelected, canRemove);
            ClearAllCommand = ReactiveCommand.Create(ClearAll, canAdd);
        }


        public abstract string OptionName { get; }
        public abstract string Description { get; }
        public char[] MissingChars { get; }

        private char _selMisC;
        public char SelectedMissingChar
        {
            get => _selMisC;
            set => this.RaiseAndSetIfChanged(ref _selMisC, value);
        }


        private string _exName = string.Empty;
        public string ExampleButtonName
        {
            get => _exName;
            set => this.RaiseAndSetIfChanged(ref _exName, value);
        }

        private IReport _res = new Report();
        public IReport Result
        {
            get => _res;
            set => this.RaiseAndSetIfChanged(ref _res, value);
        }

        public static string MissingToolTip => ConstantsFO.MissingToolTip;

        private ObservableCollection<string> _items;
        public ObservableCollection<string> CurrentItems
        {
            get => _items;
            protected set => this.RaiseAndSetIfChanged(ref _items, value);
        }

        private string _selItem;
        public string SelectedItem
        {
            get => _selItem;
            set => this.RaiseAndSetIfChanged(ref _selItem, value);
        }

        protected ObservableCollection<string>[] allItems;

        private string _step;
        public string SelectedStep
        {
            get => _step;
            set => this.RaiseAndSetIfChanged(ref _step, value);
        }


        private int _max;
        public int Max
        {
            get => _max;
            set => this.RaiseAndSetIfChanged(ref _max, value);
        }

        private int _index;
        public int Index
        {
            get => _index;
            protected set
            {
                if (_index != value)
                {
                    this.RaiseAndSetIfChanged(ref _index, value);
                    if (Index == 0)
                    {
                        CurrentItems = null;
                        SelectedStep = string.Empty;
                    }
                    else
                    {
                        CurrentItems = allItems[value - 1];
                        SelectedStep = $"{value}/{Max}";
                    }
                }
            }
        }

        private bool _isProcessed;
        public bool IsProcessed
        {
            get => _isProcessed;
            set => this.RaiseAndSetIfChanged(ref _isProcessed, value);
        }

        protected bool isChanged;

        public IReactiveCommand StartCommand { get; protected set; }

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

        protected bool isCaseSensitive = false;

        private string _toAdd;
        public string ToAdd
        {
            get => _toAdd;
            set => this.RaiseAndSetIfChanged(ref _toAdd, isCaseSensitive ? value : value.ToLowerInvariant().Trim());
        }

        public IReactiveCommand RemoveSelectedCommand { get; }
        private void RemoveSelected()
        {
            CurrentItems.Remove(SelectedItem);
        }

        public IReactiveCommand ClearAllCommand { get; }
        private void ClearAll()
        {
            CurrentItems.Clear();
        }


        public bool HasExample { get; protected set; }
        protected int exampleIndex, totalExampleCount;
        private IEnumerator<object[]> exampleEnumerator;

        protected void SetExamples(ExampleData data)
        {
            HasExample = true;
            totalExampleCount = data.Total;
            exampleEnumerator = data.GetEnumerator();

            ExampleButtonName = $"{totalExampleCount} Examples";
        }

        protected object[] GetNextExample()
        {
            if (exampleEnumerator.MoveNext())
            {
                exampleIndex++;
            }
            else
            {
                exampleIndex = 1;
                exampleEnumerator.Reset();
                exampleEnumerator.MoveNext();
            }

            Debug.Assert(exampleIndex != 0 && exampleIndex <= totalExampleCount);
            Debug.Assert(!(exampleEnumerator.Current is null));

            ExampleButtonName = $"Example {exampleIndex}/{totalExampleCount}";
            return exampleEnumerator.Current;
        }

        public IReactiveCommand ExampleCommand { get; protected set; }

        public IReactiveCommand FindCommand { get; protected set; }
        public abstract void Find();


        public static KB InputKb => KB.DamagedInput;
        public static KB ExtraInputKb => KB.ExtraInput;
        public static KB Bip32PathKb => KB.Bip32Path;
        public static KB AlphanumericPassKb => KB.AlphanumericPass;
        public static KB CustomCharPassKb => KB.CustomCharPass;
        public IWindowManager WinMan { get; set; }
        public void OpenKB(KB kb) => WinMan.ShowDialog(new KnowledgeBaseViewModel(kb));
    }
}
