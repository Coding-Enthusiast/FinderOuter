// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Avalonia.Media;
using FinderOuter.Backend;
using FinderOuter.Models;
using FinderOuter.Services;
using ReactiveUI;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;

namespace FinderOuter.ViewModels
{
    /// <summary>
    /// Base (abstract) class for view models that are supposed to be shown in the list of "options" in main window.
    /// </summary>
    public abstract class OptionVmBase : ViewModelBase
    {
        public OptionVmBase() : this(new Report(), new WindowManager())
        {
        }

        public OptionVmBase(IReport report, IWindowManager winMan) : base(winMan)
        {
            Result = report ?? new Report();
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

            IObservable<bool> canPaste = this.WhenAnyValue(x => x.CopiedList, (item) => item != null && item.Length > 0);
            PasteCommand = ReactiveCommand.Create<bool>(Paste, canPaste);
        }


        protected bool isChanged = false;


        public abstract string OptionName { get; }
        public abstract string Description { get; }


        public static string MissingToolTip => ConstantsFO.MissingToolTip;

        public IReport Result { get; }

        public char[] MissingChars { get; }

        private char _selMisC;
        public char SelectedMissingChar
        {
            get => _selMisC;
            set => this.RaiseAndSetIfChanged(ref _selMisC, value);
        }

        private string _input;
        public string Input
        {
            get => _input;
            set
            {
                if (value != _input)
                {
                    this.RaiseAndSetIfChanged(ref _input, value);
                    isChanged = true;
                }
            }
        }

        private string _comp;
        public string CompareInput
        {
            get => _comp;
            set => this.RaiseAndSetIfChanged(ref _comp, value);
        }

        public IEnumerable<DescriptiveItem<CompareInputType>> CompareInputTypeList { get; protected set; }

        private DescriptiveItem<CompareInputType> _selCompType;
        public DescriptiveItem<CompareInputType> SelectedCompareInputType
        {
            get => _selCompType;
            set => this.RaiseAndSetIfChanged(ref _selCompType, value);
        }

        public FontFamily CjkFont => FontFamily.Parse("Microsoft YaHei,Simsun,苹方-简,宋体-简");


        public IReactiveCommand CopyCommand { get; protected set; }
        public IReactiveCommand PasteCommand { get; protected set; }

        private string[] _copied = Array.Empty<string>();
        public string[] CopiedList
        {
            get => _copied;
            set => this.RaiseAndSetIfChanged(ref _copied, value);
        }

        public void Copy()
        {
            if (CurrentItems is not null)
            {
                CopiedList = CurrentItems.ToArray();
            }
        }

        public void Paste(bool replace)
        {
            if (CurrentItems is not null)
            {
                if (replace)
                {
                    CurrentItems.Clear();
                }

                foreach (var item in CopiedList)
                {
                    if (!CurrentItems.Contains(item))
                    {
                        CurrentItems.Add(item);
                    }
                }
            }
        }


        protected ObservableCollection<string>[] allItems = [];

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

        private string _step;
        public string SelectedStep
        {
            get => _step;
            protected set => this.RaiseAndSetIfChanged(ref _step, value);
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
                if (value < 0 || value > allItems?.Length)
                {
                    value = 0;
                }

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

        protected void InitSearchSpace()
        {
            CopiedList = Array.Empty<string>();
            isChanged = false;
            Index = 0;
            Max = 0;
        }

        protected void FinishSearchSpace(int missCount, string error)
        {
            if (IsProcessed)
            {
                allItems = new ObservableCollection<string>[missCount];
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

        protected void ResetSearchSpace()
        {
            CopiedList = Array.Empty<string>();
            Index = 0;
            Max = 0;
            allItems = Array.Empty<ObservableCollection<string>>();
            IsProcessed = false;
        }

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


        private string _toAdd = string.Empty;
        public string ToAdd
        {
            get => _toAdd;
            set => this.RaiseAndSetIfChanged(ref _toAdd, value);
        }

        public IReactiveCommand RemoveSelectedCommand { get; }
        private void RemoveSelected()
        {
            CurrentItems?.Remove(SelectedItem);
        }

        public IReactiveCommand ClearAllCommand { get; }
        private void ClearAll()
        {
            CurrentItems?.Clear();
        }


        public bool HasExample { get; protected set; }
        protected int exampleIndex, totalExampleCount;
        private IEnumerator<object[]> exampleEnumerator;

        private string _exName = string.Empty;
        public string ExampleButtonName
        {
            get => _exName;
            set => this.RaiseAndSetIfChanged(ref _exName, value);
        }

        protected void SetExamples(ExampleData data)
        {
            HasExample = true;
            totalExampleCount = data.Total;
            exampleEnumerator = data.GetEnumerator();

            ExampleButtonName = $"{totalExampleCount} Examples";
        }

        protected object[] GetNextExample()
        {
            Debug.Assert(HasExample);
            Debug.Assert(exampleEnumerator is not null);

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
    }
}
