// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend;
using FinderOuter.Models;
using FinderOuter.Services;
using ReactiveUI;
using System.Collections.Generic;
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
        }


        public abstract string OptionName { get; }
        public abstract string Description { get; }

        private string _exName = "";
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

        public string MissingToolTip => ConstantsFO.MissingToolTip;

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


        public KB InputKb => KB.DamagedInput;
        public KB ExtraInputKb => KB.ExtraInput;
        public KB Bip32PathKb => KB.Bip32Path;
        public KB AlphanumericPassKb => KB.AlphanumericPass;
        public KB CustomCharPassKb => KB.CustomCharPass;
        public IWindowManager WinMan { get; set; }
        public void OpenKB(KB kb) => WinMan.ShowDialog(new KnowledgeBaseViewModel(kb));
    }
}
