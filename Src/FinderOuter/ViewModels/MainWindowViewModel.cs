// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Services;
using ReactiveUI;
using System;
using System.Collections.Generic;
using System.Reflection;

namespace FinderOuter.ViewModels
{
    public class MainWindowViewModel : ViewModelBase
    {
        public MainWindowViewModel()
        {
            OptionList = new OptionVmBase[]
            {
                //new MessageSignatureViewModel(),
                //new MissingBase58ViewModel(),
                new MissingBase16ViewModel(),
                //new MissingMiniPrivateKeyViewModel(),
                //new MissingMnemonicViewModel(),
            };

            WinMan = new WindowManager();
        }



        public string WindowTitle
        {
            get
            {
                Version ver = Assembly.GetExecutingAssembly().GetName().Version;
                return $"The FinderOuter - Version {((ver.Major == 0) ? "Beta" : ver.ToString(2))}";
            }
        }

        public string VerString => Assembly.GetExecutingAssembly().GetName().Version.ToString(4);


        public IEnumerable<OptionVmBase> OptionList { get; private set; }


        private OptionVmBase _selOpt;
        public OptionVmBase SelectedOption
        {
            get => _selOpt;
            private set
            {
                this.RaiseAndSetIfChanged(ref _selOpt, value);
                this.RaisePropertyChanged(nameof(IsFindButtonVisible));
            }
        }


        public bool IsFindButtonVisible => SelectedOption != null;


        public IWindowManager WinMan { get; set; }

        public void OpenAbout() => WinMan.ShowDialog(new AboutViewModel());
        public void OpenHelp() => WinMan.ShowDialog(new HelpViewModel());
    }
}
