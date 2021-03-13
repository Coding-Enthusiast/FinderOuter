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
                new MessageSignatureViewModel(),
                new MissingBase58ViewModel(),
                new MissingBase16ViewModel(),
                new MissingMiniPrivateKeyViewModel(),
                new MissingMnemonicViewModel(),
                new MissingBip32PathViewModel(),
                new MissingArmoryViewModel(),
            };

            WinMan = new WindowManager();
        }



        public static string WindowTitle
        {
            get
            {
                Version ver = Assembly.GetExecutingAssembly().GetName().Version;
                return $"The FinderOuter - Version {((ver.Major == 0) ? "Beta" : ver.ToString(2))}";
            }
        }

        public static string VerString => Assembly.GetExecutingAssembly().GetName().Version.ToString(4);


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


        public bool IsDebug
        {
            get
            {
#if DEBUG
                return true;
#else
                return false;
#endif
            }
        }

        public string DebugWarning => "Warning: Debug mode detected. Build and run in release mode for faster performance.";

        public bool IsFindButtonVisible => SelectedOption != null;


        public IWindowManager WinMan { get; set; }

        public void OpenAbout() => WinMan.ShowDialog(new AboutViewModel());
        public void OpenHelp() => WinMan.ShowDialog(new HelpViewModel());
    }
}
