// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Models;
using FinderOuter.Services;
using ReactiveUI;
using System;
using System.Collections.Generic;
using System.ComponentModel;
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
                new MissingBip38PassViewModel(),
                new MissingMnemonicViewModel(),
                new MissingMnemonicPassViewModel(),
                new MissingBip32PathViewModel(),
                new MissingArmoryViewModel(),
                new MissingEncodingViewModel(),
            };

            WinMan = new WindowManager();
        }

        private static Version Version => Assembly.GetExecutingAssembly().GetName().Version;

        public static string WindowTitle => $"The FinderOuter - Version {((Version.Major == 0) ? "Beta" : Version.ToString(2))}";

        public static string VerString => Version.ToString(4);

        public static string DebugWarning => "Warning: Debug mode detected. Build and run in release mode for faster performance.";

        public static bool IsDebug =>
#if DEBUG
                true;
#else
                false;
#endif

        public static string UnstableWarning => "Warning: You are running an unstable version. Make sure you understand the changes " +
            "after the previous stable release.";

        public static bool IsUnstable => Version.Revision != 0;


        public bool IsOptionSelected => SelectedOption is not null;

        public bool IsWorking => SelectedOption is not null && SelectedOption.Result.CurrentState == State.Working;

        public IEnumerable<OptionVmBase> OptionList { get; private set; }

        private OptionVmBase _selOpt;
        public OptionVmBase SelectedOption
        {
            get => _selOpt;
            private set
            {
                if (value is not null)
                {
                    value.Result.PropertyChanged += SelectedOption_PropertyChanged;
                }
                else
                {
                    _selOpt.Result.PropertyChanged -= SelectedOption_PropertyChanged;
                }

                this.RaiseAndSetIfChanged(ref _selOpt, value);
                this.RaisePropertyChanged(nameof(IsOptionSelected));
                this.RaisePropertyChanged(nameof(IsWorking));
            }
        }

        private void SelectedOption_PropertyChanged(object sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName == nameof(OptionVmBase.Result.CurrentState))
            {
                this.RaisePropertyChanged(nameof(IsWorking));
            }
        }

        public HelpViewModel HelpVm => new();

        public IWindowManager WinMan { get; set; }

        public void OpenAbout() => WinMan.ShowDialog(new AboutViewModel());
    }
}
