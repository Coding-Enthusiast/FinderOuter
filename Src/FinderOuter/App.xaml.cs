// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using FinderOuter.ViewModels;
using FinderOuter.Views;

namespace FinderOuter
{
    public class App : Application
    {
        public override void Initialize()
        {
            AvaloniaXamlLoader.Load(this);
        }

        public override void OnFrameworkInitializationCompleted()
        {
            if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            {
                MainWindowViewModel vm = new();
                desktop.MainWindow = new MainWindow
                {
                    DataContext = vm
                };
                vm.Clipboard = desktop.MainWindow.Clipboard;
                vm.StorageProvider = desktop.MainWindow.StorageProvider;
            }

            base.OnFrameworkInitializationCompleted();
        }
    }
}
