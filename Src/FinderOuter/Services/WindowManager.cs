// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using FinderOuter.ViewModels;

namespace FinderOuter.Services
{
    public interface IWindowManager
    {
        void ShowDialog(VmWithSizeBase vm);
    }


    public class WindowManager : IWindowManager
    {
        public void ShowDialog(VmWithSizeBase vm)
        {
            Window win = new Window()
            {
                Content = vm,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                CanResize = false,
                Width = vm.Width,
                Height = vm.Height,
                Title = vm.GetType().Name.Replace("ViewModel", ""),
            };

            var lf = (IClassicDesktopStyleApplicationLifetime)Application.Current.ApplicationLifetime;

            win.ShowDialog(lf.MainWindow);
        }
    }
}
