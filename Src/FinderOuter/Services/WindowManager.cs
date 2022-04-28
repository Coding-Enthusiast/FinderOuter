// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using FinderOuter.Models;
using FinderOuter.ViewModels;
using System.Threading.Tasks;

namespace FinderOuter.Services
{
    public interface IWindowManager
    {
        void ShowDialog(VmWithSizeBase vm);

        Task<MessageBoxResult> ShowMessageBox(MessageBoxType mbType, string message);
    }


    public class WindowManager : IWindowManager
    {
        public void ShowDialog(VmWithSizeBase vm)
        {
            Window win = new()
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


        public async Task<MessageBoxResult> ShowMessageBox(MessageBoxType mbType, string message)
        {
            MessageBoxViewModel vm = new(mbType, message);
            Window win = new()
            {
                Content = vm,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                CanResize = false,
                SizeToContent = SizeToContent.WidthAndHeight,
                Title = "Warning!",
            };
            vm.CLoseEvent += (s, e) => win.Close();

            var lf = (IClassicDesktopStyleApplicationLifetime)Application.Current.ApplicationLifetime;
            await win.ShowDialog(lf.MainWindow);

            return vm.Result;
        }
    }
}
