// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using FinderOuter.Models;
using System;
using System.IO;
using System.Threading.Tasks;

namespace FinderOuter.Services
{
    public interface IFileManager
    {
        public Task<string[]> OpenAsync();
    }



    public class FileManager : IFileManager
    {
        public IWindowManager WinMan { get; set; } = new WindowManager();

        public async Task<string[]> OpenAsync()
        {
            OpenFileDialog dialog = new()
            {
                AllowMultiple = false,
            };
            dialog.Filters.Add(new FileDialogFilter() { Name = "Text files (.txt)", Extensions = { "txt" } });

            try
            {
                var lf = (IClassicDesktopStyleApplicationLifetime)Application.Current.ApplicationLifetime;
                string[] dir = await dialog.ShowAsync(lf.MainWindow);
                if (dir != null && dir.Length > 0)
                {
                    return File.ReadAllLines(dir[0]);
                }
            }
            catch (Exception ex)
            {
                await WinMan.ShowMessageBox(MessageBoxType.Ok, ex.Message);
            }
            return Array.Empty<string>();
        }
    }
}
