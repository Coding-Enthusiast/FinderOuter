// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Avalonia.Platform.Storage;
using FinderOuter.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace FinderOuter.Services
{
    public interface IFileManager
    {
        public Task<string[]> OpenAsync();
        public IStorageProvider StorageProvider { get; set; }
    }



    public class FileManager : IFileManager
    {
        public IWindowManager WinMan { get; set; } = new WindowManager();
        public IStorageProvider StorageProvider { get; set; }

        public async Task<string[]> OpenAsync()
        {
            FilePickerFileType fileType = new("txt")
            {
                Patterns = new string[] { "*.txt" }
            };

            FilePickerOpenOptions options = new()
            {
                AllowMultiple = false,
                FileTypeFilter = new FilePickerFileType[] { fileType },
                Title = "Text files (.txt)"
            };

            try
            {
                IReadOnlyList<IStorageFile> dir = await StorageProvider.OpenFilePickerAsync(options);
                if (dir != null && dir.Count > 0)
                {
                    return File.ReadAllLines(dir.ElementAt(0).Path.LocalPath);
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
