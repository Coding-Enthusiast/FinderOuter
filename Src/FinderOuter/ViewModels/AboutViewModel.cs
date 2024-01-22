// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Avalonia.Input.Platform;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;

namespace FinderOuter.ViewModels
{
    public class AboutViewModel : VmWithSizeBase
    {
        // Makes designer happy!
        public AboutViewModel()
        {
        }

        public AboutViewModel(IClipboard clipboard)
        {
            Clipboard = clipboard;
            // Window size has to be set or the new window that is build with WindowManager 
            // is going to have the same size as MainWindow
            Width = 600;
            Height = 400;
        }


        public IClipboard Clipboard { get; set; }
        public string NameAndVersion => $"The FinderOuter {Assembly.GetExecutingAssembly().GetName().Version.ToString(4)}";
        public string SourceLink => "https://github.com/Coding-Enthusiast/FinderOuter";
        public string BitcointalkLink => "";
        public string AvaloniaLink => "https://avaloniaui.net/";
        public string DonationUri1 => $"bitcoin:{DonationAddr1}{Bip21Extras}";
        public string DonationAddr1 => "1Q9swRQuwhTtjZZ2yguFWk7m7pszknkWyk";
        public string DonationUri2 => $"bitcoin:{DonationAddr2}{Bip21Extras}";
        public string DonationAddr2 => "bc1q3n5t9gv40ayq68nwf0yth49dt5c799wpld376s";

        private const string Bip21Extras = "?label=Coding-Enthusiast&message=Donation%20for%20FinderOuter%20project";

        public async void Copy(int i)
        {
            if (Clipboard is not null)
            {
                await Clipboard.SetTextAsync(i == 1 ? DonationAddr1 : DonationAddr2);
            }
        }
        public void Copy1() => Copy(1);
        public void Copy2() => Copy(2);

        // Taken from avalonia source code
        // https://github.com/AvaloniaUI/Avalonia/blob/4340831f29c2dda00cfc3993303921272fedfc61/src/Avalonia.Dialogs/AboutAvaloniaDialog.xaml
        public void OpenBrowser(string url)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                // If no associated application/json MimeType is found xdg-open opens retrun error
                // but it tries to open it anyway using the console editor (nano, vim, other..)
                ShellExec($"xdg-open {url}", false);
            }
            else
            {
                using Process process = Process.Start(
                    new ProcessStartInfo
                    {
                        FileName = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? url : "open",
                        Arguments = RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? $"-e {url}" : "",
                        CreateNoWindow = true,
                        UseShellExecute = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                    });
            }
        }

        private static void ShellExec(string cmd, bool waitForExit = true)
        {
            string escapedArgs = cmd.Replace("\"", "\\\"");

            using Process process = Process.Start(
                new ProcessStartInfo
                {
                    FileName = "/bin/sh",
                    Arguments = $"-c \"{escapedArgs}\"",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden
                }
            );
            if (waitForExit)
            {
                process.WaitForExit();
            }
        }
    }
}
