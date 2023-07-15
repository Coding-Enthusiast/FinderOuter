// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Avalonia.Data.Converters;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using FinderOuter.Models;
using System;
using System.Globalization;
using System.IO;

namespace FinderOuter.Backend.Mvvm.Converters
{
    public class StateToBitmapConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is State state)
            {
                Uri uri = state switch
                {
                    State.Ready => new Uri($"avares://FinderOuter/Assets/StatReady.png"),
                    State.Working => new Uri($"avares://FinderOuter/Assets/StatWorking.png"),
                    State.Paused => new Uri($"avares://FinderOuter/Assets/StatPause.png"),
                    State.Stopped => new Uri($"avares://FinderOuter/Assets/StatStop.png"),
                    State.FinishedSuccess => new Uri($"avares://FinderOuter/Assets/StatSuccess.png"),
                    State.FinishedFail => new Uri($"avares://FinderOuter/Assets/StatFail.png"),
                    _ => throw new NotImplementedException()
                };

                using Stream asset = AssetLoader.Open(uri);
                return new Bitmap(asset);
            }

            throw new NotSupportedException();
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException();
        }
    }
}
