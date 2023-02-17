// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Avalonia.Data.Converters;
using Avalonia.Media;
using FinderOuter.Models;
using System;
using System.Globalization;

namespace FinderOuter.Backend.Mvvm.Converters
{
    public class PossibilityToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is Possibility p)
            {
                return p switch
                {
                    Possibility.Maybe => Brushes.Blue,
                    Possibility.Possible => Brushes.Green,
                    Possibility.Impossible => Brushes.Red,
                    _ => throw new NotImplementedException(),
                };
            }

            throw new NotSupportedException();
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
