// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Avalonia.Data.Converters;
using FinderOuter.Models;
using System;
using System.Globalization;

namespace FinderOuter.Backend.Mvvm.Converters
{
    public class PossibilityToStringConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is Possibility p)
            {
                return p switch
                {
                    Possibility.Possible => "✔",
                    Possibility.Impossible => "X",
                    Possibility.Maybe => "?",
                    _ => throw new NotImplementedException(),
                };
            }

            throw new NotSupportedException();
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotSupportedException();
        }
    }
}
