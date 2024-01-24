// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Models;
using FinderOuter.ViewModels;
using System;
using System.Collections.Generic;
using System.Linq;

namespace FinderOuter
{
    public static class ListHelper
    {
        public static IEnumerable<T> GetAllEnumValues<T>() where T : Enum
        {
            return Enum.GetValues(typeof(T)).Cast<T>();
        }

        public static IEnumerable<DescriptiveItem<T>> GetEnumDescItems<T>(params T[] exclude) where T : Enum
        {
            foreach (T item in Enum.GetValues(typeof(T)))
            {
                if (exclude != null && !exclude.Contains(item))
                {
                    yield return new DescriptiveItem<T>(item);
                }
            }
        }

        public static IEnumerable<DescriptiveHelpInput> GetEnumDescHelpInput()
        {
            foreach (HelpInputTypes item in Enum.GetValues(typeof(HelpInputTypes)))
            {
                yield return new DescriptiveHelpInput(item);
            }
        }

        public static IEnumerable<DescriptiveKB> GetEnumDescKB()
        {
            foreach (KB item in Enum.GetValues(typeof(KB)))
            {
                yield return new DescriptiveKB(item);
            }
        }
    }
}
