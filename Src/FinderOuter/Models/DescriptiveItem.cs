// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.ViewModels;
using System;
using System.ComponentModel;
using System.Reflection;

namespace FinderOuter.Models
{
    public class DescriptiveItem<T> where T : Enum
    {
        public DescriptiveItem(T value)
        {
            Value = value;

            FieldInfo fi = value.GetType().GetField(value.ToString());
            object[] attributes = fi?.GetCustomAttributes(typeof(DescriptionAttribute), false);
            Description = (attributes != null && attributes.Length != 0) ?
                                                                ((DescriptionAttribute)attributes[0]).Description :
                                                                value.ToString();
        }

        public string Description { get; set; }
        public T Value { get; set; }
    }

    public class DescriptiveHelpInput(HelpInputTypes value) : DescriptiveItem<HelpInputTypes>(value)
    {
    }

    public class DescriptiveHelpInput2(HelpSecondInputTypes value) : DescriptiveItem<HelpSecondInputTypes>(value)
    {
    }

    public class DescriptiveKB(KB value): DescriptiveItem<KB>(value)
    {
    }
}
