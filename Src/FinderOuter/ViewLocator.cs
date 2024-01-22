// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Avalonia.Controls;
using Avalonia.Controls.Templates;
using FinderOuter.ViewModels;
using System;

namespace FinderOuter
{
    [Obsolete]
    public class ViewLocator : IDataTemplate
    {
        public bool SupportsRecycling => false;

        public Control Build(object data)
        {
            string name = data.GetType().FullName.Replace("ViewModel", "View");
            Type type = Type.GetType(name);

            if (!(type is null))
            {
                return (Control)Activator.CreateInstance(type);
            }
            else
            {
                return new TextBlock { Text = "Not Found: " + name };
            }
        }

        public bool Match(object data)
        {
            return data is ViewModelBase;
        }
    }
}