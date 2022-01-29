// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace FinderOuter.Views
{
    public partial class MissingBip38PassView : UserControl
    {
        public MissingBip38PassView() => InitializeComponent();
        private void InitializeComponent() => AvaloniaXamlLoader.Load(this);
    }
}
