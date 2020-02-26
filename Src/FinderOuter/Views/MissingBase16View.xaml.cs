using Avalonia;
using Avalonia.Controls;
using Avalonia.Markup.Xaml;

namespace FinderOuter.Views
{
    public class MissingBase16View : UserControl
    {
        public MissingBase16View()
        {
            this.InitializeComponent();
        }

        private void InitializeComponent()
        {
            AvaloniaXamlLoader.Load(this);
        }
    }
}
