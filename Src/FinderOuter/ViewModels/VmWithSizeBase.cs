// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using ReactiveUI;

namespace FinderOuter.ViewModels
{
    /// <summary>
    /// Base (abstract) class for view models that have to be shown in a new window 
    /// and need to set the window's height and width.
    /// </summary>
    public abstract class VmWithSizeBase : ViewModelBase
    {
        private double _height;
        public double Height
        {
            get => _height;
            set => this.RaiseAndSetIfChanged(ref _height, value);
        }

        private double _width;
        public double Width
        {
            get => _width;
            set => this.RaiseAndSetIfChanged(ref _width, value);
        }
    }
}
