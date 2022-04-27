// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using ReactiveUI;
using System;

namespace FinderOuter.ViewModels
{
    public class ViewModelBase : ReactiveObject
    {
        public event EventHandler CLoseEvent;

        public void RaiseCloseEvent() => CLoseEvent?.Invoke(this, null);
    }
}
