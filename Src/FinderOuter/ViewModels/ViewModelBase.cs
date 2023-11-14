// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Models;
using FinderOuter.Services;
using ReactiveUI;
using System;

namespace FinderOuter.ViewModels
{
    public class ViewModelBase : ReactiveObject
    {
        public ViewModelBase(IWindowManager winMan = null)
        {
            WinMan = winMan ?? new WindowManager();
            OpenKBCommand = ReactiveCommand.Create<KB>(OpenKB);
        }

        public event EventHandler CLoseEvent;

        public void RaiseCloseEvent() => CLoseEvent?.Invoke(this, null);

        // Don't change to static, it will break the OpenKB(KB) method
#pragma warning disable CA1822 // Mark members as static
        public KB InputKb => KB.DamagedInput;
        public KB ExtraInputKb => KB.ExtraInput;
        public KB Bip32PathKb => KB.Bip32Path;
        public KB AlphanumericPassKb => KB.AlphanumericPass;
        public KB CustomCharPassKb => KB.CustomCharPass;
        public KB ThreadKb => KB.ThreadCount;
#pragma warning restore CA1822 // Mark members as static

        public IWindowManager WinMan { get; }
        public IReactiveCommand OpenKBCommand { get; }
        public void OpenKB(KB kb) => WinMan.ShowDialog(new KnowledgeBaseViewModel(kb));
    }
}
