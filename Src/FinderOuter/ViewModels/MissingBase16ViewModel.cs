// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend;
using FinderOuter.Services;
using ReactiveUI;
using System;

namespace FinderOuter.ViewModels
{
    public class MissingBase16ViewModel : OptionVmBase
    {
        public MissingBase16ViewModel()
        {
            // Don't move this line, service must be instantiated here
            b16Service = new Base16Sevice(Result);

            IObservable<bool> isFindEnabled = this.WhenAnyValue(
                x => x.Input, x => x.MissingChar,
                x => x.Result.CurrentState, (b58, c, state) =>
                            !string.IsNullOrEmpty(b58) &&
                            b16Service.IsMissingCharValid(c) &&
                            state != Models.State.Working);

            FindCommand = ReactiveCommand.Create(Find, isFindEnabled);
        }



        public override string OptionName => "Missing Base16";
        public override string Description => $"Helps you recover missing Base-16 (hexadecimal) characters in private keys. " +
            $"Since unlike WIF (Base-58) this format has no checksum you will have to enter an additional data to check each " +
            $"result with. Currently only an address is accepted." +
            $"{Environment.NewLine}" +
            $"Enter the base-16 string and replace its missing characters with the symbol defined by {nameof(MissingChar)} " +
            $"parameter and press Find.";


        private readonly Base16Sevice b16Service;

        private string _input;
        public string Input
        {
            get => _input;
            set => this.RaiseAndSetIfChanged(ref _input, value);
        }

        private string _input2;
        public string AdditionalInput
        {
            get => _input2;
            set => this.RaiseAndSetIfChanged(ref _input2, value);
        }

        private bool _isComp = true;
        public bool IsCompressed
        {
            get => _isComp;
            set => this.RaiseAndSetIfChanged(ref _isComp, value);
        }

        private char _mis = '*';
        public char MissingChar
        {
            get => _mis;
            set => this.RaiseAndSetIfChanged(ref _mis, value);
        }


        public string MissingToolTip => $"Choose one of these symbols {Constants.Symbols} to use instead of the missing characters";

        public override void Find()
        {
            _ = b16Service.Find(Input, MissingChar, AdditionalInput, IsCompressed);
        }
    }
}
