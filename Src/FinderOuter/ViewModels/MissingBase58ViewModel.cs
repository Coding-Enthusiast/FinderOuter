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
    public class MissingBase58ViewModel : OptionVmBase
    {
        public MissingBase58ViewModel()
        {
            // Don't move this line, service must be instantiated here
            b58Service = new Base58Sevice(Result);

            IObservable<bool> isFindEnabled = this.WhenAnyValue(
                x => x.Input, x => x.MissingChar,
                x => x.Result.CurrentState, (b58, c, state) =>
                            !string.IsNullOrEmpty(b58) &&
                            b58Service.IsMissingCharValid(c) &&
                            state != Models.State.Working);

            FindCommand = ReactiveCommand.Create(Find, isFindEnabled);
        }



        public override string OptionName => "Missing Base58";
        public override string Description => $"Helps you recover missing base-58 characters in any base-58 encoded strings that " +
            $"has a checksum. Examples are private keys, extended pub/priv keys, addresses,...{Environment.NewLine}" +
            $"Enter the base-58 string and replace its missing characters with the symbol defined by {nameof(MissingChar)} " +
            $"parameter and press Find.";


        private readonly Base58Sevice b58Service;

        private string _input;
        public string Input
        {
            get => _input;
            set => this.RaiseAndSetIfChanged(ref _input, value);
        }

        private char _mis = '*';
        public char MissingChar
        {
            get => _mis;
            set => this.RaiseAndSetIfChanged(ref _mis, value);
        }

        private bool _isSpecial;
        public bool IsSpecialCase
        {
            get => _isSpecial;
            set => this.RaiseAndSetIfChanged(ref _isSpecial, value);
        }

        public string MissingToolTip => $"Choose one of these symbols {Constants.Symbols} to use instead of the missing characters";
        public string SpecialToolTip => "Select this for a special case where you have a compressed private key that is missing " +
            "exactly 3 characters and you don't know their locations.";

        public override void Find()
        {
            if (IsSpecialCase)
            {
                _ = b58Service.FindUnknownLocation(Input);
            }
            else
            {
                _ = b58Service.Find(Input, MissingChar);
            }
        }
    }
}
