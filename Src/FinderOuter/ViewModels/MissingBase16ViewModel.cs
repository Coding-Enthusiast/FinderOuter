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
                            state != State.Working);

            FindCommand = ReactiveCommand.Create(Find, isFindEnabled);

            HasExample = true;
            IObservable<bool> isExampleVisible = this.WhenAnyValue(
                x => x.Result.CurrentState,
                (state) => state != State.Working);
            ExampleCommand = ReactiveCommand.Create(Example, isExampleVisible);
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


        public override void Find()
        {
            _ = b16Service.Find(Input, MissingChar, AdditionalInput, IsCompressed);
        }


        public void Example()
        {
            int total = 2;

            switch (exampleIndex)
            {
                case 0:
                    Input = "0c28fca386c7a227600b2fe50b7cae11ec86d3b*1fbe471be89827e19d72aa1d";
                    MissingChar = '*';
                    AdditionalInput = "1LoVGDgRs9hTfTNJNuXKSpywcbdvwRXpmK";

                    Result.Message = $"This is example 1 out of {total} taken from bitcoin wiki.{Environment.NewLine}" +
                                     $"It is missing one character (f) and it should take <1 second to find it.";
                    break;
                case 1:
                    Input = "0c28fca386c7a227600?2fe50b7cae11ec?6d3b?1fbe471be89827e19d72aa1d";
                    MissingChar = '?';
                    AdditionalInput = "1LoVGDgRs9hTfTNJNuXKSpywcbdvwRXpmK";

                    Result.Message = $"This is example 2 out of {total} taken from bitcoin wiki.{Environment.NewLine}" +
                                     $"It is missing three character (b, 8, f) and it should take <1 min to find it." +
                                     $"{Environment.NewLine}It also shows how to use a different missing character.";
                    break;

                default:
                    Result.Message = "Invalid example index was given (this is a bug).";
                    break;
            }

            exampleIndex++;
            if (exampleIndex >= total)
            {
                exampleIndex = 0;
            }
        }
    }
}
