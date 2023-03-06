// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Models;
using FinderOuter.Services;
using ReactiveUI;
using System;
using System.Collections.Generic;
using System.Linq;

namespace FinderOuter.ViewModels
{
    public class MissingBase16ViewModel : OptionVmBase
    {
        public MissingBase16ViewModel()
        {
            // Don't move this line, service must be instantiated here
            b16Service = new Base16Sevice(Result);
            var inServ = new InputService();

            IObservable<bool> isFindEnabled = this.WhenAnyValue(
                x => x.Input, x => x.MissingChar,
                x => x.Result.CurrentState, (b58, c, state) =>
                            !string.IsNullOrEmpty(b58) &&
                            inServ.IsMissingCharValid(c) &&
                            state != State.Working);

            FindCommand = ReactiveCommand.Create(Find, isFindEnabled);
            ExtraInputTypeList = ListHelper.GetEnumDescItems(InputType.PrivateKey).ToArray();
            SelectedExtraInputType = ExtraInputTypeList.First();

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

        public IEnumerable<DescriptiveItem<InputType>> ExtraInputTypeList { get; }

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

        private DescriptiveItem<InputType> _selInpT2;
        public DescriptiveItem<InputType> SelectedExtraInputType
        {
            get => _selInpT2;
            set => this.RaiseAndSetIfChanged(ref _selInpT2, value);
        }

        private char _mis = '*';
        public char MissingChar
        {
            get => _mis;
            set => this.RaiseAndSetIfChanged(ref _mis, value);
        }


        public override void Find()
        {
            b16Service.Find(Input, MissingChar, AdditionalInput, SelectedExtraInputType.Value);
        }


        public void Example()
        {
            int total = 1;

            switch (exampleIndex)
            {
                case 0:
                    Input = "5122211a1006efec97f3a354d5d2e*3995fe952*c9e7fead55316fb3eabc868e";
                    MissingChar = '*';
                    AdditionalInput = "TF37R6dCk39jmuD8YvbXT2WPpwU2tBm39h";
                    SelectedExtraInputType = ExtraInputTypeList.First();
                    Result.Message = $"This is example 1 out of {total} taken from bitcoin wiki.{Environment.NewLine}" +
                                     $"It is missing two character (2, c) and it should take <1 second to find it.";
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
