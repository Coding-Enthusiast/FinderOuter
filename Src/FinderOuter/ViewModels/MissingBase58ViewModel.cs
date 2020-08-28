// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend;
using FinderOuter.Models;
using FinderOuter.Services;
using ReactiveUI;
using System;
using System.Collections.Generic;
using System.Linq;

namespace FinderOuter.ViewModels
{
    public class MissingBase58ViewModel : OptionVmBase
    {
        public MissingBase58ViewModel()
        {
            // Don't move this line, service must be instantiated here
            InputService inServ = new InputService();
            b58Service = new Base58Sevice(Result);

            IObservable<bool> isFindEnabled = this.WhenAnyValue(
                x => x.Input, x => x.MissingChar,
                x => x.Result.CurrentState, (b58, c, state) =>
                            !string.IsNullOrEmpty(b58) &&
                            inServ.IsMissingCharValid(c) &&
                            state != State.Working);

            FindCommand = ReactiveCommand.Create(Find, isFindEnabled);
            InputTypeList = ListHelper.GetAllEnumValues<Base58Sevice.InputType>();
            ExtraInputTypeList = ListHelper.GetEnumDescItems<InputType>(InputType.PrivateKey).ToArray();
            SelectedExtraInputType = ExtraInputTypeList.First();

            HasExample = true;
            IObservable<bool> isExampleVisible = this.WhenAnyValue(
                x => x.Result.CurrentState,
                (state) => state != State.Working);
            ExampleCommand = ReactiveCommand.Create(Example, isExampleVisible);
        }



        public override string OptionName => "Missing Base58";
        public override string Description => $"If you have a base-58 encoded string with a checksum (such as private key WIFs) " +
            $"that is missing some characters and you know the location of these missing characters (eg. a damaged paper wallet) " +
            $"you can use this option to recover it.{Environment.NewLine}" +
            $"All you have to do is to enter the base-58 string below and replace its missing characters with the symbol " +
            $"defined by {nameof(MissingChar)} parameter and press Find.{Environment.NewLine}" +
            $"Exception: if you have a compressed private key missing 3 characters, there is no need to use " +
            $"{nameof(MissingChar)} parameter anymore, just enter the {ConstantsFO.PrivKeyCompWifLen - 3} characters you have" +
            $" and press find.";


        private readonly Base58Sevice b58Service;

        public IEnumerable<Base58Sevice.InputType> InputTypeList { get; private set; }
        public IEnumerable<DescriptiveItem<InputType>> ExtraInputTypeList { get; }

        private Base58Sevice.InputType _selInpT;
        public Base58Sevice.InputType SelectedInputType
        {
            get => _selInpT;
            set => this.RaiseAndSetIfChanged(ref _selInpT, value);
        }

        private string _input;
        public string Input
        {
            get => _input;
            set => this.RaiseAndSetIfChanged(ref _input, value);
        }

        private DescriptiveItem<InputType> _selInpT2;
        public DescriptiveItem<InputType> SelectedExtraInputType
        {
            get => _selInpT2;
            set => this.RaiseAndSetIfChanged(ref _selInpT2, value);
        }

        private string _input2;
        public string ExtraInput
        {
            get => _input2;
            set => this.RaiseAndSetIfChanged(ref _input2, value);
        }

        private char _mis = '*';
        public char MissingChar
        {
            get => _mis;
            set => this.RaiseAndSetIfChanged(ref _mis, value);
        }


        public override void Find()
        {
            b58Service.Find(Input, MissingChar, SelectedInputType, ExtraInput, SelectedExtraInputType.Value);
        }

        public void Example()
        {
            int total = 5;

            switch (exampleIndex)
            {
                case 0:
                    Input = "5Kb8kLf9zgWQn*gidDA76*zPL6TsZZY36h**MssSzNydYXYB9KF";
                    MissingChar = '*';
                    SelectedInputType = InputTypeList.First();

                    Result.Message = $"This is example 1 out of {total} taken from bitcoin wiki.{Environment.NewLine}" +
                                     $"It is an uncompressed private key missing 4 character (o, M, W, X) and it " +
                                     $"should take <1 second to find the correct key and <10 seconds to check " +
                                     $"all possible keys.";
                    break;
                case 1:
                    Input = "L53fCHmQh??p1B4JipfBtfeHZH7cAib?G9oK19?fiFzxHgAkz6JK";
                    MissingChar = '?';
                    SelectedInputType = InputTypeList.First();

                    Result.Message = $"This is example 2 out of {total} taken from bitcoin wiki.{Environment.NewLine}" +
                                     $"It is a compressed private key missing 4 character (b, N, z, X) and it " +
                                     $"should take <1 second to find the correct key and <10 seconds to check " +
                                     $"all possible keys.{Environment.NewLine}" +
                                     $"Note the usage of a different missing character.";
                    break;
                case 2:
                    Input = "142viJrTYHA4TzryiEiuQkYk4Ay5Tfp***";
                    MissingChar = '*';
                    SelectedInputType = InputTypeList.ElementAt(1);

                    Result.Message = $"This is example 3 out of {total} taken from Bitcoin.Net test vectors.{Environment.NewLine}" +
                                     $"It is an address missing 3 character (z, q, W) and it should take <1 second to search " +
                                     $"all possible addresses and find the correct one.";
                    break;
                case 3:
                    Input = "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5**DGhwP4*5o44cvXdoY7sRzhtp**o";
                    MissingChar = '*';
                    SelectedInputType = InputTypeList.ElementAt(2);

                    Result.Message = $"This is example 4 out of {total} taken from BIP-38.{Environment.NewLine}" +
                                     $"It is a BIP-38 encrypted private key missing 5 character (s, 6, J, U, e) and it " +
                                     $"should take ~5 minutes to find the correct key and ~8 minutes to search " +
                                     $"all possible keys.";
                    break;
                case 4:
                    Input = "L53fCHmQhbNp1B4JipfBtfeHZHcAibzG9oK9XfiFzxHAkz6JK";
                    MissingChar = '*';
                    SelectedInputType = InputTypeList.First();

                    Result.Message = $"This is example 5 out of {total} taken from bitcoin wiki.{Environment.NewLine}" +
                                     $"It is a compressed private key missing 3 characters at unknown positions " +
                                     $"should take ~2 minutes to find the correct key and ~3 minutes to search " +
                                     $"all possible keys.";
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
