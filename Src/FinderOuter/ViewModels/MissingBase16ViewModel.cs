// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Models;
using FinderOuter.Services;
using ReactiveUI;
using System;
using System.Collections.Generic;
using System.Diagnostics;
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

            SetExamples(GetExampleData());
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
            object[] ex = GetNextExample();

            Input = (string)ex[0];
            MissingChar = (char)ex[1];
            AdditionalInput = (string)ex[2];
            int temp = (int)ex[3];
            Debug.Assert(temp <= ExtraInputTypeList.Count());
            SelectedExtraInputType = ExtraInputTypeList.ElementAt(temp);
            Result.Message = $"Example {exampleIndex} of {totalExampleCount}. Source: {(string)ex[4]}";
        }

        private ExampleData GetExampleData()
        {
            return new ExampleData<string, char, string, int, string>()
            {
                {
                    "0c28fca386c7a227600b2fe50b7cae11ec86d3b*1fbe471be89827e19d72aa1d",
                    '*',
                    "1LoVGDgRs9hTfTNJNuXKSpywcbdvwRXpmK",
                    0,
                    $"bitcoin wiki.{Environment.NewLine}" +
                    $"This example is missing one character (f).{Environment.NewLine}" +
                    $"Estimated time: <1 second"
                },
                {
                    "0c28fca386c7a227600?2fe50b7cae11ec?6d3b?1fbe471be89827e19d72aa1d",
                    '?',
                    "1LoVGDgRs9hTfTNJNuXKSpywcbdvwRXpmK",
                    2,
                    $"bitcoin wiki.{Environment.NewLine}" +
                    $"This example is missing three character (b, 8, f).{Environment.NewLine}" +
                    $"Note the usage of a different missing character and input type here.{Environment.NewLine}" +
                    $"Also note the multi-thread usage (parallelism).{Environment.NewLine}" +
                    $"Estimated time: <30 sec"
                },
                {
                    "8e812436a0e3323166e1f0e8ba79e19e217b2c4a53c9*0d4cca0cfb1078979df",
                    '*',
                    "04a5bb3b28466f578e6e93fbfd5f75cee1ae86033aa4bbea690e3312c087181eb366f9a1d1d6a437a9bf9fc65ec853b9fd60fa322be3997c47144eb20da658b3d1",
                    4,
                    $"https://developers.tron.network/docs/account. {Environment.NewLine}" +
                    $"This example is missing one character (7).{Environment.NewLine}" +
                    $"Note the usage of a different input type here.{Environment.NewLine}" +
                    $"This example also shows that FinderOuter can potentially be used for any altcoin " +
                    $"that uses the same cryptography algorithms as bitcoin.{Environment.NewLine}" +
                    $"In this example Tron uses the same Elliptic Curve as bitcoin but different " +
                    $"hash algorithms, ergo the public key can be used as the extra input but not addresses{Environment.NewLine}" +
                    $"Estimated time: <1 sec"
                },
            };
        }
    }
}
