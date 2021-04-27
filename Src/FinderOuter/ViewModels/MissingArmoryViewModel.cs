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
    public class MissingArmoryViewModel : OptionVmBase
    {
        public MissingArmoryViewModel()
        {
            service = new ArmoryService(Result);
            var inServ = new InputService();

            IObservable<bool> isFindEnabled = this.WhenAnyValue(
                x => x.Input,
                x => x.MissingChar,
                x => x.AdditionalInput,
                x => x.Result.CurrentState,
                (b58, c, extra, state) =>
                            !string.IsNullOrEmpty(b58) &&
                            inServ.IsMissingCharValid(c) &&
                            !string.IsNullOrEmpty(extra) &&
                            state != State.Working);

            FindCommand = ReactiveCommand.Create(Find, isFindEnabled);
            ExtraInputTypeList = ListHelper.GetEnumDescItems<InputType>().ToArray();
            SelectedExtraInputType = ExtraInputTypeList.First();

            HasExample = true;
            IObservable<bool> isExampleEnable = this.WhenAnyValue(
                x => x.Result.CurrentState,
                (state) => state != State.Working);
            ExampleCommand = ReactiveCommand.Create(Example, isExampleEnable);

            SetExamples(GetExampleData());
        }



        public override string OptionName => "Missing Armory";
        public override string Description => $"This option is useful to recover Armory recovery phrases.{Environment.NewLine}" +
            $"It supports recovering phrases that have 2 or 4 lines. Enter the phrase separating each line with a new line " +
            $"and replace the missing characters with a special missing char.{Environment.NewLine}" +
            $"The speed mainly depends on whether the checksum (last 4 characters of each line) is present or not.";

        private readonly ArmoryService service;

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
            service.FindMissing(Input, MissingChar, AdditionalInput, SelectedExtraInputType.Value);
        }

        public void Example()
        {
            object[] ex = GetNextExample();

            Input = (string)ex[0];
            MissingChar = (char)ex[1];
            AdditionalInput = (string)ex[2];
            int temp = (int)ex[3];
            Debug.Assert(temp < ExtraInputTypeList.Count());
            SelectedExtraInputType = ExtraInputTypeList.ElementAt(temp);
            Result.Message = $"Example {exampleIndex} of {totalExampleCount}. Source: {(string)ex[4]}";
        }

        private ExampleData GetExampleData()
        {
            return new ExampleData<string, char, string, int, string>()
            {
                {
                    $"adro sksk u*td nini hhgw afjj ujfn jwik inre{Environment.NewLine}" +
                    $"eorj otnk sfko de*t eafo hsou trnu gsih rhso",
                    '*',
                    "15kF4z37Do6NC9RmA41Pn3MWKwUAPpRetj",
                    1,
                    $"random.{Environment.NewLine}" +
                    $"This example is missing two character (o, r) one per line and checksums are intact.{Environment.NewLine}" +
                    $"Estimated time: <1 sec"
                },
                {
                    $"adrosksku_td nini    hhgw afjj ujfn jwik inre{Environment.NewLine}" +
                    $"eorj otnk sfko de_t eafo hsou trnu gsih rhso",
                    '_',
                    "5JvTxPsi5PgqeaaVf4hBrzRJTXwBUx6AFrMHAibKvVKC2RYMJQW",
                    5,
                    $"random.{Environment.NewLine}" +
                    $"Same as first example but it uses a different missing characters and a different additional " +
                    $"input type for comparison (the child private key). " +
                    $"It also shows FinderOuter is not strict about the spaces (only length/char count).{Environment.NewLine}" +
                    $"Estimated time: <1 sec"
                },
                {
                    $"adro **** uo*d nini hhgw afjj ujfn jwik inre{Environment.NewLine}" +
                    $"eorj ot*k s**o dert ea*o hsou trnu gsih rhso",
                    '*',
                    "15kF4z37Do6NC9RmA41Pn3MWKwUAPpRetj",
                    1,
                    $"random.{Environment.NewLine}" +
                    $"This example shows one of the most optimal cases where both checksums are intact, " +
                    $"the 68 billion phrases can be checked in less than 1 seconds.{Environment.NewLine}" +
                    $"Estimated time: <1 sec"
                },
                {
                    $"adro sksk uotd nini hhgw afjj ujfn jwik ****{Environment.NewLine}" +
                    $"eorj otnk sfko dert eafo hsou trnu gsih ****",
                    '*',
                    "15kF4z37Do6NC9RmA41Pn3MWKwUAPpRetj",
                    1,
                    $"random.{Environment.NewLine}" +
                    $"This example shows that if the input is only missing the checksum, FinderOuter will simply " +
                    $"compute the checksum and return the correct strings without needing any additional checks." +
                    $"{Environment.NewLine}" +
                    $"Estimated time: <1 sec"
                },
                {
                    $"oois wsgw jja* twof jhtg adnn n*gd wwgk esuh{Environment.NewLine}" +
                    $"fa*k frar ofof r*rt nkja eued rhsj thgf went{Environment.NewLine}" +
                    $"tsjj ohtr jtre idof ghhd jidk aidk stho jwfo{Environment.NewLine}" +
                    $"hiof thot fjot kigh odik aaow eegn dawj utnh",
                    '*',
                    "1ASHye7iYLPpysUoUpUHmivxrRh64iBMS4",
                    1,
                    $"random.{Environment.NewLine}" +
                    $"This example is missing 4 characters (n, f, d, u){Environment.NewLine}" +
                    $"This shows the case when the chain code is present.{Environment.NewLine}" +
                    $"Estimated time: <1 sec"
                },
            };
        }
    }
}
