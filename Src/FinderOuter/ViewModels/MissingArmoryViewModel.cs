// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Models;
using FinderOuter.Services;
using ReactiveUI;
using System;
using System.Diagnostics;
using System.Linq;

namespace FinderOuter.ViewModels
{
    public class MissingArmoryViewModel : OptionVmBase
    {
        public MissingArmoryViewModel()
        {
            service = new ArmoryService(Result);

            IObservable<bool> isFindEnabled = this.WhenAnyValue(
                x => x.Input,
                x => x.CompareInput,
                x => x.Result.CurrentState,
                (b58, extra, state) =>
                            !string.IsNullOrEmpty(b58) &&
                            !string.IsNullOrEmpty(extra) &&
                            state != State.Working);

            FindCommand = ReactiveCommand.Create(Find, isFindEnabled);
            CompareInputTypeList = ListHelper.GetEnumDescItems<CompareInputType>().ToArray();
            SelectedCompareInputType = CompareInputTypeList.First();

            IObservable<bool> isExampleEnable = this.WhenAnyValue(x => x.Result.CurrentState, (state) => state != State.Working);
            ExampleCommand = ReactiveCommand.Create(Example, isExampleEnable);

            SetExamples(GetExampleData());
        }



        public override string OptionName => "Missing Armory";
        public override string Description => $"This option is useful to recover Armory recovery phrases.{Environment.NewLine}" +
            $"It supports recovering phrases that have 2 or 4 lines. Enter the phrase separating each line with a new line " +
            $"and replace the missing characters with a special missing char.{Environment.NewLine}" +
            $"The speed mainly depends on whether the checksum (last 4 characters of each line) is present or not.";

        private readonly ArmoryService service;


        public override void Find()
        {
            service.FindMissing(Input, SelectedMissingChar, CompareInput, SelectedCompareInputType.Value);
        }

        public void Example()
        {
            object[] ex = GetNextExample();

            Input = (string)ex[0];
            SelectedMissingChar = MissingChars[(int)ex[1]];
            CompareInput = (string)ex[2];
            int temp = (int)ex[3];
            Debug.Assert(temp < CompareInputTypeList.Count());
            SelectedCompareInputType = CompareInputTypeList.ElementAt(temp);
            Result.Message = $"Example {exampleIndex} of {totalExampleCount}. Source: {(string)ex[4]}";
        }

        private ExampleData GetExampleData()
        {
            return new ExampleData<string, int, string, int, string>()
            {
                {
                    $"adro sksk u*td nini hhgw afjj ujfn jwik inre{Environment.NewLine}" +
                    $"eorj otnk sfko de*t eafo hsou trnu gsih rhso",
                    Array.IndexOf(MissingChars, '*'),
                    "15kF4z37Do6NC9RmA41Pn3MWKwUAPpRetj",
                    1,
                    $"random.{Environment.NewLine}" +
                    $"This example is missing two character (o, r) one per line and checksums are intact.{Environment.NewLine}" +
                    $"Estimated time: <1 sec"
                },
                {
                    $"adrosksku_td nini    hhgw afjj ujfn jwik inre{Environment.NewLine}" +
                    $"eorj otnk sfko de_t eafo hsou trnu gsih rhso",
                    Array.IndexOf(MissingChars, '_'),
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
                    Array.IndexOf(MissingChars, '*'),
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
                    Array.IndexOf(MissingChars, '*'),
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
                    Array.IndexOf(MissingChars, '*'),
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
