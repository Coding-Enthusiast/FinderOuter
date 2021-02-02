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
using System.Diagnostics;
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
            ExtraInputTypeList = ListHelper.GetEnumDescItems(InputType.PrivateKey).ToArray();
            SelectedExtraInputType = ExtraInputTypeList.First();

            HasExample = true;
            IObservable<bool> isExampleVisible = this.WhenAnyValue(
                x => x.Result.CurrentState,
                (state) => state != State.Working);
            ExampleCommand = ReactiveCommand.Create(Example, isExampleVisible);

            SetExamples(GetExampleData());
        }



        public override string OptionName => "Missing Base58";
        public override string Description => $"If you have a base-58 encoded string with a checksum such as private key WIFs " +
            $"(full list can be found under Input type dropdown) that is missing some characters at known locations " +
            $"(eg. a damaged paper wallet) you can use this option to recover it.{Environment.NewLine}" +
            $"Enter the base-58 string below and replace its missing characters with the symbol " +
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
            object[] ex = GetNextExample();

            Input = (string)ex[0];
            MissingChar = (char)ex[1];

            int temp1 = (int)ex[2];
            Debug.Assert(temp1 < InputTypeList.Count());
            SelectedInputType = InputTypeList.ElementAt(temp1);

            ExtraInput = (string)ex[3];

            int temp2 = (int)ex[4];
            Debug.Assert(temp2 < ExtraInputTypeList.Count());
            SelectedExtraInputType = ExtraInputTypeList.ElementAt(temp2);

            Result.Message = $"Example {exampleIndex} of {totalExampleCount}. Source: {(string)ex[5]}";
        }

        private ExampleData GetExampleData()
        {
            return new ExampleData<string, char, int, string, int, string>()
            {
                {
                    "5Kb8kLf9zgWQn*gidDA76*zPL6TsZZY36h**MssSzNydYXYB9KF",
                    '*',
                    0,
                    null,
                    0,
                    $"bitcoin wiki.{Environment.NewLine}" +
                    $"This example is an uncompressed private key missing 4 character (o, M, W, X).{Environment.NewLine}" +
                    $"Estimated time: <1 sec to find, <5 sec to check all"
                },
                {
                    "L53fCHmQh??p1B4JipfBtfeHZH7cAib?G9oK19?fiFzxHgAkz6JK",
                    '?',
                    0,
                    null,
                    0,
                    $"bitcoin wiki.{Environment.NewLine}" +
                    $"This example is a compressed private key missing 4 character (b, N, z, X).{Environment.NewLine}" +
                    $"Note the usage of a different missing character.{Environment.NewLine}" +
                    $"Estimated time: <1 sec to find, <1 sec to check all"
                },
                {
                    "5JBK1WUuytf9HURTCwCVmKghDUgqEs3NRa1dsKja4FgRBQ*****",
                    '*',
                    0,
                    null,
                    0,
                    $"random key{Environment.NewLine}" +
                    $"This example is an uncompressed private key missing 5 character (N, G, c, a, A).{Environment.NewLine}" +
                    $"Note that since these characters are all missing from the end, FinderOuter automatically chooses " +
                    $"an optimized algorithm that only checks 1 key instead of 656,356,768 greatly increasing the speed." +
                    $"{Environment.NewLine}" +
                    $"Also note that this cas doesn't need any additional input to check against since it only checks " +
                    $"one key.{Environment.NewLine}" +
                    $"Estimated time: <1 sec"
                },
                {
                    "KxpWVF8Cr71MZi2vfgDjxdUCW5CovBsTZShoj7gtuMny********",
                    '*',
                    0,
                    "1DjPqd6oBjii7PQh7JY1yAmPpHEHPWcaF3",
                    0,
                    $"random key{Environment.NewLine}" +
                    $"This example is a compressed private key missing 8 character (i,i,V,j,k,V,e,v).{Environment.NewLine}" +
                    $"Note that since these characters are all missing from the end, FinderOuter automatically chooses " +
                    $"an optimized algorithm that only checks 117 keys instead of 128 trillion (128,063,081,718,016) " +
                    $"greatly increasing the speed.{Environment.NewLine}" +
                    $"Also note that this optimized method requires an additional input such as public key or address " +
                    $"of this private key to check each result against it since all of them are valid.{Environment.NewLine}" +
                    $"Estimated time: <1 sec"
                },
                {
                    "5Kb8kLf9zgWQn*gidDA76*zPL6TsZZY36h**MssSzNy*YXYB9KF",
                    '*',
                    0,
                    null,
                    0,
                    $"bitcoin wiki{Environment.NewLine}" +
                    $"This example is an uncompressed private key missing 5 character (o, M, W, X, d).{Environment.NewLine}" +
                    $"Note the multi-thread usage (parallelism).{Environment.NewLine}" +
                    $"Also note that sometimes FinderOuter can find more than one valid base58, in this case 3." +
                    $"{Environment.NewLine}" +
                    $"Estimated time: <3 min"
                },
                {
                    "L53fCHmQhbNp1B4JipfBtfe**H7cA*bzG9o*19XfiF*xHgAkz6JK",
                    '*',
                    0,
                    null,
                    0,
                    $"bitcoin wiki{Environment.NewLine}" +
                    $"This example is a compressed private key missing 5 character (H, Z, i, K, z).{Environment.NewLine}" +
                    $"Note the multi-thread usage (parallelism).{Environment.NewLine}" +
                    $"Estimated time: <3 sec to find, <30 sec to check all"
                },
                {
                    "L53fCHmQhbNp1B4JipfBtfeHZHcAibzG9oK9XfiFzxHAkz6JK",
                    '*',
                    0,
                    null,
                    0,
                    $"bitcoin wiki{Environment.NewLine}" +
                    $"This example is a compressed private key missing 3 character at unknown positions.{Environment.NewLine}" +
                    $"Note that this is a special case and it uses multi-thread (parallelism).{Environment.NewLine}" +
                    $"Estimated time: <2 min to find, <3.5 min to check all"
                },
                {
                    "142viJrTYHA4TzryiEiuQkYk4Ay5Tfp***",
                    '*',
                    1,
                    null,
                    0,
                    $"Bitcoin.Net test vectors{Environment.NewLine}" +
                    $"This example is a P2PKH address missing 3 character (z, q, W).{Environment.NewLine}" +
                    $"Estimated time: <1 sec"
                },
                {
                    "39vipRmsscHCg**T7FHfq*UmCoNZ*oCygq",
                    '*',
                    1,
                    null,
                    0,
                    $"Bitcoin.Net test vectors{Environment.NewLine}" +
                    $"This example is a P2SH address missing 4 character (3, s, S, r).{Environment.NewLine}" +
                    $"Estimated time: <6 sec"
                },
                {
                    "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s*DGhwP4*5o44cvXdoY7sRzhtp**o",
                    '*',
                    2,
                    null,
                    0,
                    $"BIP-38 test vectors{Environment.NewLine}" +
                    $"This example is a BIP-38 encrypted private key missing 4 character (6, J, U, e).{Environment.NewLine}" +
                    $"Estimated time: <3 sec to find, <6 second to check all"
                },
                {
                    "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5**DGhwP4*5o44cvXdoY7sRzhtp**o",
                    '*',
                    2,
                    null,
                    0,
                    $"BIP-38 test vectors{Environment.NewLine}" +
                    $"This example is a BIP-38 encrypted private key missing 5 character (s, 6, J, U, e).{Environment.NewLine}" +
                    $"Note the multi-thread usage (parallelism).{Environment.NewLine}" +
                    $"Estimated time: <1 min to find, <3 min to check all"
                },
            };
        }
    }
}
