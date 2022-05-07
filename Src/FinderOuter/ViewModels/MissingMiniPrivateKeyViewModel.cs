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
    public class MissingMiniPrivateKeyViewModel : OptionVmBase
    {
        public MissingMiniPrivateKeyViewModel()
        {
            // Don't move this line, service must be instantiated here
            InputService inServ = new();
            miniService = new MiniKeyService(Result);

            IObservable<bool> isFindEnabled = this.WhenAnyValue(
                x => x.Input,
                x => x.ExtraInput,
                x => x.Result.CurrentState, (miniKey, addr, state) =>
                            !string.IsNullOrEmpty(miniKey) &&
                            !string.IsNullOrEmpty(addr) &&
                            state != State.Working);

            FindCommand = ReactiveCommand.Create(Find, isFindEnabled);

            HasExample = true;
            IObservable<bool> isExampleVisible = this.WhenAnyValue(
                x => x.Result.CurrentState,
                (state) => state != State.Working);
            ExampleCommand = ReactiveCommand.Create(Example, isExampleVisible);

            ExtraInputTypeList = ListHelper.GetEnumDescItems(InputType.PrivateKey).ToArray();
            SelectedExtraInputType = ExtraInputTypeList.First();

            SetExamples(GetExampleData());
        }

        public override string OptionName => "Missing mini private key";

        public override string Description =>
            $"This option can recover missing characters in a mini private key." +
            $"{Environment.NewLine}" +
            $"Enter the mini key (22 or 26 or 30 characters long starting with S) in first box while replacing its missing " +
            $"characters with the specified missing character and enter the " +
            $"corresponding address in second box and click Find button.";


        private readonly MiniKeyService miniService;

        public IEnumerable<DescriptiveItem<InputType>> ExtraInputTypeList { get; }

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


        public override void Find()
        {
            miniService.Find(Input, ExtraInput, SelectedExtraInputType.Value, SelectedMissingChar);
        }

        public void Example()
        {
            object[] ex = GetNextExample();

            Input = (string)ex[0];
            SelectedMissingChar = MissingChars[(int)ex[1]];
            ExtraInput = (string)ex[2];
            int temp = (int)ex[3];
            Debug.Assert(temp < ExtraInputTypeList.Count());
            SelectedExtraInputType = ExtraInputTypeList.ElementAt(temp);
            Result.Message = $"Example {exampleIndex} of {totalExampleCount}. Source: {(string)ex[4]}";
        }

        private ExampleData GetExampleData()
        {
            return new ExampleData<string, int, string, int, string>()
            {
                {
                    "SzavMBLoXU6kDr*tUV*ffv",
                    Array.IndexOf(MissingChars, '*'),
                    "19GuvDvMMUZ8vq84wT79fvnvhMd5MnfTkR",
                    0,
                    $"bitcoin wiki.{Environment.NewLine}" +
                    $"This example is a 22 digit long mini-key and is missing 2 (q, m).{Environment.NewLine}" +
                    $"Estimated time: <1 sec"
                },
                {
                    "SzavMBLoXU6kDrqtUVmf--",
                    Array.IndexOf(MissingChars, '-'),
                    "02588D202AFCC1EE4AB5254C7847EC25B9A135BBDA0F2BC69EE1A714749FD77DC9",
                    4,
                    $"bitcoin wiki.{Environment.NewLine}" +
                    $"This example is a 22 digit long mini-key and is missing 2 (f, v).{Environment.NewLine}" +
                    $"Note the usage of a different missing character and extra input type (pubkey).{Environment.NewLine}" +
                    $"Estimated time: <1 sec"
                },
                {
                    "S6c56bnXQiB*k9mqS*E7ykVQ7Nzr*y",
                    Array.IndexOf(MissingChars, '*'),
                    "1CciesT23BNionJeXrbxmjc7ywfiyM4oLW",
                    1,
                    $"bitcoin wiki.{Environment.NewLine}" +
                    $"This example is a 30 digit long mini-key missing 3 (j, Y, R).{Environment.NewLine}" +
                    $"Note the usage of a different extra input type (address using uncompressed pubkey).{Environment.NewLine}" +
                    $"Estimated time: <10 sec"
                },
                {
                    "SzavMBLo*U6*D**tU*mffv",
                    Array.IndexOf(MissingChars, '*'),
                    "02588D202AFCC1EE4AB5254C7847EC25B9A135BBDA0F2BC69EE1A714749FD77DC9",
                    4,
                    $"bitcoin wiki.{Environment.NewLine}" +
                    $"This example is missing 5 characters (X, k, r, q, V).{Environment.NewLine}" +
                    $"Note the multi-thread usage (parallelism).{Environment.NewLine}" +
                    $"Estimated time: <1 min"
                }
            };
        }
    }
}
