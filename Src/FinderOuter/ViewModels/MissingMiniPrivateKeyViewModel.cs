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
    public class MissingMiniPrivateKeyViewModel : OptionVmBase
    {
        public MissingMiniPrivateKeyViewModel()
        {
            // Don't move this line, service must be instantiated here
            InputService inServ = new InputService();
            miniService = new MiniKeyService(Result);

            IObservable<bool> isFindEnabled = this.WhenAnyValue(
                x => x.Input,
                x => x.ExtraInput,
                x => x.MissingChar,
                x => x.Result.CurrentState, (miniKey, addr, c, state) =>
                            !string.IsNullOrEmpty(miniKey) &&
                            !string.IsNullOrEmpty(addr) &&
                            inServ.IsMissingCharValid(c) &&
                            state != State.Working);

            FindCommand = ReactiveCommand.Create(Find, isFindEnabled);

            HasExample = true;
            IObservable<bool> isExampleVisible = this.WhenAnyValue(
                x => x.Result.CurrentState,
                (state) => state != State.Working);
            ExampleCommand = ReactiveCommand.Create(Example, isExampleVisible);

            ExtraInputTypeList = ListHelper.GetEnumDescItems(InputType.PrivateKey).ToArray();
            SelectedExtraInputType = ExtraInputTypeList.First();
        }

        public override string OptionName => "Missing mini private key";

        public override string Description =>
            $"This option can recover missing characters in a mini private key." +
            $"{Environment.NewLine}" +
            $"Enter the mini key (22 or 30 characters long starting with S) in first box while replacing its missing " +
            $"characters with the specified {nameof(MissingChar)} and enter the " +
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

        private char _mis = '*';
        public char MissingChar
        {
            get => _mis;
            set => this.RaiseAndSetIfChanged(ref _mis, value);
        }

        public override void Find()
        {
            miniService.Find(Input, ExtraInput, SelectedExtraInputType.Value, MissingChar);
        }

        public void Example()
        {
            int total = 3;

            switch (exampleIndex)
            {
                case 0:
                    Input = "SzavMBLoXU6kDr*tUV*ffv";
                    MissingChar = '*';
                    ExtraInput = "19GuvDvMMUZ8vq84wT79fvnvhMd5MnfTkR";
                    SelectedExtraInputType = ExtraInputTypeList.First();

                    Result.Message = $"This is example 1 out of {total} taken from bitcoin wiki.{Environment.NewLine}" +
                                     $"It is missing 2 characters (q, m) and it should take <1 second to find the correct key.";
                    break;
                case 1:
                    Input = "SzavMBLoXU6kDrqtUVmf--";
                    MissingChar = '-';
                    ExtraInput = "19GuvDvMMUZ8vq84wT79fvnvhMd5MnfTkR";
                    SelectedExtraInputType = ExtraInputTypeList.First();

                    Result.Message = $"This is example 2 out of {total} taken from bitcoin wiki.{Environment.NewLine}" +
                                     $"It is missing 2 characters (f, v) and it should take <1 second to find the correct key." +
                                     $"{Environment.NewLine}Note the usage of a different missing character.";
                    break;
                case 2:
                    Input = "S6c56bnXQiB*k9mqS*E7ykVQ7Nzr*y";
                    MissingChar = '*';
                    ExtraInput = "1CciesT23BNionJeXrbxmjc7ywfiyM4oLW";
                    SelectedExtraInputType = ExtraInputTypeList.ElementAt(1);

                    Result.Message = $"This is example 3 out of {total} taken from bitcoin wiki.{Environment.NewLine}" +
                                     $"It is missing 3 characters (j, Y, R) and it should take <30 seconds to find the " +
                                     $"correct key." +
                                     $"{Environment.NewLine}The address this time is using the uncompressed public key.";
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
