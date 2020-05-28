// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Services;
using ReactiveUI;
using System;

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
                            state != Models.State.Working);

            FindCommand = ReactiveCommand.Create(Find, isFindEnabled);
        }

        public override string OptionName => "Missing mini private key";

        public override string Description => 
            $"This option can recover missing characters in a mini private key." +
            $"{Environment.NewLine}" +
            $"Enter the mini key (22 or 30 characters long starting with S) in first box while replacing its missing " +
            $"characters with the specified {nameof(MissingChar)} and enter the " +
            $"corresponding address in second box and click Find button.";


        private readonly MiniKeyService miniService;

        private string _input;
        public string Input
        {
            get => _input;
            set => this.RaiseAndSetIfChanged(ref _input, value);
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
            _ = miniService.Find(Input, ExtraInput, MissingChar);
        }
    }
}
