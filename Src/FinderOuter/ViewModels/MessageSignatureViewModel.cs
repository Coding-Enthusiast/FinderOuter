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
    public class MessageSignatureViewModel : OptionVmBase
    {
        public MessageSignatureViewModel()
        {
            msgVerifier = new MessageSignatureService(Result);

            IObservable<bool> isFindEnabled = this.WhenAnyValue(
                x => x.Message,
                x => x.Address,
                x => x.Signature,
                x => x.Result.CurrentState,
                (msg, adr, sig, state) =>
                                         !string.IsNullOrEmpty(msg) &&
                                         !string.IsNullOrEmpty(adr) &&
                                         !string.IsNullOrEmpty(sig) &&
                                         state != State.Working);

            FindCommand = ReactiveCommand.Create(Find, isFindEnabled);
            FindProblemCommand = ReactiveCommand.Create(FindProblem, isFindEnabled);
        }



        public override string OptionName => "Message signature";
        public override string Description => $"Verifies message signatures and if the verification failed " +
            $"it can try to find where the issue was.{Environment.NewLine}" +
            $"Fill in the text boxes below with message (UTF8 encoding), address (base-58 or bech-32 encoding) " +
            $"and signature (base-64 encoding) and press find. " +
            $"The generated report will have all the information including the steps that were taken.";

        private readonly MessageSignatureService msgVerifier;


        private string _msg;
        public string Message
        {
            get => _msg;
            set => this.RaiseAndSetIfChanged(ref _msg, value);
        }

        private string _addr;
        public string Address
        {
            get => _addr;
            set => this.RaiseAndSetIfChanged(ref _addr, value);
        }

        private string _sig;
        public string Signature
        {
            get => _sig;
            set => this.RaiseAndSetIfChanged(ref _sig, value);
        }

        private bool _isVis;
        public bool IsFindProblemVisible
        {
            get => _isVis;
            set => this.RaiseAndSetIfChanged(ref _isVis, value);
        }



        public override void Find()
        {
            IsFindProblemVisible = !msgVerifier.Validate(Message, Address, Signature);
        }


        public IReactiveCommand FindProblemCommand { get; protected set; }

        public void FindProblem()
        {
            _ = msgVerifier.TryFindProblem(Message, Address, Signature);
        }
    }
}
