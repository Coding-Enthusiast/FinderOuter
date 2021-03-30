// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using Autarkysoft.Bitcoin.Encoders;
using FinderOuter.Models;
using ReactiveUI;
using System;
using System.Collections.Generic;

namespace FinderOuter.ViewModels
{


    public class MissingEncodingViewModel : OptionVmBase
    {
        public MissingEncodingViewModel()
        {
            EncodingList = new EncodingState[]
            {
                new EncodingState(EncodingName.Base16),
                new EncodingState(EncodingName.Base43),
                new EncodingState(EncodingName.Base58),
                new EncodingState(EncodingName.Base58Check),
                new EncodingState(EncodingName.Base64),
            };

            IObservable<bool> isFindEnabled = this.WhenAnyValue(
                x => x.Input,
                (input) => !string.IsNullOrEmpty(input));

            FindCommand = ReactiveCommand.Create(Find, isFindEnabled);
        }


        public override string OptionName => "Missing encoding";
        public override string Description => $"This option can be used to guess the encoding of a given string." +
            $"{Environment.NewLine}It works by eliminating encodings and letting user decode the input with any " +
            $"encoder to see the raw bytes.";


        public IEnumerable<EncodingState> EncodingList { get; }

        private string _input;
        public string Input
        {
            get => _input;
            set
            {
                if (_input != value)
                {
                    this.RaiseAndSetIfChanged(ref _input, value);
                    foreach (EncodingState item in EncodingList)
                    {
                        item.Possible = Possibility.Maybe;
                    }
                }
            }
        }


        public void Decode(EncodingName name)
        {
            Result.Init();

            try
            {
                byte[] ba = name switch
                {
                    EncodingName.Base16 => Base16.Decode(Input),
                    EncodingName.Base43 => new Base43().Decode(Input),
                    EncodingName.Base58 => new Base58().Decode(Input),
                    EncodingName.Base58Check => new Base58().DecodeWithCheckSum(Input),
                    EncodingName.Base64 => Convert.FromBase64String(Input),
                    _ => throw new NotImplementedException(),
                };

                Result.FoundAnyResult = true;
                Result.AddMessage($"{ba.Length} bytes: {ba.ToBase16()}");
            }
            catch (Exception ex)
            {
                Result.AddMessage(ex.Message);
            }


            Result.Finalize();
        }

        public override void Find()
        {
            foreach (EncodingState item in EncodingList)
            {
                item.SetPossibility(Input);
            }
        }
    }
}
