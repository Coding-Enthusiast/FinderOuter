// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.Encoders;
using ReactiveUI;
using System;

namespace FinderOuter.Models
{
    public class EncodingState : ReactiveObject
    {
        public EncodingState(EncodingName name)
        {
            Name = name;
        }

        public EncodingName Name { get; }

        private Possibility _possible;
        public Possibility Possible
        {
            get => _possible;
            set => this.RaiseAndSetIfChanged(ref _possible, value);
        }


        public void SetPossibility(string input)
        {
            bool validity = Name switch
            {
                EncodingName.Base16 => Base16.IsValid(input),
                EncodingName.Base43 => Base43.IsValid(input),
                EncodingName.Base58 => Base58.IsValid(input),
                EncodingName.Base58Check => Base58.IsValidWithChecksum(input),
                EncodingName.Base64 => CheckBase64(input),
                _ => throw new NotImplementedException(),
            };

            Possible = validity ? Possibility.Possible : Possibility.Impossible;
        }

        private static bool CheckBase64(string input)
        {
            try
            {
                Convert.FromBase64String(input);
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
