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
using System.Diagnostics;

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
            $"{Environment.NewLine}Enter the string in the TextBox below and either click Find to check it with all " +
            $"encoders or click one of the Decode buttons below to specifically decode using that encoder. The result " +
            $"will always show the raw bytes in hexadecimal format.";


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


        private bool HasValidChars(ReadOnlySpan<char> charSet, string input)
        {
            bool b = true;

            ReadOnlySpan<char> arr = input.AsSpan();
            for (int i = 0; i < arr.Length; i++)
            {
                if (!charSet.Contains(arr[i]))
                {
                    Result.AddMessage($"Invalid character ({arr[i]}) found at index {i}.");
                    b = false;
                }
            }
            return b;
        }

        private byte[] CheckBase16()
        {
            string input = Input;
            if (Input.StartsWith(Base16.Prefix))
            {
                input = Input.Replace(Base16.Prefix, "");
            }

            if (HasValidChars(Base16.CharSet, input.ToLower()))
            {
                if (Input.Length % 2 != 0)
                {
                    Result.AddMessage("Input length is invalid (has to be divisible by 2).");
                }
                else
                {
                    bool b = Base16.TryDecode(Input, out byte[] result);
                    Debug.Assert(b && result != null);
                    return result;
                }
            }
            return null;
        }

        private byte[] CheckBase43()
        {
            if (HasValidChars(Base43.CharSet, Input))
            {
                bool b = Base43.TryDecode(Input, out byte[] result);
                Debug.Assert(b && result != null);
                return result;
            }
            return null;
        }

        private byte[] CheckBase58(bool checksum)
        {
            if (HasValidChars(Base58.CharSet, Input))
            {
                if (checksum)
                {
                    if (Base58.IsValidWithChecksum(Input))
                    {
                        bool b = Base58.TryDecodeWithChecksum(Input, out byte[] result);
                        Debug.Assert(b && result != null);
                        return result;
                    }
                    else
                    {
                        Result.AddMessage("Input has an invalid checksum. Skipping checksum validation.");
                        bool b = Base58.TryDecode(Input, out byte[] result);
                        Debug.Assert(b && result != null);
                        return result;
                    }
                }
                else
                {
                    bool b = Base58.TryDecode(Input, out byte[] result);
                    Debug.Assert(b && result != null);
                    return result;
                }
            }
            return null;
        }

        public void Decode(EncodingName name)
        {
            Result.Init();
            if (string.IsNullOrEmpty(Input))
            {
                Result.AddMessage("Input can not be null or empty.");
                Result.Finalize();
                return;
            }

            Result.AddMessage($"Input has {Input.Length} character{(Input.Length > 1 ? "s" : "")}.");

            try
            {
                byte[] ba = name switch
                {
                    EncodingName.Base16 => CheckBase16(),
                    EncodingName.Base43 => CheckBase43(),
                    EncodingName.Base58 => CheckBase58(false),
                    EncodingName.Base58Check => CheckBase58(true),
                    EncodingName.Base64 => Convert.FromBase64String(Input),
                    _ => throw new NotImplementedException(),
                };

                if (ba != null)
                {
                    Result.FoundAnyResult = true;
                    Result.AddMessage($"Decoded data has {ba.Length} bytes.{Environment.NewLine}Data in Base-16: {ba.ToBase16()}");
                }
            }
            catch (Exception ex)
            {
                Result.AddMessage($"Decoder threw an exception: {ex.Message}");
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
