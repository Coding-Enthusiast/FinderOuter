// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.Cryptography.EllipticCurve;
using Autarkysoft.Bitcoin.Encoders;
using FinderOuter.Backend;
using FinderOuter.Services.Comparers;
using System;
using System.Linq;

namespace FinderOuter.Services.SearchSpaces
{
    public class B16SearchSpace : SearchSpaceBase
    {
        public static readonly char[] AllChars = ConstantsFO.Base16Chars.ToCharArray();
        public byte[] preComputed;

        public bool Process(string input, char missChar, out string error)
        {
            Input = input;

            if (!InputService.IsValidBase16Key(input, missChar, out error))
            {
                return false;
            }
            else
            {
                MissCount = input.Count(c => c == missChar);
                if (MissCount == 0)
                {
                    error = null;
                    return true;
                }

                MissingIndexes = new int[MissCount];
                preComputed = new byte[32];
                for (int i = 0, j = 0; i < preComputed.Length; i++)
                {
                    int hi, lo;
                    if (input[i * 2] == missChar)
                    {
                        hi = 0;
                        MissingIndexes[j++] = i * 2;
                    }
                    else
                    {
                        hi = input[i * 2] - 65;
                        hi = hi + 10 + ((hi >> 31) & 7);
                    }
                    if (input[i * 2 + 1] == missChar)
                    {
                        lo = 0;
                        MissingIndexes[j++] = i * 2 + 1;
                    }
                    else
                    {
                        lo = input[i * 2 + 1] - 65;
                        lo = lo + 10 + ((lo >> 31) & 7) & 0x0f;
                    }

                    preComputed[i] = (byte)(lo | hi << 4);
                }

                error = null;
                return true;
            }
        }

        public bool ProcessNoMissing(ICompareService comparer, out string message)
        {
            if (!comparer.IsInitialized)
            {
                message = "Comparer is not initializd.";
                return false;
            }

            if (MissCount != 0)
            {
                message = "This method should not be called with missing characters.";
                return false;
            }
            // A quick check to make sure no exceptions are thrown later (this should always pass since
            // Input is already processed)
            if (!Base16.TryDecode(Input, out byte[] ba) || ba.Length != 32)
            {
                message = "Invalid Base-16 key.";
                return false;
            }

            Scalar8x32 key = new(ba, out bool overflow);
            if (key.IsZero || overflow)
            {
                message = "The given key is out of range.";
                return false;
            }

            if (comparer.Compare(key))
            {
                message = $"The given key is valid and the given {comparer.CompareType} is correctly derived from it.";
                return true;
            }
            else
            {
                PrivateKey prv = new(ba);
                message = $"The given key is valid but the given {comparer.CompareType} can not be derived from it." +
                          $"{Environment.NewLine}" +
                          $"List of addresses that can be derived from this key:{Environment.NewLine}" +
                          $"{AddressService.GetAllAddresses(prv.ToPublicKey(comparer.Calc))}";

                return false;
            }
        }

        public bool SetValues(string[][] array, out string error)
        {
            uint[] all = Enumerable.Range(0, AllChars.Length).Select(i => (uint)i).ToArray();
            return ProcessValues(array, out error) && ProcessCharValues(array, AllChars, all, out error);
        }
    }
}
