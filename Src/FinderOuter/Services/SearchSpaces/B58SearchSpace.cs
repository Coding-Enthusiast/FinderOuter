// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using FinderOuter.Backend;
using FinderOuter.Models;
using System;
using System.Diagnostics;
using System.Linq;
using System.Numerics;

namespace FinderOuter.Services.SearchSpaces
{
    public class B58SearchSpace : SearchSpaceBase
    {
        public static readonly char[] AllChars = ConstantsFO.Base58Chars.ToCharArray();
        public bool isComp;
        public ulong[] multPow58, preComputed;
        public int[] multMissingIndexes;
        public Base58Type inputType;


        /// <summary>
        /// Returns powers of 58 multiplied by <paramref name="maxPow"/> then shifts them left so that it doesn't need it later
        /// when converting to SHA256 working vector
        /// <para/>[0*58^0, 0*58^1, ..., 0*58^<paramref name="maxPow"/>, 1*58^0, 1*58^1, ...]
        /// </summary>
        public static ulong[] GetShiftedMultPow58(int maxPow, int uLen, int shift)
        {
            Debug.Assert(shift is >= 0 and <= 24);

            byte[] padded = new byte[4 * uLen];
            ulong[] multPow = new ulong[maxPow * uLen * 58];
            for (int i = 0, pindex = 0; i < 58; i++)
            {
                for (int j = 0; j < maxPow; j++)
                {
                    BigInteger val = BigInteger.Pow(58, j) * i;
                    byte[] temp = val.ToByteArrayExt(false, true);

                    Array.Clear(padded, 0, padded.Length);
                    Buffer.BlockCopy(temp, 0, padded, 0, temp.Length);

                    for (int k = 0; k < padded.Length; pindex++, k += 4)
                    {
                        multPow[pindex] = (uint)(padded[k] << 0 | padded[k + 1] << 8 | padded[k + 2] << 16 | padded[k + 3] << 24);
                        multPow[pindex] <<= shift;
                    }
                }
            }
            return multPow;
        }

        private bool ProcessPrivateKey(string key, char missChar, out string error)
        {
            Debug.Assert(MissCount > 0);

            if (InputService.CanBePrivateKey(key, out error))
            {
                MissingIndexes = new int[MissCount];
                multMissingIndexes = new int[MissCount];
                isComp = key.Length == ConstantsFO.PrivKeyCompWifLen;

                const int uLen = 10; // Maximum result (58^52) is 39 bytes = 39/4 = 10 uint
                multPow58 = isComp
                    ? GetShiftedMultPow58(ConstantsFO.PrivKeyCompWifLen, uLen, 16)
                    : GetShiftedMultPow58(ConstantsFO.PrivKeyUncompWifLen, uLen, 24);

                preComputed = new ulong[uLen];

                // calculate what we already have and store missing indexes
                int mis = 0;
                for (int i = key.Length - 1, j = 0; i >= 0; i--)
                {
                    int t = (key.Length - 1 - i) * uLen;
                    if (key[i] != missChar)
                    {
                        int index = ConstantsFO.Base58Chars.IndexOf(key[i]);
                        int chunk = (index * key.Length * uLen) + t;
                        for (int k = uLen - 1; k >= 0; k--, j++)
                        {
                            preComputed[k] += multPow58[k + chunk];
                        }
                    }
                    else
                    {
                        MissingIndexes[mis] = i;
                        multMissingIndexes[mis] = t;
                        mis++;
                        j += uLen;
                    }
                }

                return true;
            }
            else
            {
                return false;
            }
        }

        private bool ProcessAddress(string address, char missChar, out string error)
        {
            if (MissCount == 0)
            {
                if (address[0] != ConstantsFO.B58AddressChar1 && address[0] != ConstantsFO.B58AddressChar2)
                {
                    error = "The given address has an invalid first character.";
                    return false;
                }
                else
                {
                    error = null;
                    return true;
                }
            }
            else if (!address.StartsWith(ConstantsFO.B58AddressChar1) && !address.StartsWith(ConstantsFO.B58AddressChar2))
            {
                error = $"Base-58 address should start with {ConstantsFO.B58AddressChar1} or {ConstantsFO.B58AddressChar2}.";
                return false;
            }
            else if (address.Length < ConstantsFO.B58AddressMinLen || address.Length > ConstantsFO.B58AddressMaxLen)
            {
                error = $"Address length must be between {ConstantsFO.B58AddressMinLen} and {ConstantsFO.B58AddressMaxLen} " +
                        $"(but it is {address.Length}).";
                return false;
            }
            else
            {
                const int uLen = 7;
                MissingIndexes = new int[MissCount];
                multMissingIndexes = new int[MissCount];
                preComputed = new ulong[uLen];
                multPow58 = GetShiftedMultPow58(address.Length, uLen, 24);

                // calculate what we already have and store missing indexes
                int mis = 0;
                for (int i = Input.Length - 1, j = 0; i >= 0; i--)
                {
                    int t = (Input.Length - 1 - i) * uLen;
                    if (Input[i] != missChar)
                    {
                        int index = ConstantsFO.Base58Chars.IndexOf(Input[i]);
                        int chunk = (index * address.Length * uLen) + t;
                        for (int k = uLen - 1; k >= 0; k--, j++)
                        {
                            preComputed[k] += multPow58[k + chunk];
                        }
                    }
                    else
                    {
                        MissingIndexes[mis] = i;
                        multMissingIndexes[mis] = t;
                        mis++;
                        j += uLen;
                    }
                }

                error = null;
                return true;
            }
        }

        private bool ProcessBip38(string bip38, char missChar, out string error)
        {
            if (MissCount == 0)
            {
                error = null;
                return true;
            }
            else if (!bip38.StartsWith(ConstantsFO.Bip38Start))
            {
                error = $"Base-58 encoded BIP-38 should start with {ConstantsFO.Bip38Start}.";
                return false;
            }
            else if (bip38.Length != ConstantsFO.Bip38Base58Len)
            {
                error = $"Base-58 encoded BIP-38 length must have {ConstantsFO.Bip38Base58Len} characters.";
                return false;
            }
            else
            {
                MissingIndexes = new int[MissCount];
                multMissingIndexes = new int[MissCount];
                const int uLen = 11;
                preComputed = new ulong[uLen];
                multPow58 = GetShiftedMultPow58(bip38.Length, uLen, 8);

                // calculate what we already have and store missing indexes
                int mis = 0;
                for (int i = Input.Length - 1, j = 0; i >= 0; i--)
                {
                    int t = (Input.Length - 1 - i) * uLen;
                    if (Input[i] != missChar)
                    {
                        int index = ConstantsFO.Base58Chars.IndexOf(Input[i]);
                        int chunk = (index * bip38.Length * uLen) + t;
                        for (int k = uLen - 1; k >= 0; k--, j++)
                        {
                            preComputed[k] += multPow58[k + chunk];
                        }
                    }
                    else
                    {
                        MissingIndexes[mis] = i;
                        multMissingIndexes[mis] = t;
                        mis++;
                        j += uLen;
                    }
                }

                error = null;
                return true;
            }
        }

        public bool Process(string input, char missChar, Base58Type t, out string error)
        {
            Input = input;
            inputType = t;

            if (string.IsNullOrEmpty(input))
            {
                error = "Input can not be null or empty.";
                return false;
            }
            else if (!InputService.IsMissingCharValid(missChar))
            {
                error = "Missing character is not accepted.";
                return false;
            }
            else if (!InputService.CheckChars(input, AllChars, missChar, out error))
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
                switch (t)
                {
                    case Base58Type.PrivateKey:
                        return ProcessPrivateKey(Input, missChar, out error);
                    case Base58Type.Address:
                        return ProcessAddress(Input, missChar, out error);
                    case Base58Type.Bip38:
                        return ProcessBip38(Input, missChar, out error);
                    default:
                        error = "Given input type is not defined.";
                        return false;
                }
            }
        }


        public bool ProcessNoMissing(out string message)
        {
            if (MissCount != 0)
            {
                message = "This method should not be called with missing characters.";
                return false;
            }

            if (inputType == Base58Type.PrivateKey)
            {
                return InputService.IsValidWif(Input, out message);
            }
            else if (inputType == Base58Type.Address)
            {
                return InputService.IsValidBase58Address(Input, out message);
            }
            else if (inputType == Base58Type.Bip38)
            {
                return InputService.IsValidBase58Bip38(Input, out message);
            }
            else
            {
                message = "Undefined input type.";
                return false;
            }
        }


        public bool SetValues(string[][] array, out string error)
        {
            if (array is null)
            {
                // ViewModels should never send null array
                error = "Permutations list can not be null (this is a bug).";
                return false;
            }

            if (array.Length != MissCount)
            {
                error = "Permutations list doesn't have the same number of arrays as missing characters count.";
                return false;
            }

            int totalLen = 0;
            int maxLen = 0;
            int maxIndex = 0;
            for (int i = 0; i < array.Length; i++)
            {
                if (array[i] is null || array[i].Length < 2)
                {
                    error = $"Search space values are not correctly set. " +
                            $"Add at least 2 possible values for the {(i + 1).ToOrdinal()} missing position.";
                    return false;
                }

                totalLen += array[i].Length;

                if (array[i].Length > maxLen)
                {
                    maxLen = array[i].Length;
                    maxIndex = i;
                }
            }

            if (maxIndex != 0)
            {
                string[] t1 = array[maxIndex];
                array[maxIndex] = array[0];
                array[0] = t1;

                int t2 = MissingIndexes[maxIndex];
                MissingIndexes[maxIndex] = MissingIndexes[0];
                MissingIndexes[0] = t2;

                t2 = multMissingIndexes[maxIndex];
                multMissingIndexes[maxIndex] = multMissingIndexes[0];
                multMissingIndexes[0] = t2;
            }

            AllPermutationValues = new uint[totalLen];
            PermutationCounts = new int[MissCount];

            uint[] all = Enumerable.Range(0, AllChars.Length).Select(i => (uint)i).ToArray();
            return ProcessCharValues(array, AllChars, all, out error);
        }
    }
}
