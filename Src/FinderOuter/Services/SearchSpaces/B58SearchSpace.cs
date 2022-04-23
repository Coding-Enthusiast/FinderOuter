// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend;
using System;
using System.Diagnostics;
using System.Linq;
using System.Numerics;

namespace FinderOuter.Services.SearchSpaces
{
    public class B58SearchSpace
    {
        public B58SearchSpace()
        {
            inputService = new InputService();
        }

        private readonly InputService inputService;

        public readonly char[] AllChars = ConstantsFO.Base58Chars.ToCharArray();
        public string key;
        public int missCount;
        bool isComp;
        public ulong[] multPow58, preComputed;
        public int[] missingIndexes, multMissingIndexes;
        public int[] permutationCounts;
        public uint[] allPermutationValues;
        internal Base58Service.InputType inputType;

        public bool IsProcessed { get; private set; }


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
            missCount = key.Count(c => c == missChar);
            if (missCount == 0)
            {
                error = null;
                return true;
            }
            else
            {
                if (inputService.CanBePrivateKey(key, out error))
                {
                    missingIndexes = new int[missCount];
                    multMissingIndexes = new int[missCount];
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
                            missingIndexes[mis] = i;
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
        }

        private bool ProcessAddress(string address, char missChar, out string error)
        {
            missCount = address.Count(c => c == missChar);
            if (missCount == 0)
            {
                error = null;
                return true;
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
                missingIndexes = new int[missCount];
                multMissingIndexes = new int[missCount];
                preComputed = new ulong[uLen];
                multPow58 = GetShiftedMultPow58(address.Length, uLen, 24);

                // calculate what we already have and store missing indexes
                int mis = 0;
                for (int i = key.Length - 1, j = 0; i >= 0; i--)
                {
                    int t = (key.Length - 1 - i) * uLen;
                    if (key[i] != missChar)
                    {
                        int index = ConstantsFO.Base58Chars.IndexOf(key[i]);
                        int chunk = (index * address.Length * uLen) + t;
                        for (int k = uLen - 1; k >= 0; k--, j++)
                        {
                            preComputed[k] += multPow58[k + chunk];
                        }
                    }
                    else
                    {
                        missingIndexes[mis] = i;
                        multMissingIndexes[mis] = t;
                        mis++;
                        j += uLen;
                    }
                }

                //uint[] pt = new uint[30];

                //preComputed[1] += preComputed[0] >> 32;
                //pt[13] = ((uint)preComputed[1] & 0xff000000) | 0b00000000_10000000_00000000_00000000U;
                //preComputed[2] += preComputed[1] >> 32;
                //pt[12] = (uint)preComputed[2]; preComputed[3] += preComputed[2] >> 32;
                //pt[11] = (uint)preComputed[3]; preComputed[4] += preComputed[3] >> 32;
                //pt[10] = (uint)preComputed[4]; preComputed[5] += preComputed[4] >> 32;
                //pt[9] = (uint)preComputed[5]; preComputed[6] += preComputed[5] >> 32;
                //pt[8] = (uint)preComputed[6]; 
                //Debug.Assert(preComputed[6] >> 32 == 0);

                //uint expectedCS = (uint)preComputed[0] >> 24 | (uint)preComputed[1] << 8;

                error = null;
                return true;
            }
        }

        private bool ProcessBip38(string bip38, char missChar, out string error)
        {
            missCount = bip38.Count(c => c == missChar);
            if (missCount == 0)
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
                error = $"Base-58 encoded BIP-38 length must be between {ConstantsFO.Bip38Base58Len}.";
                return false;
            }
            else
            {
                missingIndexes = new int[missCount];
                multMissingIndexes = new int[missCount];
                const int uLen = 11;
                preComputed = new ulong[uLen];
                multPow58 = GetShiftedMultPow58(bip38.Length, uLen, 8);

                // calculate what we already have and store missing indexes
                int mis = 0;
                for (int i = key.Length - 1, j = 0; i >= 0; i--)
                {
                    int t = (key.Length - 1 - i) * uLen;
                    if (key[i] != missChar)
                    {
                        int index = ConstantsFO.Base58Chars.IndexOf(key[i]);
                        int chunk = (index * bip38.Length * uLen) + t;
                        for (int k = uLen - 1; k >= 0; k--, j++)
                        {
                            preComputed[k] += multPow58[k + chunk];
                        }
                    }
                    else
                    {
                        missingIndexes[mis] = i;
                        multMissingIndexes[mis] = t;
                        mis++;
                        j += uLen;
                    }
                }

                error = null;
                return true;
            }
        }

        public bool Process(string input, char missChar, Base58Service.InputType t, out string error)
        {
            IsProcessed = false;

            key = input;
            inputType = t;

            if (!inputService.IsMissingCharValid(missChar))
            {
                error = "Missing character is not accepted.";
                return false;
            }
            else if (string.IsNullOrWhiteSpace(key) || !key.All(c => ConstantsFO.Base58Chars.Contains(c) || c == missChar))
            {
                error = "Input contains invalid base-58 character(s).";
                return false;
            }
            else
            {
                switch (t)
                {
                    case Base58Service.InputType.PrivateKey:
                        return ProcessPrivateKey(key, missChar, out error);
                    case Base58Service.InputType.Address:
                        return ProcessAddress(key, missChar, out error);
                    case Base58Service.InputType.Bip38:
                        return ProcessBip38(key, missChar, out error);
                    default:
                        error = "Given input type is not defined.";
                        return false;
                }
            }
        }


        public bool SetValues(string[][] result)
        {
            if (result.Length != missCount)
            {
                return false;
            }

            int totalLen = 0;
            int maxLen = 0;
            int maxIndex = 0;
            for (int i = 0; i < result.Length; i++)
            {
                if (result[i].Length <= 1)
                {
                    return false;
                }
                totalLen += result[i].Length;

                if (result[i].Length > maxLen)
                {
                    maxLen = result[i].Length;
                    maxIndex = i;
                }
            }

            if (maxIndex != 0)
            {
                string[] t1 = result[maxIndex];
                result[maxIndex] = result[0];
                result[0] = t1;

                int t2 = missingIndexes[maxIndex];
                missingIndexes[maxIndex] = missingIndexes[0];
                missingIndexes[0] = t2;
            }

            allPermutationValues = new uint[totalLen];
            permutationCounts = new int[missCount];

            int index1 = 0;
            int index2 = 0;
            char[] allChars = ConstantsFO.Base58Chars.ToCharArray();
            foreach (string[] item in result)
            {
                permutationCounts[index2++] = item.Length;
                foreach (string s in item)
                {
                    if (s.Length > 1)
                    {
                        return false;
                    }
                    int i = Array.IndexOf(allChars, s[0]);
                    if (i < 0)
                    {
                        return false;
                    }
                    allPermutationValues[index1++] = (uint)i;
                }
            }

            return true;
        }


        public BigInteger GetTotal()
        {
            BigInteger res = BigInteger.One;
            foreach (int item in permutationCounts)
            {
                res *= item;
            }
            return res;
        }
    }
}
