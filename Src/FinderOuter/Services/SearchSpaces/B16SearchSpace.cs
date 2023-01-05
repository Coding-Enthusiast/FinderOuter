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
            if (MissCount != 0)
            {
                message = "This method should not be called with missing characters.";
                return false;
            }
            // A quick check to make sure no exceptions are thrown later (this should alwyas pass since
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

            bool success = comparer.Compare(key);
            if (success)
            {
                message = $"The given key is valid and the given {comparer.CompareType} is correctly derived from it.";
                return true;
            }
            else
            {
                // TODO: generate all addresses here?
                message = "";


                return false;
            }
        }

        public bool SetValues(string[][] result)
        {
            if (result.Length != MissCount || result.Any(x => x.Length < 2))
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

                int t2 = MissingIndexes[maxIndex];
                MissingIndexes[maxIndex] = MissingIndexes[0];
                MissingIndexes[0] = t2;
            }

            AllPermutationValues = new uint[totalLen];
            PermutationCounts = new int[MissCount];

            int index1 = 0;
            int index2 = 0;

            foreach (string[] item in result)
            {
                PermutationCounts[index2++] = item.Length;
                foreach (string s in item)
                {
                    if (s.Length > 1)
                    {
                        return false;
                    }
                    int i = Array.IndexOf(AllChars, s[0]);
                    if (i < 0)
                    {
                        return false;
                    }
                    AllPermutationValues[index1++] = (uint)i;
                }
            }

            return true;
        }
    }
}
