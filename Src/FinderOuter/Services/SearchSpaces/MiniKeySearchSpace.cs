// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend;
using System;
using System.Linq;
using System.Text;

namespace FinderOuter.Services.SearchSpaces
{
    public class MiniKeySearchSpace : SearchSpaceBase
    {
        public static readonly char[] AllChars = ConstantsFO.Base58Chars.ToCharArray();
        public static readonly byte[] AllBytes = Encoding.UTF8.GetBytes(ConstantsFO.Base58Chars);
        public byte[] preComputed;

        private void PreCompute(char missingChar)
        {
            int mis = 0;
            for (int i = 0; i < Input.Length; i++)
            {
                if (Input[i] == missingChar)
                {
                    MissingIndexes[mis++] = i;
                }
                else
                {
                    preComputed[i] = (byte)Input[i];
                }
            }
        }

        public bool Process(string input, char missingChar, out string error)
        {
            Input = input;

            if (!InputService.IsMissingCharValid(missingChar))
            {
                error = "Missing character is not accepted.";
                return false;
            }
            else if (string.IsNullOrWhiteSpace(Input) || !Input.All(c => AllChars.Contains(c) || c == missingChar))
            {
                error = "Input contains invalid base-58 character(s).";
                return false;
            }
            else if (!Input.StartsWith(ConstantsFO.MiniKeyStart))
            {
                error = $"Minikey must start with {ConstantsFO.MiniKeyStart}.";
                return false;
            }
            else
            {
                MissCount = Input.Count(c => c == missingChar);
                if (MissCount == 0)
                {
                    error = null;
                    return true;
                }
                else
                {
                    MissingIndexes = new int[MissCount];
                    switch (Input.Length)
                    {
                        case ConstantsFO.MiniKeyLen1:
                            preComputed = new byte[ConstantsFO.MiniKeyLen1];
                            break;
                        case ConstantsFO.MiniKeyLen2:
                            preComputed = new byte[ConstantsFO.MiniKeyLen2];
                            break;
                        case ConstantsFO.MiniKeyLen3:
                            preComputed = new byte[ConstantsFO.MiniKeyLen3];
                            break;
                        default:
                            error = $"Minikey length must be {ConstantsFO.MiniKeyLen1} or {ConstantsFO.MiniKeyLen2} or " +
                                    $"{ConstantsFO.MiniKeyLen3}.";
                            return false;
                    }

                    PreCompute(missingChar);
                    error = null;
                    return true;
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

            return InputService.IsValidMinikey(Input, out message);
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
                    AllPermutationValues[index1++] = AllBytes[i];
                }
            }

            return true;
        }
    }
}
