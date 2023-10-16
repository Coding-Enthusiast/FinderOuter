// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using System;
using System.Diagnostics;
using System.Numerics;

namespace FinderOuter.Services.SearchSpaces
{
    public abstract class SearchSpaceBase
    {
        public string Input { get; protected set; }
        public uint[] AllPermutationValues { get; protected set; }
        public int[] PermutationCounts { get; protected set; } = Array.Empty<int>();
        public int[] MissingIndexes { get; protected set; }
        public int MissCount { get; protected set; }


        public bool ProcessValues(string[][] array, out string error)
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
            }

            AllPermutationValues = new uint[totalLen];
            PermutationCounts = new int[MissCount];

            error = string.Empty;
            return true;
        }


        public bool ProcessCharValues(string[][] array, char[] allChars, uint[] permutationVals, out string error)
        {
            Debug.Assert(array is not null);
            Debug.Assert(array.Length == MissCount);

            int index1 = 0;
            int index2 = 0;
            foreach (string[] item in array)
            {
                Debug.Assert(item is not null && item.Length >= 2);

                PermutationCounts[index2++] = item.Length;
                foreach (string s in item)
                {
                    if (string.IsNullOrEmpty(s) || s.Length != 1)
                    {
                        error = $"Given value ({s}) is not a valid character.";
                        return false;
                    }
                    int i = Array.IndexOf(allChars, s[0]);
                    if (i < 0)
                    {
                        error = $"Given character ({s}) is not found in the valid characters list.";
                        return false;
                    }
                    if (i > permutationVals.Length)
                    {
                        error = "Given permutation value list is not valid (this is a bug).";
                        return false;
                    }
                    AllPermutationValues[index1++] = permutationVals[i];
                }
            }

            error = string.Empty;
            return true;
        }


        public BigInteger GetTotal()
        {
            BigInteger res = BigInteger.One;
            foreach (int item in PermutationCounts)
            {
                res *= item;
            }
            return res;
        }
    }
}
