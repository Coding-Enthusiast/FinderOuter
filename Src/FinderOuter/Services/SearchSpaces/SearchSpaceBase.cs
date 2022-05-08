// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System.Numerics;

namespace FinderOuter.Services.SearchSpaces
{
    public abstract class SearchSpaceBase
    {
        public InputService InputService { get; set; } = new();

        public string Input { get; protected set; }
        public uint[] AllPermutationValues { get; protected set; }
        public int[] PermutationCounts { get; protected set; }
        public int[] MissingIndexes { get; protected set; }
        public int MissCount { get; protected set; }


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
