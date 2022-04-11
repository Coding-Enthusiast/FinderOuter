// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System.Diagnostics;

namespace FinderOuter.Models
{
    public unsafe struct Permutation
    {
        public Permutation(int maximum, uint* values)
        {
            max = maximum;
            pt = values;
            index = 0;
        }


        public readonly int max;
        private int index;
        private readonly uint* pt;
        

        public uint GetValue() => pt[index];

        public uint GetNextValue()
        {
            Debug.Assert(index + 1 < max);
            return pt[index++];
        }

        public bool Increment()
        {
            index++;
            if (index == max)
            {
                index = 0;
                return false;
            }
            else
            {
                return true;
            }
        }
    }
}
