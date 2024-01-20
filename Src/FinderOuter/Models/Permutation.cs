// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

namespace FinderOuter.Models
{
    public unsafe struct Permutation
    {
        public Permutation(int size, uint* values)
        {
            max = size;
            pt = values;
            index = 0;
        }


        public readonly int max;
        private int index;
        private readonly uint* pt;


        public uint GetValue() => pt[index];


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
