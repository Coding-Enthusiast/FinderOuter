// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System;

namespace FinderOuter.Models
{
    public unsafe struct PermutationVar
    {
        public PermutationVar(int size, byte* values, int* lengths)
        {
            max = size;
            src = values;
            lens = lengths;
            index = 0;
            pos = 0;
        }


        public readonly int max;
        private int index, pos;
        private readonly byte* src;
        private readonly int* lens;


        public bool Increment()
        {
            index++;
            if (index == max)
            {
                index = 0;
                pos = 0;
                return false;
            }
            else
            {
                pos += lens[index - 1];
                return true;
            }
        }

        /// <summary>
        /// Writes the next value to the given pointer
        /// </summary>
        /// <param name="res">Pointer to the stream to write to</param>
        /// <param name="dstSizeInBytes">Total size of the stream to write to</param>
        /// <returns>Number of bytes written (should be used to move <paramref name="res"/> forward)</returns>
        public int WriteValue(byte* res, int dstSizeInBytes)
        {
            int len = lens[index];
            Buffer.MemoryCopy(src + pos, res, dstSizeInBytes, len);
            return len;
        }
    }
}
