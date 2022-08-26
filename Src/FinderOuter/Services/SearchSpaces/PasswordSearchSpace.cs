// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using FinderOuter.Backend.Hashing;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace FinderOuter.Services.SearchSpaces
{
    public class PasswordSearchSpace : SearchSpaceBase
    {
        public int PasswordLength { get; private set; }
        public int MaxPasswordSize { get; private set; }
        public byte[] AllValues { get; private set; }
        public int[] PermutationLengths { get; private set; }

        public bool Process(int passLength, out string error)
        {
            if (passLength > Sha256Fo.BlockByteSize)
            {
                error = "Password is too long (bigger than SHA256 block size).";
                return false;
            }
            PasswordLength = passLength;

            error = string.Empty;
            return true;
        }


        public bool SetValues(string[][] result)
        {
            if (result.Length != PasswordLength || result.Any(x => x.Length < 1))
            {
                return false;
            }

            int totalLen = 0;
            int maxLen = 0;
            int maxIndex = 0;
            for (int i = 0; i < result.Length; i++)
            {
                if (result[i].Length < 1)
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

            PermutationLengths = new int[totalLen];
            PermutationCounts = new int[MissCount];

            FastStream stream = new();
            int index1 = 0;
            int index2 = 0;
            MaxPasswordSize = 0;
            foreach (string[] item in result)
            {
                PermutationCounts[index2++] = item.Length;
                int max = 0;
                foreach (string s in item)
                {
                    if (s.Length > 1)
                    {
                        return false;
                    }
                    byte[] t = Encoding.UTF8.GetBytes(s);
                    stream.Write(t);
                    PermutationLengths[index1++] = t.Length;

                    if (s.Length > max)
                    {
                        max = s.Length;
                    }
                }
                Debug.Assert(max > 0);
                MaxPasswordSize += max;
            }

            AllValues = stream.ToByteArray();

            return true;
        }
    }
}
