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
        /// <summary>
        /// Number of chars/words in the password
        /// </summary>
        public int PasswordLength { get; private set; }
        /// <summary>
        /// Maximum possible password size in bytes (will be padded to be divisible by 4)
        /// </summary>
        public int MaxPasswordSize { get; private set; }
        public byte[] AllValues { get; private set; }
        public int[] PermutationLengths { get; private set; }
        public int[] PermutationSizes { get; private set; }
        public string[] AllWords { get; set; }

        public bool isComp, isEc, hasLot;
        public byte[] encryptedBA;
        public uint salt;


        public bool Process(string bip38, int passLength, out string error)
        {
            // I don't think anyone has a 1 char password so we take the lazy route and reject it (at least for now)
            if (passLength <= 1)
            {
                error = "Passwords smaller than 1 byte are not supported.";
                return false;
            }
            // Passwords bigger than 64 bytes need to be hashed first inside HMACSHA256 so we need a different MainLoop code
            // Considering that 64 byte is too big to brute force, we simply reject it
            if (passLength > Sha256Fo.BlockByteSize)
            {
                error = "Password is too long (bigger than SHA256 block size).";
                return false;
            }

            if (!InputService.IsValidBase58Bip38(bip38, out error))
            {
                return false;
            }
            else if (!InputService.TryDecodeBip38(bip38, out encryptedBA, out byte[] saltBa, out isComp, out isEc, out hasLot, out error))
            {
                return false;
            }
            else
            {
                salt = (uint)(saltBa[0] << 24 | saltBa[1] << 16 | saltBa[2] << 8 | saltBa[3]);
            }

            PasswordLength = passLength;

            error = string.Empty;
            return true;
        }


        public bool SetValues(string[][] result, out string error)
        {
            if (result.Length != PasswordLength || result.Any(x => x.Length < 1))
            {
                error = "Invalid array length.";
                return false;
            }

            int totalLen = 0;
            for (int i = 0; i < result.Length; i++)
            {
                if (result[i].Length < 1)
                {
                    error = "At least 2 possible items is needed.";
                    return false;
                }
                totalLen += result[i].Length;
            }

            PermutationLengths = new int[totalLen];
            PermutationCounts = new int[PasswordLength];
            PermutationSizes = new int[PasswordLength];

            FastStream stream = new();
            int index1 = 0;
            int index2 = 0;
            MaxPasswordSize = 0;
            foreach (string[] item in result)
            {
                int max = 0;
                foreach (string s in item)
                {
                    byte[] t = Encoding.UTF8.GetBytes(s);
                    stream.Write(t);
                    PermutationLengths[index1++] = t.Length;
                    PermutationSizes[index2] += t.Length;

                    if (s.Length > max)
                    {
                        max = s.Length;
                    }
                }
                Debug.Assert(max > 0);
                MaxPasswordSize += max;

                PermutationCounts[index2++] = item.Length;
            }

            while (MaxPasswordSize % 4 != 0)
            {
                MaxPasswordSize++;
            }
            if (MaxPasswordSize > Sha256Fo.BlockByteSize)
            {
                error = "Password is too long (bigger than SHA256 block size).";
                return false;
            }

            AllValues = stream.ToByteArray();

            error = string.Empty;
            return true;
        }
    }
}
