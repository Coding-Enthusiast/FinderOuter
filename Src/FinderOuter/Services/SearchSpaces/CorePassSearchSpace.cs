// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using Autarkysoft.Bitcoin.Encoders;
using FinderOuter.Backend.Hashing;
using System;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace FinderOuter.Services.SearchSpaces
{
    public class CorePassSearchSpace : SearchSpaceBase
    {
        /// <summary>
        /// Number of chars/words in the password
        /// </summary>
        public int PasswordLength { get; private set; }
        /// <summary>
        /// Maximum possible password size in bytes (will be padded to be divisible by 4)
        /// </summary>
        public int MaxPasswordSize { get; private set; }
        public byte[] Encrypted { get; private set; }
        public byte[] Salt { get; private set; }
        public byte[] XOR { get; private set; }
        public int Iteration { get; private set; }
        public byte[] AllValues { get; private set; }
        public int[] PermutationLengths { get; private set; }
        public int[] PermutationSizes { get; private set; }


        public bool Process(string hex, int passLength, out string error)
        {
            if (string.IsNullOrWhiteSpace(hex))
            {
                error = "Input hex can not be null or empty.";
                return false;
            }
            if (!InputService.CheckChars(hex.ToLower(), Base16.CharSet, null, out error))
            {
                return false;
            }
            if (!Base16.TryDecode(hex, out byte[] result))
            {
                // Can happen if the length is not divisible by 2
                error = "Invalid hex string.";
                return false;
            }
            if (result.Length < 70)
            {
                error = $"Input hex is expected to be at least 70 bytes but it is {result.Length} bytes.";
                return false;
            }

            // Start reading the stream
            FastStreamReader stream = new(result);
            if (!stream.FindAndSkip([0x43, 0x00, 0x01, 0x30]))
            {
                error = "Could not find 0x43000130 in the given hex.";
                return false;
            }
            stream.Skip(4);

            if (!stream.TryReadByteArray(48, out byte[] encKey))
            {
                error = "The 48-byte encrypted key was not found in the input hex located after 0x43000130.";
                return false;
            }

            if (!stream.TryReadByte(out byte saltLen))
            {
                error = $"{Errors.EndOfStream.Convert()} (1 byte salt length was not found).";
                return false;
            }

            if (saltLen != 8)
            {
                error = $"Salt lengths other than 8 (input indicates {saltLen}) are not supported.";
                return false;
            }

            if (!stream.TryReadByteArray(8, out byte[] salt))
            {
                error = $"{Errors.EndOfStream.Convert()} (8 byte salt was not found).";
                return false;
            }

            if (!stream.TryReadInt32(out int derivationMethod))
            {
                error = $"{Errors.EndOfStream.Convert()} (4 byte derivation method was not found).";
                return false;
            }

            if (derivationMethod != 0)
            {
                error = $"Only the derivation method 0 is supported.{Environment.NewLine}" +
                        $"The input's derivation method in the given input is {derivationMethod} which means either " +
                        $"the input is broken or a new algorithm was used that is not supported by FinderOuter.";
                return false;
            }

            if (!stream.TryReadInt32(out int iteration))
            {
                error = $"{Errors.EndOfStream.Convert()} (4 byte iteration was not found).";
                return false;
            }

            // TODO: to make writing our future loops simpler we assume iternation count is not bigger than what
            //       fits inside an Int32. Bitcoin core's source code has to be checked to make sure how it treats
            //       this number...
            if (iteration < 0)
            {
                error = $"Your iteration count is huge.{Environment.NewLine}" +
                        $"Report this on GitHub if you want it changed: " +
                        $"Bitcoin core iteration count =0x{iteration.ToByteArray(false).ToBase16()} was rejected.";
                return false;
            }

            // TODO: This length may actually be a CompactInt (bitcoin core source code needs to be checked).
            //       However, since we only support 0 it doesn't matter.
            if (!stream.TryReadByte(out byte extraLen))
            {
                error = $"{Errors.EndOfStream.Convert()} (1 byte extra parameter length was not found).";
                return false;
            }

            if (extraLen != 0)
            {
                error = $"Only the extra parameter length 0 is supported.{Environment.NewLine}" +
                        $"The extra parameter length in the given input is {derivationMethod} which means either " +
                        $"the input is broken or a new algorithm was used that is not supported by FinderOuter.";
                return false;
            }

#if DEBUG
            AssertArray(salt, saltLen);
            AssertArray(encKey, 48);
#endif

            if (passLength < 1)
            {
                error = "Password length must be at least 1.";
                return false;
            }

            PasswordLength = passLength;
            Iteration = iteration;
            Salt = salt;
            Encrypted = encKey.SubArray(32, 16);
            XOR = encKey.SubArray(16, 16);

            error = string.Empty;
            return true;
        }

#if DEBUG
        private static void AssertArray(byte[] data, int size)
        {
            Debug.Assert(data != null);
            Debug.Assert(data.Length == size);
        }
#endif


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
            if (MaxPasswordSize > Sha512Fo.BlockByteSize)
            {
                error = "Password is too long (bigger than SHA512 block size).";
                return false;
            }

            AllValues = stream.ToByteArray();

            error = string.Empty;
            return true;
        }
    }
}
