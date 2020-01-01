// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System;
using System.Globalization;
using System.Linq;
using System.Numerics;

namespace FinderOuter.Backend.Encoders
{
    /// <summary>
    /// All base-16 (hexadecimal) strings will be in lower case.
    /// </summary>
    public static class Base16
    {
        private const string Prefix = "0x";
        private const string Base16Chars = "0123456789abcdef";



        /// <summary>
        /// Checks to see if a given string is a valid base-16 encoded string.
        /// </summary>
        /// <param name="hexToCheck">Hex string to check.</param>
        /// <returns>True if valid, fale if otherwise.</returns>
        public static bool IsValid(string hexToCheck)
        {
            if (hexToCheck == null || hexToCheck.Length % 2 != 0)
            {
                return false;
            }
            if (hexToCheck.StartsWith(Prefix))
            {
                hexToCheck = hexToCheck.Substring(2);
            }

            return hexToCheck.All(c => Base16Chars.Contains(char.ToLower(c)));
        }


        /// <summary>
        /// Reverses a given base-16 encoded string.
        /// </summary>
        /// <exception cref="ArgumentException"/>
        /// <param name="hexToReverse">Hex reverse.</param>
        /// <returns>Reversed base16 result.</returns>
        public static string Reverse(string hexToReverse)
        {
            if (!IsValid(hexToReverse))
            {
                throw new ArgumentException("Input is not a valid hex.");
            }

            string start = string.Empty;
            if (hexToReverse.StartsWith(Prefix))
            {
                start = Prefix;
                hexToReverse = hexToReverse.Substring(2);
            }
            byte[] ba = ToByteArray(hexToReverse);
            Array.Reverse(ba);

            return $"{start}{ba.ToBase16()}";
        }


        /// <summary>
        /// Converts a given base-16 encoded string to its byte array representation.
        /// </summary>
        /// <exception cref="ArgumentException"/>
        /// <param name="hex">Hex to convert.</param>
        /// <returns>An array of bytes equivalant of the given base16 encoded string.</returns>
        public static byte[] ToByteArray(string hex)
        {
            if (!IsValid(hex))
            {
                throw new ArgumentException($"Input is not a valid hex. <{hex}>");
            }

            if (hex.StartsWith(Prefix))
            {
                hex = hex.Substring(2);
            }

            byte[] ba = new byte[hex.Length / 2];
            for (int i = 0; i < ba.Length; i++)
            {
                int hi = hex[i * 2] - 65;
                hi = hi + 10 + ((hi >> 31) & 7);

                int lo = hex[i * 2 + 1] - 65;
                lo = lo + 10 + ((lo >> 31) & 7) & 0x0f;

                ba[i] = (byte)(lo | hi << 4);
            }
            return ba;
        }


        /// <summary>
        /// Conversts a given string to base-16 encoded string.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <param name="s">String to convert.</param>
        /// <param name="bLen">Length of the resulting hex in bytes (used for null padding). 
        /// if used, it should be bigger or equal to final result size. 
        /// Default is 0 which doesn't change the result size</param>
        /// <returns>A base-16 encoded string.</returns>
        public static string FromString(string s, int bLen = 0)
        {
            if (s == null) // Empty string is accepted.
            {
                throw new ArgumentNullException(nameof(s), "Input can not be null.");
            }

            string hex = string.Join("", s.Select(c => ((int)c).ToString("x2")));

            if (bLen == 0)
            {
                return hex;
            }
            else
            {
                if ((2 * bLen) < hex.Length)
                {
                    throw new ArgumentOutOfRangeException(nameof(bLen), "Base16 encoded result is bigger than asking byte length.");
                }

                return string.Concat(hex, new string('0', (2 * bLen) - hex.Length));
            }
        }


        /// <summary>
        /// Converts a base-16 encoded string to an ASCII encoded string.
        /// <para/>* Can remove null padding.
        /// </summary>
        /// <exception cref="ArgumentException"/>
        /// <param name="hex">Hex to convert.</param>
        /// <param name="removeNullPadding">[Optional] true removes null padding.</param>
        /// <returns>An ASCII encoded string.</returns>
        public static string ToStringAscii(string hex, bool removeNullPadding = false)
        {
            if (!IsValid(hex))
            {
                throw new ArgumentException("Input is not a valid Hex.");
            }

            byte[] ba = ToByteArray(hex); // ToByteArray removes prefix if available.
            return ba.ToStringAscii(removeNullPadding);
        }


        /// <summary>
        /// Converts a base-16 encoded string to a <see cref="BigInteger"/>.
        /// </summary>
        /// <exception cref="ArgumentException"/>
        /// <param name="hex">Hex to convert.</param>
        /// <param name="returnPositive">If true will always return a positive number, otherwise will not change the sign.</param>
        /// <returns>A <see cref="BigInteger"/> equal to the given hex.</returns>
        public static BigInteger ToBigInt(string hex, bool returnPositive)
        {
            if (!IsValid(hex))
            {
                throw new ArgumentException("Input is not a valid Hex.");
            }

            byte[] ba = ToByteArray(hex);
            return ba.ToBigInt(true, returnPositive);
        }


        /// <summary>
        /// Converts a base-16 encoded string to its unsigned 8-bit integer equivalant.
        /// </summary>
        /// <exception cref="ArgumentException"/>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <param name="hex">Hex to convert.</param>
        /// <returns>An 8-bit unsigned integer.</returns>
        public static byte ToByte(string hex)
        {
            if (!IsValid(hex))
            {
                throw new ArgumentException("Input is not a valid Hex.");
            }
            if (hex.StartsWith(Prefix))
            {
                hex = hex.Substring(2);
            }
            if (hex.Length != sizeof(byte) * 2)
            {
                throw new ArgumentOutOfRangeException(nameof(hex), "Inputs can only be 1 byte.");
            }

            return byte.Parse(hex, NumberStyles.HexNumber);
        }


        /// <summary>
        /// Converts a base-16 encoded string to its unsigned 16-bit integer equivalant.
        /// </summary>
        /// <exception cref="ArgumentException"/>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <param name="hex">Hex to convert.</param>
        /// <param name="bigEndian">Endianness of the hex, default is big-endian (true).</param>
        /// <returns>A 16-bit unsigned integer.</returns>
        public static ushort ToUint16(string hex, bool bigEndian = true)
        {
            if (!IsValid(hex))
            {
                throw new ArgumentException("Input is not a valid Hex.");
            }
            if (hex.StartsWith(Prefix))
            {
                hex = hex.Substring(2);
            }
            if (hex.Length != sizeof(ushort) * 2)
            {
                throw new ArgumentOutOfRangeException(nameof(hex), "Input can only be 2 bytes.");
            }

            byte[] ba = ToByteArray(hex);
            return ba.ToUInt16(bigEndian);
        }


        /// <summary>
        /// Converts a base-16 encoded string to its unsigned 32-bit integer equivalant.
        /// </summary>
        /// <exception cref="ArgumentException"/>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <param name="hex">Hex to convert.</param>
        /// <param name="bigEndian">Endianness of the hex, default is big-endian (true).</param>
        /// <returns>A 32-bit unsigned integer.</returns>
        public static uint ToUint32(string hex, bool bigEndian = true)
        {
            if (!IsValid(hex))
            {
                throw new ArgumentException("Input is not a valid Hex.");
            }
            if (hex.StartsWith(Prefix))
            {
                hex = hex.Substring(2);
            }
            if (hex.Length != sizeof(uint) * 2)
            {
                throw new ArgumentOutOfRangeException(nameof(hex), "Input can only be 4 byte.");
            }

            byte[] ba = ToByteArray(hex);
            return ba.ToUInt32(bigEndian);
        }


        /// <summary>
        /// Converts a base-16 encoded string to its unsigned 64-bit integer equivalant.
        /// </summary>
        /// <exception cref="ArgumentException"/>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <param name="hex">Hex to convert.</param>
        /// <param name="bigEndian">Endianness of the hex, default is big-endian (true).</param>
        /// <returns>A 64-bit unsigned integer.</returns>
        public static ulong ToUint64(string hex, bool bigEndian = true)
        {
            if (!IsValid(hex))
            {
                throw new ArgumentException("Input is not a valid Hex.");
            }
            if (hex.StartsWith(Prefix))
            {
                hex = hex.Substring(2);
            }
            if (hex.Length != sizeof(ulong) * 2)
            {
                throw new ArgumentOutOfRangeException(nameof(hex), "Input can only be 8 byte.");
            }

            byte[] ba = ToByteArray(hex);
            return ba.ToUInt64(bigEndian);
        }

    }
}
