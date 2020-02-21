// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend.Cryptography.Hashing;
using System;
using System.Linq;
using System.Numerics;
using System.Text;

namespace FinderOuter.Backend.Encoders
{
    /// <summary>
    /// This is the encoding bitcoin uses to convert byte arrays into human readable strings. 
    /// It has the ability to add a checksum for error detection.
    /// https://en.bitcoin.it/wiki/Base58Check_encoding
    /// </summary>
    public class Base58
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Base58"/> using parameters of the given <see cref="ICoin"/>.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <param name="coin">Coin to use</param>
        public Base58()
        {
            b58Chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
            hash = new Sha256(true);
        }



        private const int CheckSumSize = 4;
        protected string b58Chars;
        private readonly IHashFunction hash;
        protected int baseValue = 58;
        protected int logBaseValue = 733;



        /// <summary>
        /// Checks to see if a given string is a valid base-58 encoded string with a valid checksum.
        /// </summary>
        /// <param name="encoded">Input string to check.</param>
        /// <returns>True if input was a valid base-58 encoded string with checksum, false if otherwise.</returns>
        public bool IsValid(string encoded)
        {
            return HasValidChars(encoded) && HasValidCheckSum(encoded);
        }


        internal bool HasValidChars(string val)
        {
            if (val == null) // We consider empty string to be valid (white space will be caught in next condition)
            {
                return false;
            }

            if (!val.All(c => b58Chars.Contains(c)))
            {
                return false;
            }

            return true;
        }

        internal bool HasValidCheckSum(string val)
        {
            byte[] data = DecodeWithoutValidation(val);
            if (data.Length < CheckSumSize)
            {
                return false;
            }

            byte[] dataWithoutCheckSum = data.SubArray(0, data.Length - CheckSumSize);
            byte[] checkSum = data.SubArrayFromEnd(CheckSumSize);
            byte[] calculatedCheckSum = CalculateCheckSum(dataWithoutCheckSum);

            return checkSum[0] == calculatedCheckSum[0]
                && checkSum[1] == calculatedCheckSum[1]
                && checkSum[2] == calculatedCheckSum[2]
                && checkSum[3] == calculatedCheckSum[3];
        }

        private byte[] CalculateCheckSum(byte[] data)
        {
            return hash.ComputeHash(data).SubArray(0, CheckSumSize);
        }


        /// <summary>
        /// Converts a base-58 encoded string back to its byte array representation.
        /// </summary>
        /// <exception cref="FormatException"/>
        /// <param name="encoded">Base-58 encoded string.</param>
        /// <returns>Byte array of the given string.</returns>
        public byte[] Decode(string encoded)
        {
            if (!HasValidChars(encoded))
                throw new FormatException($"Input is not a valid Base-{baseValue} encoded string.");

            return DecodeWithoutValidation(encoded);
        }


        /// <summary>
        /// Converts a valid base-58 encoded string back to its byte array representation.
        /// <para/> * Does not check validity of characters. Use <see cref="HasValidChars(string)"/> before calling this method.
        /// </summary>
        /// <remarks>
        /// By skipping validation (Linq.All) this method becomes 4 times faster.
        /// This is also 6 times faster than using BigInteger since it decodes directly to base-256.
        /// </remarks>
        /// <param name="validB58EncodedString">A valid base-58 encoded string.</param>
        /// <returns>Byte array of the given base-58 string.</returns>
        private byte[] DecodeWithoutValidation(string validB58EncodedString)
        {
            int index = 0;
            int leadingZeroCount = 0;
            while (index < validB58EncodedString.Length && validB58EncodedString[index] == '1')
            {
                leadingZeroCount++;
                index++;
            }

            // This is a basic base conversion based on a simple principle that the total value is calculated like this:
            // charIndex0 * 58^0 + charIndex1 * 58^1 + charIndex2 * 58^2 = charIndex0 + 58*(charIndex1 + 58*(charIndex2)) ...

            // Base-256 (byte array) in big-endian order
            byte[] b256 = new byte[(validB58EncodedString.Length - index) * logBaseValue / 1000 + 1]; // log(58) / log(256), rounded up.
            for (; index < validB58EncodedString.Length; index++)
            {
                int carry = b58Chars.IndexOf(validB58EncodedString[index]);
                for (int i = b256.Length - 1; i >= 0; i--)
                {
                    carry += baseValue * b256[i];
                    b256[i] = (byte)(carry % 256);
                    carry /= 256;
                }
            }

            // Skip leading zeroes in Base-256.
            int zeros = 0;
            while (zeros < b256.Length && b256[zeros] == 0)
            {
                zeros++;
            }

            byte[] result = new byte[leadingZeroCount + (b256.Length - zeros)];
            for (int i = leadingZeroCount; i < result.Length; i++)
            {
                result[i] = b256[zeros++];
            }
            return result;
        }


        /// <summary>
        /// Converts a base-58 encoded string back to its byte array representation while validating and removing checksum bytes.
        /// </summary>
        /// <exception cref="FormatException"/>
        /// <param name="b58EncodedStringWithCheckSum">Base-58 encoded string with checksum.</param>
        /// <returns>Byte array of the given string.</returns>
        public byte[] DecodeWithCheckSum(string b58EncodedStringWithCheckSum)
        {
            if (!HasValidChars(b58EncodedStringWithCheckSum))
            {
                throw new FormatException($"Input is not a valid base-{baseValue} encoded string.");
            }

            byte[] data = DecodeWithoutValidation(b58EncodedStringWithCheckSum);
            if (data.Length < CheckSumSize)
            {
                throw new FormatException($"Input is not a valid base-{baseValue} encoded string.");
            }

            byte[] dataWithoutCheckSum = data.SubArray(0, data.Length - CheckSumSize);
            byte[] checkSum = data.SubArrayFromEnd(CheckSumSize);
            byte[] calculatedCheckSum = CalculateCheckSum(dataWithoutCheckSum);

            if (!checkSum.IsEqualTo(calculatedCheckSum))
            {
                throw new FormatException("Invalid checksum.");
            }

            return dataWithoutCheckSum;
        }


        /// <summary>
        /// Converts the given byte array to its equivalent string representation that is encoded with base-58 digits.
        /// </summary>
        /// <remarks>
        /// Unlike Decode functions, using BigInteger here makes things slightly faster. 
        /// The difference will be more noticeable with larger byte arrays such as extended keys (BIP32).
        /// </remarks>
        /// <exception cref="ArgumentNullException"/>
        /// <param name="data">Byte array to encode.</param>
        /// <returns>The string representation in base-58.</returns>
        public string Encode(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data), "Input can not be null!");


            BigInteger big = data.ToBigInt(true, true);

            StringBuilder result = new StringBuilder();
            while (big > 0)
            {
                big = BigInteger.DivRem(big, baseValue, out BigInteger remainder);
                result.Insert(0, b58Chars[(int)remainder]);
            }

            // Append `1` for each leading 0 byte
            for (var i = 0; i < data.Length && data[i] == 0; i++)
            {
                result.Insert(0, '1');
            }

            return result.ToString();
        }


        /// <summary>
        /// Converts the given byte array to its equivalent string representation that is encoded with base-58 digits,
        /// with 4 byte appended checksum.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <param name="data">Byte array to encode.</param>
        /// <returns>The string representation in base-58 with a checksum.</returns>
        public string EncodeWithCheckSum(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data), "Input can not be null!");


            byte[] checkSum = CalculateCheckSum(data);
            return Encode(data.ConcatFast(checkSum));
        }

    }
}
