// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using System;
using System.Numerics;
using System.Text;

namespace FinderOuter.Backend
{
    /// <summary>
    /// Helper class for working with byte arrays
    /// </summary>
    public class ByteArray
    {
        /// <summary>
        /// Concatinates a list of arrays together and returns a bigger array containing all the elements.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <param name="arrays">Array of byte arrays to concatinate.</param>
        /// <returns>An array of bytes.</returns>
        public static byte[] ConcatArrays(params byte[][] arrays)
        {
            if (arrays == null)
                throw new ArgumentNullException(nameof(arrays), "Array params can not be null.");

            // Linq is avoided to increase speed.
            int len = 0;
            foreach (byte[] arr in arrays)
            {
                if (arr == null)
                {
                    throw new ArgumentNullException(nameof(arr), "Can't concatinate with null array(s)!");
                }
                len += arr.Length;
            }

            byte[] result = new byte[len];

            int offset = 0;
            foreach (byte[] arr in arrays)
            {
                Buffer.BlockCopy(arr, 0, result, offset, arr.Length);
                offset += arr.Length;
            }

            return result;
        }
    }





    public static class ByteArrayExtension
    {
        /// <summary>
        /// Compares a given byte arrays to another and returns 1 if bigger, -1 if smaller and 0 if equal.
        /// <para/>* Considers byte arrays as representing integral values so both byte arrays should be in big endian 
        /// and starting zeros will be ignored.
        /// </summary>
        /// <remarks>
        /// This is 10 times faster than converting byte arrays to a BigInteger and comparing that.
        /// </remarks>
        /// <exception cref="ArgumentNullException"/>
        /// <param name="first">First byte array for comparison.</param>
        /// <param name="second">The byte array to compare to.</param>
        /// <returns>1 if first is bigger, -1 if first is smaller and 0 if both are equal.</returns>
        public static int CompareTo(this byte[] first, byte[] second)
        {
            if (first == null)
                throw new ArgumentNullException(nameof(first), "First byte array can not be null!");
            if (second == null)
                throw new ArgumentNullException(nameof(second), "Second byte array can not be null!");


            int zeros1 = 0;
            int zeros2 = 0;
            foreach (byte item in first)
            {
                if (item == 0)
                {
                    zeros1++;
                }
                else
                {
                    break;
                }
            }
            foreach (byte item in second)
            {
                if (item == 0)
                {
                    zeros2++;
                }
                else
                {
                    break;
                }
            }

            if (first.Length - zeros1 > second.Length - zeros2)
            {
                return 1;
            }
            else if (first.Length - zeros1 < second.Length - zeros2)
            {
                return -1;
            }
            else if (first.Length - zeros1 == 0 && second.Length - zeros2 == 0)
            {
                return 0;
            }
            else
            {
                unsafe
                {
                    fixed (byte* f = &first[0], s = &second[0])
                    {
                        for (int i = 0; i < first.Length - zeros1; i++)
                        {
                            if (f[i + zeros1] > s[i + zeros2])
                            {
                                return 1;
                            }
                            else if (f[i + zeros1] < s[i + zeros2])
                            {
                                return -1;
                            }
                        }
                    }
                }
            }

            return 0;
        }


        /// <summary>
        /// Returns binary length of the given byte array according to its endianness.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <param name="ba">Bytes to use</param>
        /// <param name="isBigEndian">Endianness of the byte array</param>
        /// <param name="removeZeros">
        /// True will remove both zero bytes and zero bits.
        /// If you want to remove zero bytes and not zero bits, 
        /// call <see cref="TrimStart(byte[])"/> or <see cref="TrimEnd(byte[])"/> depending on endianness, before calling this function.
        /// <para/>Example (big-endian): 0000_0000 0000_0101 -> true:3 false:16
        /// </param>
        /// <returns>Binary length</returns>
        public static int GetBitLength(this byte[] ba, bool isBigEndian, bool removeZeros = true)
        {
            if (ba == null)
                throw new ArgumentNullException(nameof(ba), "Input can not be null!");

            if (ba.Length == 0)
                return 0;

            if (!removeZeros)
            {
                return ba.Length * 8;
            }
            else
            {
                byte[] trimmed = isBigEndian ? ba.TrimStart() : ba.TrimEnd();
                if (trimmed.Length == 0)
                {
                    return 0;
                }

                int len = 0;
                byte last = isBigEndian ? trimmed[0] : trimmed[^1];
                while (last != 0)
                {
                    last >>= 1;
                    len++;
                }
                return len + ((trimmed.Length - 1) * 8);
            }
        }


        /// <summary>
        /// Creates a copy of the given byte array padded with zeros on the left (inserted at index 0) to the given length.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="IndexOutOfRangeException"/>
        /// <param name="ba">Byte array to pad</param>
        /// <param name="finalSize">Desired final size of the returned array.</param>
        /// <returns>A zero padded array of bytes.</returns>
        public static byte[] PadLeft(this byte[] ba, int finalSize)
        {
            if (ba == null)
                throw new ArgumentNullException(nameof(ba), "Input can not be null!");
            if (finalSize < 0)
                throw new IndexOutOfRangeException($"{nameof(finalSize)} can not be negative.");
            if (ba.Length > finalSize)
                throw new IndexOutOfRangeException("Input is longer than final size.");


            byte[] result = new byte[finalSize];
            Buffer.BlockCopy(ba, 0, result, finalSize - ba.Length, ba.Length);
            return result;
        }


        /// <summary>
        /// Creates a copy of the given byte array padded with zeros on the right (inserted after last index) to the given length.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="IndexOutOfRangeException"/>
        /// <param name="ba">Byte array to pad</param>
        /// <param name="finalSize">Desired final size of the returned array.</param>
        /// <returns>A zero padded array of bytes.</returns>
        public static byte[] PadRight(this byte[] ba, int finalSize)
        {
            if (ba == null)
                throw new ArgumentNullException(nameof(ba), "Input can not be null!");
            if (finalSize < 0)
                throw new IndexOutOfRangeException($"{nameof(finalSize)} can not be negative.");
            if (ba.Length > finalSize)
                throw new IndexOutOfRangeException("Input is longer than final size.");


            byte[] result = new byte[finalSize];
            Buffer.BlockCopy(ba, 0, result, 0, ba.Length);
            return result;
        }


        /// <summary>
        /// Converts the given four bytes to a 32-bit signed integer.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <param name="ba">The array of bytes to convert (must be 4 bytes long).</param>
        /// <param name="isBigEndian">Endianness of given bytes.</param>
        /// <returns>A 32-bit signed integer.</returns>
        public static int ToInt32(this byte[] ba, bool isBigEndian)
        {
            if (ba == null)
                throw new ArgumentNullException(nameof(ba), "Byte array can not be null.");
            if (ba.Length != sizeof(int))
                throw new ArgumentOutOfRangeException(nameof(ba), ba.ToBase16(), "Byte array must be 4 bytes.");


            unchecked
            {
                return isBigEndian ?
                    ba[3] | (ba[2] << 8) | (ba[1] << 16) | (ba[0] << 24) :
                    ba[0] | (ba[1] << 8) | (ba[2] << 16) | (ba[3] << 24);
            }
        }


        /// <summary>
        /// Converts the given eight bytes to a 64-bit signed integer.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <param name="ba">The array of bytes to convert (must be 8 bytes long).</param>
        /// <param name="isBigEndian">Endianness of given bytes.</param>
        /// <returns>A 32-bit signed integer.</returns>
        public static long ToInt64(this byte[] ba, bool isBigEndian)
        {
            if (ba == null)
                throw new ArgumentNullException(nameof(ba), "Byte array can not be null.");
            if (ba.Length != sizeof(long))
                throw new ArgumentOutOfRangeException(nameof(ba), ba.ToBase16(), "Byte array must be 8 bytes.");


            unchecked
            {
                return isBigEndian ?
                    ba[7] | ((long)ba[6] << 8) | ((long)ba[5] << 16) | ((long)ba[4] << 24) |
                            ((long)ba[3] << 32) | ((long)ba[2] << 40) | ((long)ba[1] << 48) | ((long)ba[0] << 56) :
                    ba[0] | ((long)ba[1] << 8) | ((long)ba[2] << 16) | ((long)ba[3] << 24) |
                            ((long)ba[4] << 32) | ((long)ba[5] << 40) | ((long)ba[6] << 48) | ((long)ba[7] << 56);
            }
        }


        /// <summary>
        /// Converts the given two bytes to a 16-bit unsigned integer.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <param name="ba">The array of bytes to convert (must be 2 bytes long).</param>
        /// <param name="isBigEndian">Endianness of given bytes.</param>
        /// <returns>A 16-bit unsigned integer.</returns>
        public static ushort ToUInt16(this byte[] ba, bool isBigEndian)
        {
            if (ba == null)
                throw new ArgumentNullException(nameof(ba), "Byte array can not be null.");
            if (ba.Length != sizeof(ushort))
                throw new ArgumentOutOfRangeException(nameof(ba), ba.ToBase16(), "Byte array must be 2 bytes.");


            unchecked
            {
                return isBigEndian ?
                    (ushort)(ba[1] | (ba[0] << 8)) :
                    (ushort)(ba[0] | (ba[1] << 8));
            }
        }

        /// <summary>
        /// Converts the given two bytes to a 32-bit unsigned integer.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <param name="ba">The array of bytes to convert (must be 4 bytes long).</param>
        /// <param name="isBigEndian">Endianness of given bytes.</param>
        /// <returns>A 32-bit unsigned integer.</returns>
        public static uint ToUInt32(this byte[] ba, bool isBigEndian)
        {
            if (ba == null)
                throw new ArgumentNullException(nameof(ba), "Byte array can not be null.");
            if (ba.Length != sizeof(uint))
                throw new ArgumentOutOfRangeException(nameof(ba), ba.ToBase16(), "Byte array must be 4 bytes.");


            unchecked
            {
                return isBigEndian ?
                    (uint)(ba[3] | (ba[2] << 8) | (ba[1] << 16) | (ba[0] << 24)) :
                    (uint)(ba[0] | (ba[1] << 8) | (ba[2] << 16) | (ba[3] << 24));
            }
        }

        /// <summary>
        /// Converts the given two bytes to a 64-bit unsigned integer.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <param name="ba">The array of bytes to convert (must be 8 bytes long).</param>
        /// <param name="isBigEndian">Endianness of given bytes.</param>
        /// <returns>A 64-bit unsigned integer.</returns>
        public static ulong ToUInt64(this byte[] ba, bool isBigEndian)
        {
            if (ba == null)
                throw new ArgumentNullException(nameof(ba), "Byte array can not be null.");
            if (ba.Length != sizeof(ulong))
                throw new ArgumentOutOfRangeException(nameof(ba), ba.ToBase16(), "Byte array must be 8 bytes.");


            unchecked
            {
                return isBigEndian ?
                    ba[7] | ((ulong)ba[6] << 8) | ((ulong)ba[5] << 16) | ((ulong)ba[4] << 24) |
                            ((ulong)ba[3] << 32) | ((ulong)ba[2] << 40) | ((ulong)ba[1] << 48) | ((ulong)ba[0] << 56) :
                    ba[0] | ((ulong)ba[1] << 8) | ((ulong)ba[2] << 16) | ((ulong)ba[3] << 24) |
                            ((ulong)ba[4] << 32) | ((ulong)ba[5] << 40) | ((ulong)ba[6] << 48) | ((ulong)ba[7] << 56);
            }
        }
    }





    public static class LongExtension
    {
        /// <summary>
        /// Converts the given 64-bit signed integer to a base-16 (hexadecimal) encoded string.
        /// </summary>
        /// <param name="i">The 64-bit signed integer to convert.</param>
        /// <param name="bigEndian">Endianness of the byte array to use for encoding.</param>
        /// <returns>A base-16 encoded string.</returns>
        public static string ToBase16(this long i, bool bigEndian)
        {
            return i.ToByteArray(bigEndian).ToBase16();
        }

        /// <summary>
        /// Converts the given 64-bit signed integer to an array of bytes with a desired endianness.
        /// </summary>
        /// <param name="i">The 64-bit signed integer to convert.</param>
        /// <param name="bigEndian">Endianness of the returned byte array.</param>
        /// <returns>An array of bytes.</returns>
        public static byte[] ToByteArray(this long i, bool bigEndian)
        {
            unchecked
            {
                if (bigEndian)
                {
                    return new byte[]
                    {
                        (byte)(i >> 56),
                        (byte)(i >> 48),
                        (byte)(i >> 40),
                        (byte)(i >> 32),
                        (byte)(i >> 24),
                        (byte)(i >> 16),
                        (byte)(i >> 8),
                        (byte)i
                    };
                }
                else
                {
                    return new byte[]
                    {
                        (byte)i,
                        (byte)(i >> 8),
                        (byte)(i >> 16),
                        (byte)(i >> 24),
                        (byte)(i >> 32),
                        (byte)(i >> 40),
                        (byte)(i >> 48),
                        (byte)(i >> 56)
                    };
                }
            }
        }

    }





    public static class UIntExtension
    {
        /// <summary>
        /// Converts the given 8-bit unsigned integer to a base-16 (hexadecimal) encoded string.
        /// </summary>
        /// <param name="i">The 8-bit unsigned integer to convert.</param>
        /// <returns>A base-16 encoded string.</returns>
        public static string ToBase16(this byte i)
        {
            return (new byte[] { i }).ToBase16();
        }

        /// <summary>
        /// Converts the given 16-bit unsigned integer to a base-16 (hexadecimal) encoded string.
        /// </summary>
        /// <param name="i">The 16-bit unsigned integer to convert.</param>
        /// <param name="bigEndian">Endianness of the byte array to use for encoding.</param>
        /// <returns>A base-16 encoded string.</returns>
        public static string ToBase16(this ushort i, bool bigEndian)
        {
            return i.ToByteArray(bigEndian).ToBase16();
        }

        /// <summary>
        /// Converts the given 32-bit unsigned integer to a base-16 (hexadecimal) encoded string.
        /// </summary>
        /// <param name="i">The 32-bit unsigned integer to convert.</param>
        /// <param name="bigEndian">Endianness of the byte array to use for encoding.</param>
        /// <returns>A base-16 encoded string.</returns>
        public static string ToBase16(this uint i, bool bigEndian)
        {
            return i.ToByteArray(bigEndian).ToBase16();
        }

        /// <summary>
        /// Converts the given 64-bit unsigned integer to a base-16 (hexadecimal) encoded string.
        /// </summary>
        /// <param name="i">The 64-bit unsigned integer to convert.</param>
        /// <param name="bigEndian">Endianness of the byte array to use for encoding.</param>
        /// <returns>A base-16 encoded string.</returns>
        public static string ToBase16(this ulong i, bool bigEndian)
        {
            return i.ToByteArray(bigEndian).ToBase16();
        }


        /// <summary>
        /// Converts the given 16-bit unsigned integer to an array of bytes with a desired endianness.
        /// </summary>
        /// <param name="i">The 16-bit unsigned integer to convert.</param>
        /// <param name="bigEndian">Endianness of the returned byte array.</param>
        /// <returns>An array of bytes.</returns>
        public static byte[] ToByteArray(this ushort i, bool bigEndian)
        {
            unchecked
            {
                if (bigEndian)
                {
                    return new byte[]
                    {
                        (byte)(i >> 8),
                        (byte)i
                    };
                }
                else
                {
                    return new byte[]
                    {
                        (byte)i,
                        (byte)(i >> 8)
                    };
                }
            }
        }

        /// <summary>
        /// Converts the given 32-bit unsigned integer to an array of bytes with a desired endianness.
        /// </summary>
        /// <param name="i">The 32-bit unsigned integer to convert.</param>
        /// <param name="bigEndian">Endianness of the returned byte array.</param>
        /// <returns>An array of bytes.</returns>
        public static byte[] ToByteArray(this uint i, bool bigEndian)
        {
            unchecked
            {
                if (bigEndian)
                {
                    return new byte[]
                    {
                        (byte)(i >> 24),
                        (byte)(i >> 16),
                        (byte)(i >> 8),
                        (byte)i
                    };
                }
                else
                {
                    return new byte[]
                    {
                        (byte)i,
                        (byte)(i >> 8),
                        (byte)(i >> 16),
                        (byte)(i >> 24)
                    };
                }
            }
        }

        /// <summary>
        /// Converts the given 64-bit unsigned integer to an array of bytes with a desired endianness.
        /// </summary>
        /// <param name="i">The 64-bit unsigned integer to convert.</param>
        /// <param name="bigEndian">Endianness of the returned byte array.</param>
        /// <returns>An array of bytes.</returns>
        public static byte[] ToByteArray(this ulong i, bool bigEndian)
        {
            unchecked
            {
                if (bigEndian)
                {
                    return new byte[]
                    {
                        (byte)(i >> 56),
                        (byte)(i >> 48),
                        (byte)(i >> 40),
                        (byte)(i >> 32),
                        (byte)(i >> 24),
                        (byte)(i >> 16),
                        (byte)(i >> 8),
                        (byte)i
                    };
                }
                else
                {
                    return new byte[]
                    {
                        (byte)i,
                        (byte)(i >> 8),
                        (byte)(i >> 16),
                        (byte)(i >> 24),
                        (byte)(i >> 32),
                        (byte)(i >> 40),
                        (byte)(i >> 48),
                        (byte)(i >> 56)
                    };
                }
            }
        }

    }





    public static class BigIntegerExtension
    {
        /// <summary>
        /// Returns total number of non-zero bits in binary representation of a positive <see cref="BigInteger"/>. Example:
        /// <para/>0010 = 1
        /// <para/>1010 = 2
        /// </summary>
        /// <remarks>
        /// This uses Brian Kernighan's algorithm with Time Complexity: O(log N)
        /// </remarks>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <param name="big">BigInteger value to use</param>
        /// <returns>Number of 1s.</returns>
        public static int GetBitCount(this BigInteger big)
        {
            if (big < 0)
                throw new ArgumentOutOfRangeException(nameof(big), "Negative numbers are not accepted here!");


            int result = 0;
            while (big != 0)
            {
                result++;
                big &= (big - 1);
            }
            return result;
        }


        /// <summary>
        /// Returns binary length of the given positive <see cref="BigInteger"/>.
        /// </summary>
        /// <remarks>
        /// BigInteger.Log(big, 2) won't work here becasue it is not accurate for very large numbers.
        /// </remarks>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <param name="big">BigInteger value to use</param>
        /// <param name="removeLeadingZeros">
        /// True will remove leading zeros. 
        /// <para/> 0000_0101 -> true:3 false:8
        /// </param>
        /// <returns>Binary length</returns>
        public static int GetBitLength(this BigInteger big, bool removeLeadingZeros)
        {
            if (big < 0)
                throw new ArgumentOutOfRangeException(nameof(big), "Negative numbers are not accepted here!");

            if (big == 0)
            {
                return 0;
            }

            if (!removeLeadingZeros)
            {
                return big.ToByteArrayExt(false, true).Length * 8;
            }
            else
            {
                if (big == 1) return 1;

                int len = 0;
                while (big != 0)
                {
                    big >>= 1;
                    len++;
                }
                return len;
            }
        }


        /// <summary>
        /// Returns square root of the given positive <see cref="BigInteger"/> using Babylonian (aka Heron's) method.
        /// </summary>
        /// <remarks>
        /// The algorithm: https://en.wikipedia.org/wiki/Methods_of_computing_square_roots#Babylonian_method
        /// </remarks>
        /// <exception cref="ArithmeticException"/>
        /// <param name="big">Number to find square root of</param>
        /// <returns>Square root result</returns>
        public static BigInteger Sqrt(this BigInteger big)
        {
            if (big.Sign < 0)
                throw new ArithmeticException("This function doesn't work for negative numbers.");

            if (big == 0)
                return 0;
            if (big < long.MaxValue)
                return new BigInteger((int)Math.Sqrt((double)big));

            // The initial estimate:
            int bitLength = big.GetBitLength(true);
            BigInteger root = BigInteger.One << (bitLength / 2);

            while (!IsSqrt(big, root))
            {
                // 1/2 (x0 + s/x0)
                root = (root + (big / root)) / 2;
            }

            return root;
        }
        private static bool IsSqrt(BigInteger n, BigInteger root)
        {
            BigInteger lowerBound = root * root;
            BigInteger upperBound = (root + 1) * (root + 1);

            return (lowerBound <= n) && (n < upperBound);
        }


        /// <summary>
        /// Converts a <see cref="BigInteger"/> value to its binary representation.
        /// </summary>
        /// <param name="big">Big Integer value to convert.</param>
        /// <returns>A binary representation of the <see cref="BigInteger"/></returns>
        public static string ToBinary(this BigInteger big)
        {
            byte[] bytes = big.ToByteArrayExt(false, true);

            StringBuilder result = new(bytes.Length * 8);
            for (int i = bytes.Length - 1; i >= 0; i--)
            {
                result.Append(Convert.ToString(bytes[i], 2).PadLeft(8, '0'));
            }

            return result.ToString();
        }


        /// <summary>
        /// Converts a <see cref="BigInteger"/> value to a byte array in a desired endianness 
        /// and can remove positive byte sign if available.
        /// </summary>
        /// <remarks>
        /// *Ext is used to make this function different from .Net core's function of the same name.
        /// </remarks>
        /// <param name="big">Big Integer value to convert.</param>
        /// <param name="returnBigEndian">Endianness of bytes in the returned array.</param>
        /// <param name="removePositiveSign">If true will remove the byte indicating positive numbers if available.</param>
        /// <returns>An array of bytes.</returns>
        public static byte[] ToByteArrayExt(this BigInteger big, bool returnBigEndian, bool removePositiveSign)
        {
            byte[] ba = big.ToByteArray(); // Result is always in little-endian

            // Remove positive sign if wanted and if available:
            if (removePositiveSign && ba.Length > 1 && ba[^1] == 0)
            {
                ba = ba.SubArray(0, ba.Length - 1);
            }

            if (returnBigEndian)
            {
                Array.Reverse(ba);
            }

            return ba;
        }
    }
}
