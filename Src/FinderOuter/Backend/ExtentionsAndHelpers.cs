// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System;
using System.Numerics;
using System.Text;

namespace FinderOuter.Backend
{
    /// <summary>
    /// The exception that is thrown when something very unlikely happens. Usually used in cryptography.
    /// </summary>
    public class UnlikelyException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="UnlikelyException"/> with a specified error message 
        /// and will add additioanl message to the start of it.
        /// </summary>
        /// <param name="message">
        /// The error message that explains the reason for the exception and should contain additional data for error reporting.
        /// An additional message will be appended to the beginning of it explaining what to do.
        /// </param>
        public UnlikelyException(string message) : base($"{MessageBase}{message}") { }
        /// <summary>
        /// Initializes a new instance of the <see cref="UnlikelyException"/> with a specified error message 
        /// and a reference to the inner exception. 
        /// An additional message will be appended to the beginning of it explaining what to do.
        /// </summary>
        /// <param name="message">
        /// The error message that explains the reason for the exception and should contain additional data for error reporting.
        /// An additional message will be appended to the beginning of it explaining what to do.
        /// </param>
        /// <param name="innerException">The exception that is the cause of the current exception</param>
        public UnlikelyException(string message, Exception innerException) : base($"{MessageBase}{message}", innerException) { }


        private static readonly string MessageBase =
            $"A highly unlikely exception occured!{Environment.NewLine}" +
            $"Please make sure to report the conditions on GitHub (https://github.com/Coding-Enthusiast){Environment.NewLine}" +
            $"Additional information (if it contains secret information you must consider them compromised):{Environment.NewLine}";

    }





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
            foreach (var arr in arrays)
            {
                if (arr == null)
                {
                    throw new ArgumentNullException(nameof(arr), "Can't concatinate with null array(s)!");
                }
                len += arr.Length;
            }

            byte[] result = new byte[len];

            int offset = 0;
            foreach (var arr in arrays)
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
        /// Appends a new byte to the beginning of the given byte array and returns a new array with a bigger length.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <param name="arr">Source array to append to.</param>
        /// <param name="newItem">The value to append to source.</param>
        /// <returns>The extended array of bytes.</returns>
        public static byte[] AppendToBeginning(this byte[] arr, byte newItem)
        {
            if (arr == null)
                throw new ArgumentNullException(nameof(arr), "Byte array can not be null!");


            byte[] result = new byte[arr.Length + 1];
            result[0] = newItem;
            Buffer.BlockCopy(arr, 0, result, 1, arr.Length);
            return result;
        }


        /// <summary>
        /// Appends a new byte to the end of the given byte array and returns a new array with a bigger length.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <param name="arr">Source array to append to.</param>
        /// <param name="newItem">The value to append to source.</param>
        /// <returns>The extended array of bytes.</returns>
        public static byte[] AppendToEnd(this byte[] arr, byte newItem)
        {
            if (arr == null)
                throw new ArgumentNullException(nameof(arr), "Byte array can not be null!");


            byte[] result = new byte[arr.Length + 1];
            result[^1] = newItem;
            Buffer.BlockCopy(arr, 0, result, 0, arr.Length);
            return result;
        }


        /// <summary>
        /// Creates a copy (clone) of the given byte array, will return null if the source was null instead of throwing an exception.
        /// </summary>
        /// <param name="ba">Byte array to clone</param>
        /// <returns>Copy (clone) of the given byte array</returns>
        public static byte[] CloneByteArray(this byte[] ba)
        {
            if (ba == null)
            {
                return null;
            }
            else
            {
                byte[] result = new byte[ba.Length];
                Buffer.BlockCopy(ba, 0, result, 0, ba.Length);
                return result;
            }
        }


        /// <summary>
        /// Concatinates two given byte arrays and returns a new byte array containing all the elements. 
        /// </summary>
        /// <remarks>
        /// This is a lot faster than Linq (~30 times)
        /// </remarks>
        /// <exception cref="ArgumentNullException"/>
        /// <param name="firstArray">First set of bytes in the final array.</param>
        /// <param name="secondArray">Second set of bytes in the final array.</param>
        /// <returns>The concatinated array of bytes.</returns>
        public static byte[] ConcatFast(this byte[] firstArray, byte[] secondArray)
        {
            if (firstArray == null)
                throw new ArgumentNullException(nameof(firstArray), "First array can not be null!");
            if (secondArray == null)
                throw new ArgumentNullException(nameof(secondArray), "Second array can not be null!");


            byte[] result = new byte[firstArray.Length + secondArray.Length];
            Buffer.BlockCopy(firstArray, 0, result, 0, firstArray.Length);
            Buffer.BlockCopy(secondArray, 0, result, firstArray.Length, secondArray.Length);
            return result;
        }


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
            foreach (var item in first)
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
            foreach (var item in second)
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
        /// Determines whether two byte arrays are equal.
        /// </summary>
        /// <remarks>
        /// This is A LOT faster than Linq.
        /// </remarks>
        /// <exception cref="ArgumentNullException"/>
        /// <param name="first">First byte array for comparing.</param>
        /// <param name="second">Second byte array for comparing.</param>
        /// <returns>True if two sequences were equal, false if otherwise.</returns>
        public static bool IsEqualTo(this byte[] first, byte[] second)
        {
            if (first == null)
                throw new ArgumentNullException(nameof(first), "First byte array can not be null!");
            if (second == null)
                throw new ArgumentNullException(nameof(second), "Second byte array can not be null!");


            // TODO: use Span<byte>.SequenceEqual() it is even faster than this method!
            if (first.Length != second.Length)
            {
                return false;
            }
            if (first.Length == 0) // lengths are equal if we are here
            {
                return true;
            }
            unsafe
            {
                fixed (byte* f = &first[0], s = &second[0])
                {
                    int len = first.Length;
                    byte* cfPt = f; // cfPt is changing first pointer
                    byte* csPt = s;
                    while (len >= 8)
                    {
                        if (*(ulong*)csPt != *(ulong*)cfPt)
                        {
                            return false;
                        }
                        cfPt += 8;
                        csPt += 8;
                        len -= 8;
                    }

                    // Here len can be anything from 0 to 7 and we take 4 of it if possible if>=4
                    if (len >= 4)
                    {
                        if (*(uint*)cfPt != *(uint*)csPt)
                        {
                            return false;
                        }
                        cfPt += 4;
                        csPt += 4;
                        len -= 4;
                    }

                    // Here len can be anything from 0 to 3
                    if (len >= 2)
                    {
                        if (*(ushort*)cfPt != *(ushort*)csPt)
                        {
                            return false;
                        }
                        cfPt += 2;
                        csPt += 2;
                        len -= 2;
                    }

                    // Here len can only be 0 or 1
                    if (len == 1)
                    {
                        if (*csPt != *cfPt)
                        {
                            return false;
                        }
                        // no need to change pointer and len anymore, this was the last item.
                    }
                }
            }

            return true;
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
        /// Creates a new array from the given array by taking a specified number of items starting from a given index.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="IndexOutOfRangeException"/>
        /// <param name="sourceArray">The array containing bytes to take.</param>
        /// <param name="index">Starting index in <paramref name="sourceArray"/>.</param>
        /// <param name="count">Number of elements to take.</param>
        /// <returns>An array of bytes.</returns>
        public static byte[] SubArray(this byte[] sourceArray, int index, int count)
        {
            if (sourceArray == null)
                throw new ArgumentNullException(nameof(sourceArray), "Input can not be null!");
            if (index < 0 || count < 0)
                throw new IndexOutOfRangeException("Index or count can not be negative.");
            if (sourceArray.Length != 0 && index > sourceArray.Length - 1 || sourceArray.Length == 0 && index != 0)
                throw new IndexOutOfRangeException("Index can not be bigger than array length.");
            if (count > sourceArray.Length - index)
                throw new IndexOutOfRangeException("Array is not long enough.");


            byte[] result = new byte[count];
            Buffer.BlockCopy(sourceArray, index, result, 0, count);
            return result;
        }


        /// <summary>
        /// Creates a new array from the given array by taking items starting from a given index.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="IndexOutOfRangeException"/>
        /// <param name="sourceArray">The array containing bytes to take.</param>
        /// <param name="index">Starting index in <paramref name="sourceArray"/>.</param>
        /// <returns>An array of bytes.</returns>
        public static byte[] SubArray(this byte[] sourceArray, int index)
        {
            if (sourceArray == null)
                throw new ArgumentNullException(nameof(sourceArray), "Input can not be null!");
            if (sourceArray.Length != 0 && index > sourceArray.Length - 1 || sourceArray.Length == 0 && index != 0)
                throw new IndexOutOfRangeException("Index can not be bigger than array length.");

            return SubArray(sourceArray, index, sourceArray.Length - index);
        }


        /// <summary>
        /// Creates a new array from the given array by taking the specified number of items from the end of the array.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="IndexOutOfRangeException"/>
        /// <param name="sourceArray">The array containing bytes to take.</param>
        /// <param name="count">Number of elements to take.</param>
        /// <returns>An array of bytes.</returns>
        public static byte[] SubArrayFromEnd(this byte[] sourceArray, int count)
        {
            if (sourceArray == null)
                throw new ArgumentNullException(nameof(sourceArray), $"Input can not be null!");
            if (count < 0)
                throw new IndexOutOfRangeException("Count can not be negative.");
            if (count > sourceArray.Length)
                throw new IndexOutOfRangeException("Array is not long enough.");

            return (count == 0) ? new byte[0] : sourceArray.SubArray(sourceArray.Length - count, count);
        }


        /// <summary>
        /// Converts the given byte array to base-16 (Hexadecimal) encoded string.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <param name="ba">The array of bytes to convert.</param>
        /// <returns>Base-16 (Hexadecimal) encoded string.</returns>
        public static string ToBase16(this byte[] ba)
        {
            if (ba == null)
                throw new ArgumentNullException(nameof(ba), "Byte array can not be null.");


            char[] ca = new char[ba.Length * 2];
            int b;
            for (int i = 0; i < ba.Length; i++)
            {
                b = ba[i] >> 4;
                ca[i * 2] = (char)(87 + b + (((b - 10) >> 31) & -39));
                b = ba[i] & 0xF;
                ca[i * 2 + 1] = (char)(87 + b + (((b - 10) >> 31) & -39));
            }
            return new string(ca);
        }


        /// <summary>
        /// Converts a byte array to base-64 encoded string.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <param name="ba">The array of bytes to convert.</param>
        /// <returns>Base-64 encoded string.</returns>
        public static string ToBase64(this byte[] ba)
        {
            if (ba == null)
                throw new ArgumentNullException(nameof(ba), "Byte array can not be null.");

            return Convert.ToBase64String(ba);
        }


        /// <summary>
        /// Converts a byte array to an ASCII encoded string.
        /// <para/>* Can remove null padding.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <param name="ba">The array of bytes.</param>
        /// <param name="removeNullPadding">If true, will try to remove null padding (from end).</param>
        /// <returns>ASCII encoded string.</returns>
        public static string ToStringAscii(this byte[] ba, bool removeNullPadding = false)
        {
            if (ba == null)
                throw new ArgumentNullException(nameof(ba), "Byte array can not be null.");


            if (removeNullPadding)
            {
                ba = ba.TrimEnd();
            }
            return Encoding.ASCII.GetString(ba);
        }


        /// <summary>
        /// Converts a byte array to a UTF-8 encoded string.
        /// <para/>* Can remove null padding.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <param name="ba">The array of bytes.</param>
        /// <param name="removeNullPadding">If true, will try to remove null padding (from end).</param>
        /// <returns>ASCII encoded string.</returns>
        public static string ToStringUtf8(this byte[] ba, bool removeNullPadding = false)
        {
            if (ba == null)
                throw new ArgumentNullException(nameof(ba), "Byte array can not be null.");


            if (removeNullPadding)
            {
                ba = ba.TrimEnd();
            }
            return Encoding.UTF8.GetString(ba);
        }


        /// <summary>
        /// Converts the given arbitrary length bytes to a its equivalant <see cref="BigInteger"/>.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <param name="ba">The array of bytes to convert.</param>
        /// <param name="isBigEndian">Endianness of given bytes.</param>
        /// <param name="treatAsPositive">If true will treat the given bytes as always a positive integer.</param>
        /// <returns>A BigInteger.</returns>
        public static BigInteger ToBigInt(this byte[] ba, bool isBigEndian, bool treatAsPositive)
        {
            if (ba == null)
                throw new ArgumentNullException(nameof(ba), "Byte array can not be null.");


            if (ba.Length == 0)
            {
                return BigInteger.Zero;
            }

            // Make a copy of the array to avoid changing original array in case a reverse was needed.
            byte[] bytesToUse = new byte[ba.Length];
            Buffer.BlockCopy(ba, 0, bytesToUse, 0, ba.Length);

            // BigInteger constructor takes little-endian bytes
            if (isBigEndian)
            {
                Array.Reverse(bytesToUse);
            }

            if (treatAsPositive && (bytesToUse[^1] & 0x80) > 0)
            {
                bytesToUse = bytesToUse.AppendToEnd(0);
            }

            return new BigInteger(bytesToUse);
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


        /// <summary>
        /// Removes zeros from the end of the given byte array.
        /// <para/>NOTE: If there is no zeros to trim, the same byte array will be return (careful about changing the reference)
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <param name="ba">Byte array to trim.</param>
        /// <returns>Trimmed bytes.</returns>
        public static byte[] TrimEnd(this byte[] ba)
        {
            if (ba == null)
                throw new ArgumentNullException(nameof(ba), "Byte array can not be null!");


            int index = ba.Length - 1;
            int count = 0;
            while (index >= 0 && ba[index] == 0)
            {
                index--;
                count++;
            }
            return (count == 0) ? ba : (count == ba.Length) ? new byte[0] : ba.SubArray(0, ba.Length - count);
        }

        /// <summary>
        /// Removes zeros from the beginning of the given byte array.
        /// <para/>NOTE: If there is no zeros to trim, the same byte array will be return (careful about changing the reference)
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <param name="ba">Byte array to trim.</param>
        /// <returns>Trimmed bytes.</returns>
        public static byte[] TrimStart(this byte[] ba)
        {
            if (ba == null)
                throw new ArgumentNullException(nameof(ba), "Byte array can not be null!");


            int index = 0;// index acts both as "index" and "count"
            while (index != ba.Length && ba[index] == 0)
            {
                index++;
            }
            return (index == 0) ? ba : (index == ba.Length) ? new byte[0] : ba.SubArray(index);
        }

    }





    public static class IntExtension
    {
        /// <summary>
        /// Converts the given 32-bit signed integer to a base-16 (hexadecimal) encoded string.
        /// </summary>
        /// <param name="i">The 32-bit signed integer to convert.</param>
        /// <param name="bigEndian">Endianness of the byte array to use for encoding.</param>
        /// <returns>A base-16 encoded string.</returns>
        public static string ToBase16(this int i, bool bigEndian)
        {
            return i.ToByteArray(bigEndian).ToBase16();
        }

        /// <summary>
        /// Converts the given 32-bit signed integer to an array of bytes with a desired endianness.
        /// </summary>
        /// <param name="i">The 32-bit signed integer to convert.</param>
        /// <param name="bigEndian">Endianness of the returned byte array.</param>
        /// <returns>An array of bytes.</returns>
        public static byte[] ToByteArray(this int i, bool bigEndian)
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
        /// Calculates integer modulo n and always returns a positive result between 0 and <paramref name="n"/>-1.
        /// </summary>
        /// <exception cref="ArithmeticException"/>
        /// <exception cref="DivideByZeroException"/>
        /// <param name="big">BigInteger value to use</param>
        /// <param name="n">A positive BigInteger used as divisor.</param>
        /// <returns>Result of mod in [0, n-1] range</returns>
        public static BigInteger Mod(this BigInteger big, BigInteger n)
        {
            if (n == 0)
                throw new DivideByZeroException("Can't divide by zero!");
            if (n < 0)
                throw new ArithmeticException("Divisor can not be negative");


            BigInteger reminder = big % n;
            return reminder.Sign >= 0 ? reminder : reminder + n;
        }


        /// <summary>
        /// Finds modular multiplicative inverse of the integer a such that ax ≡ 1 (mod m) 
        /// using Extended Euclidean algorithm. If gcd(a,m) != 1 an <see cref="ArithmeticException"/> will be thrown.
        /// </summary>
        /// <exception cref="DivideByZeroException"/>
        /// <exception cref="ArithmeticException"/>
        /// <param name="a">The integer a in ax ≡ 1 (mod m)</param>
        /// <param name="m">The modulus m in ax ≡ 1 (mod m)</param>
        /// <returns></returns>
        public static BigInteger ModInverse(this BigInteger a, BigInteger m)
        {
            if (a == 0)
                throw new DivideByZeroException("a can't be 0!");

            if (a == 1) return 1;
            if (a < 0) a = a.Mod(m);

            BigInteger s = 0;
            BigInteger oldS = 1;
            BigInteger r = m;
            BigInteger oldR = a % m;

            while (r != 0)
            {
                BigInteger quotient = oldR / r;

                BigInteger prov = r;
                r = oldR - quotient * prov;
                oldR = prov;

                prov = s;
                s = oldS - quotient * prov;
                oldS = prov;
            }

            // The resulting oldR is the Greatest Common Divisor of (a,m) and it needs to be 1.
            if (oldR != 1)
            {
                throw new ArithmeticException($"Modular multiplicative inverse doesn't exist because greatest common divisor of {nameof(a)} and {nameof(m)} is not 1.");
            }

            return oldS.Mod(m);
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
        /// Converts a <see cref="BigInteger"/> value to a base-16 (hexadecimal) encoded string 
        /// and can remove positive byte sign if available.
        /// </summary>
        /// <param name="big">Big Integer value to convert.</param>
        /// <param name="removePositiveSign">If true will remove the byte indicating positive numbers if available.</param>
        /// <returns>A base16 encoded string.</returns>
        public static string ToBase16(this BigInteger big, bool removePositiveSign)
        {
            return big.ToByteArrayExt(true, removePositiveSign).ToBase16();
        }


        /// <summary>
        /// Converts a <see cref="BigInteger"/> value to its binary representation.
        /// </summary>
        /// <param name="big">Big Integer value to convert.</param>
        /// <returns>A binary representation of the <see cref="BigInteger"/></returns>
        public static string ToBinary(this BigInteger big)
        {
            byte[] bytes = big.ToByteArrayExt(false, true);

            StringBuilder result = new StringBuilder(bytes.Length * 8);
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
