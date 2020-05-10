// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using System;

namespace FinderOuter.Backend
{
    /// <summary>
    /// Variable length integers used in DER encoding indicating length of the data. Only up to 4 bytes lengths are supported here.
    /// </summary>
    public struct DerInt : IComparable, IComparable<DerInt>, IEquatable<DerInt>
    {
        /// <summary>
        /// Initializes a new instance of <see cref="DerInt"/> using a 32-bit signed integer.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <param name="val">Value to use (must be >= 0)</param>
        public DerInt(int val)
        {
            if (val < 0)
                throw new ArgumentOutOfRangeException(nameof(val), "DerInt value can not be negative!");

            value = (uint)val;
            badEncoding = null;
        }

        /// <summary>
        /// Initializes a new instance of <see cref="DerInt"/> using a 32-bit unsigned integer.
        /// </summary>
        /// <param name="val">Value to use</param>
        public DerInt(uint val)
        {
            value = val;
            badEncoding = null;
        }



        /// <summary>
        /// Integer value of this instance.
        /// </summary>
        public readonly uint value;
        private byte[] badEncoding;



        /// <summary>
        /// Initializes a new instance of <see cref="DerInt"/> by reading it from a byte array using strict encoding rules.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="FormatException"/>
        /// <param name="data">Byte array containing a <see cref="DerInt"/>.</param>
        /// <returns>A new instance of <see cref="DerInt"/></returns>
        public static DerInt ReadFromBytes(byte[] data)
        {
            int i = 0;
            return ReadFromBytes(data, ref i, true);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="DerInt"/> by reading it from a byte array 
        /// starting from the given offset and changing it based on the length of the data that was read.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="IndexOutOfRangeException"/>
        /// <exception cref="FormatException"/>
        /// <param name="data">Byte array containing a <see cref="DerInt"/>.</param>
        /// <param name="offset">Offset in <paramref name="data"/> to start reading from.</param>
        /// <param name="isStrict">If true, string encoding rules will be enforced</param>
        /// <returns>A new instance of <see cref="DerInt"/></returns>
        public static DerInt ReadFromBytes(byte[] data, ref int offset, bool isStrict)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentNullException(nameof(data), "Data can not be null or empty!");
            if (offset < 0)
                throw new IndexOutOfRangeException("Offset can not be negative.");
            if (offset >= data.Length)
                throw new IndexOutOfRangeException("Offset is bigger than data length.");


            if (!TryReadFromBytes(data, ref offset, isStrict, out DerInt result, out string error))
            {
                throw new FormatException(error);
            }
            return result;
        }


        /// <summary>
        /// Reads the <see cref="DerInt"/> value from the given byte array starting from the specified offset, 
        /// changing that offset based on the length of data that was read. The return value indicates success.
        /// </summary>
        /// <param name="data">Byte array containing a <see cref="DerInt"/>.</param>
        /// <param name="offset">Offset in <paramref name="data"/> to start reading from.</param>
        /// <param name="isStrict">If true, string encoding rules will be enforced</param>
        /// <param name="result">The result</param>
        /// <param name="error">Error message (null if sucessful, otherwise will contain information about the failure).</param>
        /// <returns>True if reading was successful, false if otherwise.</returns>
        public static bool TryReadFromBytes(byte[] data, ref int offset, bool isStrict, out DerInt result, out string error)
        {
            if (data == null || data.Length == 0)
            {
                error = "Data can not be null or empty.";
                result = 0;
                return false;
            }
            if (offset < 0)
            {
                error = "Offset can not be negative.";
                result = 0;
                return false;
            }
            if (data.Length - offset < 1)
            {
                error = "Data length is not valid.";
                result = 0;
                return false;
            }


            if (data[offset] <= 127) // 1 byte
            {
                result = new DerInt((uint)data[offset]);
                offset++;
            }
            else if (data[offset] == 128)
            {
                if (isStrict)
                {
                    error = "Size can not be zero.";
                    result = 0;
                    return false;
                }
                else
                {
                    result = new DerInt(0)
                    {
                        badEncoding = new byte[1] { 128 }
                    };
                    offset++;
                    error = null;
                    return true;
                }
            }
            else if (data[offset] == (128 + sizeof(byte))) //0b1000_0001 + 1 byte
            {
                if (data.Length - offset < (1 + sizeof(byte)))
                {
                    error = "Data length is not valid.";
                    result = 0;
                    return false;
                }
                byte val = data[offset + 1];
                if (val <= 127)
                {
                    if (isStrict)
                    {
                        error = "For values less than 128, one byte format should be used.";
                        result = 0;
                        return false;
                    }
                    else
                    {
                        result = new DerInt(val)
                        {
                            badEncoding = new byte[2] { data[offset], data[offset + 1] }
                        };
                        offset += 2;
                        error = null;
                        return true;
                    }
                }
                result = new DerInt((uint)val);
                offset += 2;
            }
            else // Size can be 2, 3 or 4 bytes. Technically it can be bigger sizes too, but we do not support it in this encoding.
            {
                int size = data[offset] & 0b0111_1111;
                if (size > 4)
                {
                    error = "Sizes bigger than 4 bytes are not accepted in this encoding.";
                    result = 0;
                    return false;
                }

                uint val = 0;
                for (int i = 0, j = (size - 1) * 8; i < size; i++, j -= 8)
                {
                    val |= (uint)data[offset + i + 1] << j;
                }

                if (data[offset + 1] == 0)
                {
                    if (isStrict)
                    {
                        error = "Encoded lengths must use the shortest format possible.";
                        result = 0;
                        return false;
                    }
                    else
                    {
                        result = new DerInt(val)
                        {
                            badEncoding = data.SubArray(offset, size + 1)
                        };
                        offset += size + 1;
                        error = null;
                        return true;
                    }
                }

                result = new DerInt(val);
                offset += size + 1;
            }

            error = null;
            return true;
        }


        /// <summary>
        /// Converts this value to its byte array representation.
        /// </summary>
        /// <returns>An array of bytes in big-endian order</returns>
        public byte[] ToByteArray()
        {
            if (badEncoding != null)
            {
                return badEncoding;
            }

            if (value <= 127) // 1 Byte
            {
                return new byte[] { (byte)value };
            }
            else
            {
                byte[] result = value.ToByteArray(true).TrimStart();
                return new byte[] { (byte)(0b1000_0000 | result.Length) }.ConcatFast(result);
            }
        }


        public static implicit operator DerInt(uint val)
        {
            return new DerInt(val);
        }
        public static implicit operator DerInt(ushort val)
        {
            return new DerInt(val);
        }
        public static implicit operator DerInt(byte val)
        {
            return new DerInt(val);
        }
        public static explicit operator DerInt(int val)
        {
            if (val < 0)
                throw new InvalidCastException("DerInt can not be negative");

            return new DerInt(val);
        }

        public static implicit operator uint(DerInt val)
        {
            return val.value;
        }
        public static explicit operator ushort(DerInt val)
        {
            return checked((ushort)val.value);
        }
        public static explicit operator byte(DerInt val)
        {
            return checked((byte)val.value);
        }
        public static explicit operator int(DerInt val)
        {
            return checked((int)val.value);
        }


        public static bool operator >(DerInt left, DerInt right)
        {
            return left.CompareTo(right) > 0;
        }
        public static bool operator >=(DerInt left, DerInt right)
        {
            return left.CompareTo(right) >= 0;
        }
        public static bool operator <(DerInt left, DerInt right)
        {
            return left.CompareTo(right) < 0;
        }
        public static bool operator <=(DerInt left, DerInt right)
        {
            return left.CompareTo(right) <= 0;
        }
        public static bool operator ==(DerInt left, DerInt right)
        {
            return left.CompareTo(right) == 0;
        }
        public static bool operator !=(DerInt left, DerInt right)
        {
            return left.CompareTo(right) != 0;
        }


        #region Interfaces and overrides

        /// <summary>
        /// Compares the value of a given <see cref="DerInt"/> with the value of this instance and 
        /// And returns -1 if smaller, 0 if equal and 1 if bigger.
        /// </summary>
        /// <param name="other">Other <see cref="DerInt"/> to compare to this instance.</param>
        /// <returns>-1 if smaller, 0 if equal and 1 if bigger.</returns>
        public int CompareTo(DerInt other)
        {
            return value.CompareTo(other.value);
        }

        /// <summary>
        /// Checks if the given object is of type <see cref="DerInt"/> and then compares its value with the value of this instance.
        /// Returns -1 if smaller, 0 if equal and 1 if bigger.
        /// </summary>
        /// <exception cref="ArgumentException"/>
        /// <param name="obj">The object to compare to this instance.</param>
        /// <returns>-1 if smaller, 0 if equal and 1 if bigger</returns>
        public int CompareTo(object obj)
        {
            if (obj is null)
                return 1;
            if (!(obj is DerInt))
                throw new ArgumentException($"Object must be of type {nameof(DerInt)}");

            return CompareTo((DerInt)obj);
        }

        /// <summary>
        /// Checks if the value of the given <see cref="DerInt"/> is equal to the value of this instance.
        /// </summary>
        /// <param name="other">Other <see cref="DerInt"/> value to compare to this instance.</param>
        /// <returns>true if the value is equal to the value of this instance; otherwise, false.</returns>
        public bool Equals(DerInt other)
        {
            return CompareTo(other) == 0;
        }

        /// <summary>
        /// Checks if the given object is of type <see cref="DerInt"/> and if its value is equal to the value of this instance.
        /// </summary>
        /// <exception cref="ArgumentException"/>
        /// <param name="obj">The object to compare to this instance.</param>
        /// <returns>
        /// true if value is an instance of <see cref="DerInt"/> 
        /// and equals the value of this instance; otherwise, false.
        /// </returns>
        public override bool Equals(object obj)
        {
            if (!(obj is DerInt))
                throw new ArgumentException($"Object must be of type {nameof(DerInt)}");

            return Equals((DerInt)obj);
        }

        /// <summary>
        /// Returns the hash code for this instance.
        /// </summary>
        /// <returns>A 32-bit signed integer hash code</returns>
        public override int GetHashCode()
        {
            return value.GetHashCode();
        }

        /// <summary>
        /// Converts the value of the current instance to its equivalent string representation.
        /// </summary>
        /// <returns>A string representation of the value of the current instance</returns>
        public override string ToString()
        {
            return value.ToString();
        }

        #endregion

    }
}
