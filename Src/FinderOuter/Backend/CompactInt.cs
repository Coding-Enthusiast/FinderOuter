// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System;

namespace FinderOuter.Backend
{
    /// <summary>
    /// Compact representation of up to 64 bytes integers also known as "variable length integer" as defined by bitcoin.
    /// </summary>
    /// <remarks>https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer</remarks>
    public readonly struct CompactInt : IComparable, IComparable<CompactInt>, IEquatable<CompactInt>
    {
        /// <summary>
        /// Initializes a new instance of <see cref="CompactInt"/> using a 64-bit signed integer.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <param name="val">Value to use (must be >= 0)</param>
        public CompactInt(long val)
        {
            if (val < 0)
                throw new ArgumentOutOfRangeException(nameof(val), "CompactInt value can not be negative.");

            value = (ulong)val;
        }

        /// <summary>
        /// Initializes a new instance of <see cref="CompactInt"/> using a 32-bit signed integer.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <param name="val">Value to use (must be >= 0)</param>
        public CompactInt(int val)
        {
            if (val < 0)
                throw new ArgumentOutOfRangeException(nameof(val), "CompactInt value can not be negative.");

            value = (ulong)val;
        }

        /// <summary>
        /// Initializes a new instance of <see cref="CompactInt"/> using a 64-bit unsigned integer.
        /// </summary>
        /// <param name="val">Value to use</param>
        public CompactInt(ulong val)
        {
            value = val;
        }



        /// <summary>
        /// Integer value of this instance.
        /// </summary>
        private readonly ulong value;



        /// <summary>
        /// Initializes a new instance of <see cref="CompactInt"/> by reading it from a byte array.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="FormatException"/>
        /// <param name="data">Byte array containing a <see cref="CompactInt"/>.</param>
        /// <returns>A new instance of <see cref="CompactInt"/></returns>
        public static CompactInt ReadFromBytes(byte[] data)
        {
            int i = 0;
            return ReadFromBytes(data, ref i);
        }

        /// <summary>
        /// Initializes a new instance of <see cref="CompactInt"/> by reading it from a byte array 
        /// starting from the given offset and changing it based on the length of the data that was read.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="IndexOutOfRangeException"/>
        /// <exception cref="FormatException"/>
        /// <param name="data">Byte array containing a <see cref="CompactInt"/>.</param>
        /// <param name="offset">Offset in <paramref name="data"/> to start reading from.</param>
        /// <returns>A new instance of <see cref="CompactInt"/></returns>
        public static CompactInt ReadFromBytes(byte[] data, ref int offset)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentNullException(nameof(data), "Data can not be null or empty!");
            if (offset < 0)
                throw new IndexOutOfRangeException("Offset can not be negative.");
            if (offset >= data.Length)
                throw new IndexOutOfRangeException("Offset is bigger than data length.");


            if (!TryReadFromBytes(data, ref offset, out CompactInt result, out string error))
            {
                throw new FormatException(error);
            }
            return result;
        }


        /// <summary>
        /// Reads the <see cref="CompactInt"/> value from the given byte array starting from the specified offset. 
        /// changing that offset based on the length of data that was read. The return value indicates success.
        /// </summary>
        /// <param name="data">Byte array containing a <see cref="CompactInt"/>.</param>
        /// <param name="offset">Offset in <paramref name="data"/> to start reading from.</param>
        /// <param name="result">The result</param>
        /// <param name="error">Error message (null if sucessful, otherwise will contain information about the failure).</param>
        /// <returns>True if reading was successful, false if otherwise.</returns>
        public static bool TryReadFromBytes(byte[] data, ref int offset, out CompactInt result, out string error)
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


            if (data[offset] <= 252)
            {
                result = new CompactInt((ulong)data[offset]);
                offset++;
            }
            else if (data[offset] == 253 && data.Length - offset >= (1 + sizeof(ushort))) //0xfd --> must be followed by 2 bytes
            {
                ushort val = data.SubArray(offset + 1, sizeof(ushort)).ToUInt16(false);
                if (val <= 252)
                {
                    error = "For values less than 253, one byte format should be used.";
                    result = 0;
                    return false;
                }
                result = new CompactInt((ulong)val);
                offset += 3;
            }
            else if (data[offset] == 254 && data.Length - offset >= (1 + sizeof(uint))) //0xfe --> must be followed by 4 bytes
            {
                uint val = data.SubArray(offset + 1, sizeof(uint)).ToUInt32(false);
                if (val <= ushort.MaxValue)
                {
                    error = "For values less than 2 bytes, [253, ushort] format should be used.";
                    result = 0;
                    return false;
                }
                result = new CompactInt((ulong)val);
                offset += 5;
            }
            else if (data[offset] == 255 && data.Length - offset >= (1 + sizeof(ulong))) //0xff --> must be followed by 8 bytes
            {
                ulong val = data.SubArray(offset + 1, sizeof(ulong)).ToUInt64(false);
                if (val <= uint.MaxValue)
                {
                    error = "For values less than 4 bytes, [254, uint] format should be used.";
                    result = 0;
                    return false;
                }
                result = new CompactInt(val);
                offset += 9;
            }
            else
            {
                error = "Invalid data length.";
                result = 0;
                return false;
            }

            error = null;
            return true;
        }


        /// <summary>
        /// Converts this value to its byte array representation.
        /// </summary>
        /// <returns>An array of bytes in little-endian order</returns>
        public byte[] ToByteArray()
        {
            if (value <= 252) // 1 Byte
            {
                return new byte[] { (byte)value };
            }
            else if (value <= 0xffff) // 1 + 2 Byte
            {
                return new byte[] { 0xfd }.ConcatFast(((ushort)value).ToByteArray(false));
            }
            else if (value <= 0xffffffff) // 1 + 4 Byte
            {
                return new byte[] { 0xfe }.ConcatFast(((uint)value).ToByteArray(false));
            }
            else // < 0xffffffffffffffff // 1 + 8 Byte
            {
                return new byte[] { 0xff }.ConcatFast(((ulong)value).ToByteArray(false));
            }
        }


        public static implicit operator CompactInt(ulong val)
        {
            return new CompactInt(val);
        }
        public static implicit operator CompactInt(uint val)
        {
            return new CompactInt(val);
        }
        public static implicit operator CompactInt(ushort val)
        {
            return new CompactInt(val);
        }
        public static implicit operator CompactInt(byte val)
        {
            return new CompactInt(val);
        }
        public static explicit operator CompactInt(long val)
        {
            if (val < 0)
                throw new InvalidCastException("CompactInt can not be negative");

            return new CompactInt(val);
        }
        public static explicit operator CompactInt(int val)
        {
            if (val < 0)
                throw new InvalidCastException("CompactInt can not be negative");

            return new CompactInt(val);
        }

        public static implicit operator ulong(CompactInt val)
        {
            return val.value;
        }
        public static explicit operator uint(CompactInt val)
        {
            return checked((uint)val.value);
        }
        public static explicit operator ushort(CompactInt val)
        {
            return checked((ushort)val.value);
        }
        public static explicit operator byte(CompactInt val)
        {
            return checked((byte)val.value);
        }
        public static explicit operator long(CompactInt val)
        {
            return checked((int)val.value);
        }
        public static explicit operator int(CompactInt val)
        {
            return checked((int)val.value);
        }


        public static bool operator >(CompactInt left, CompactInt right)
        {
            return left.CompareTo(right) > 0;
        }
        public static bool operator >=(CompactInt left, CompactInt right)
        {
            return left.CompareTo(right) >= 0;
        }
        public static bool operator <(CompactInt left, CompactInt right)
        {
            return left.CompareTo(right) < 0;
        }
        public static bool operator <=(CompactInt left, CompactInt right)
        {
            return left.CompareTo(right) <= 0;
        }
        public static bool operator ==(CompactInt left, CompactInt right)
        {
            return left.CompareTo(right) == 0;
        }
        public static bool operator !=(CompactInt left, CompactInt right)
        {
            return left.CompareTo(right) != 0;
        }


        #region Interfaces and overrides

        /// <summary>
        /// Compares the value of a given <see cref="CompactInt"/> with the value of this instance and 
        /// And returns -1 if smaller, 0 if equal and 1 if bigger.
        /// </summary>
        /// <param name="other">Other <see cref="CompactInt"/> to compare to this instance.</param>
        /// <returns>-1 if smaller, 0 if equal and 1 if bigger.</returns>
        public int CompareTo(CompactInt other)
        {
            return value.CompareTo(other.value);
        }

        /// <summary>
        /// Checks if the given object is of type <see cref="CompactInt"/> and then compares its value with the value of this instance.
        /// Returns -1 if smaller, 0 if equal and 1 if bigger.
        /// </summary>
        /// <exception cref="ArgumentException"/>
        /// <param name="obj">The object to compare to this instance.</param>
        /// <returns>-1 if smaller, 0 if equal and 1 if bigger</returns>
        public int CompareTo(object obj)
        {
            if (obj is null)
                return 1;
            if (!(obj is CompactInt))
                throw new ArgumentException($"Object must be of type {nameof(CompactInt)}");

            return CompareTo((CompactInt)obj);
        }

        /// <summary>
        /// Checks if the value of the given <see cref="CompactInt"/> is equal to the value of this instance.
        /// </summary>
        /// <param name="other">Other <see cref="CompactInt"/> value to compare to this instance.</param>
        /// <returns>true if the value is equal to the value of this instance; otherwise, false.</returns>
        public bool Equals(CompactInt other)
        {
            return CompareTo(other) == 0;
        }

        /// <summary>
        /// Checks if the given object is of type <see cref="CompactInt"/> and if its value is equal to the value of this instance.
        /// </summary>
        /// <exception cref="ArgumentException"/>
        /// <param name="obj">The object to compare to this instance.</param>
        /// <returns>
        /// true if value is an instance of <see cref="CompactInt"/> 
        /// and equals the value of this instance; otherwise, false.
        /// </returns>
        public override bool Equals(object obj)
        {
            if (!(obj is CompactInt))
                throw new ArgumentException($"Object must be of type {nameof(CompactInt)}");

            return Equals((CompactInt)obj);
        }

        /// <summary>
        /// Returns the hash code for this instance.
        /// </summary>
        /// <returns>A 32-bit signed integer hash code.</returns>
        public override int GetHashCode()
        {
            return value.GetHashCode();
        }

        /// <summary>
        /// Converts the value of the current instance to its equivalent string representation.
        /// </summary>
        /// <returns>A string representation of the value of the current instance.</returns>
        public override string ToString()
        {
            return value.ToString();
        }

        #endregion

    }
}
