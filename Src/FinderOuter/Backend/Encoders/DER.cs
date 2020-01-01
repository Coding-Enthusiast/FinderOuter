// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System;
using System.Numerics;

namespace FinderOuter.Backend.Encoders
{
    /// <summary>
    /// A simplified implementation of Distinguished Encoding Rules (DER) used for serialization of signatures.
    /// </summary>
    /// <remarks>
    /// Helpful for future implementation changes:
    /// https://docs.microsoft.com/en-us/windows/desktop/seccertenroll/distinguished-encoding-rules
    /// </remarks>
    public class DER
    {
        private enum DERTag : byte
        {
            Integer = 0x02,
            Sequence = 0x30
        }

        // SEQ(INT|INT) = TLV(TLV|TLV) = 1+1+1(1+1+1|1+1+1)
        private const int Min2IntSize = 9;
        // SEQ(data) = TLV = 1+1+1
        private const int MinSeqSize = 3;
        // INT(data) = TLV = 1+1+1
        private const int MinIntSize = MinSeqSize;



        /// <summary>
        /// Decodes DER-encoded bytes containing two integers using strict formatting rules for <see cref="DerInt"/> lengths,
        /// and returns their <see cref="BigInteger"/> representation in an array.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="FormatException"/>
        /// <param name="data">DER-encoded byte array</param>
        /// <returns>An array containing the two <see cref="BigInteger"/>s</returns>
        public BigInteger[] Decode2Integers(byte[] data)
        {
            return Decode2Integers(data, 0, true);
        }

        /// <summary>
        /// Decodes DER-encoded bytes containing two integers starting from the given index
        /// and returns their <see cref="BigInteger"/> representation in an array.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="IndexOutOfRangeException"/>
        /// <exception cref="FormatException"/>
        /// <param name="data">DER-encoded byte array</param>
        /// <param name="index">Index inside <paramref name="data"/> to start from</param>
        /// <param name="isStrict">If true, string encoding rules will be enforced for <see cref="DerInt"/> lengths.</param>
        /// <returns>An array containing the two <see cref="BigInteger"/>s</returns>
        public BigInteger[] Decode2Integers(byte[] data, int index, bool isStrict)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data), "Data can not be null or empty.");
            // The order of these two checks should not be changed
            if (index < 0)
                throw new IndexOutOfRangeException("Index can not be negative.");
            if (data.Length - index <= 0)
                throw new IndexOutOfRangeException("Index can not be bigger than data length.");


            if (!TryDecode2Integers(data, ref index, isStrict, out BigInteger r, out BigInteger s, out string error))
            {
                throw new FormatException(error);
            }
            else
            {
                return new BigInteger[] { r, s };
            }
        }


        /// <summary>
        /// Decodes the given byte array starting from the specified offset to get 2 integers out.
        /// The return value indicates success.
        /// </summary>
        /// <param name="data">Byte array containing two integers.</param>
        /// <param name="offset">The offset inside the <paramref name="data"/> to start from.</param>
        /// <param name="isStrict">Indicates enforcing of strict encoding rules for <see cref="DerInt"/> lengths.</param>
        /// <param name="r">The first integer (R)</param>
        /// <param name="s">The second integer (S)</param>
        /// <param name="error">Error message (null if sucessful, otherwise will contain information about the failure).</param>
        /// <returns>True if decoding was successful, false if otherwise.</returns>
        public bool TryDecode2Integers(byte[] data, ref int offset, bool isStrict, out BigInteger r, out BigInteger s, out string error)
        {
            if (offset < 0)
            {
                error = "Offset can not be negative.";
                r = s = 0;
                return false;
            }
            if (data == null || data.Length - offset < Min2IntSize)
            {
                r = s = 0;
                error = "Data length is not valid.";
                return false;
            }


            if (!TryDecodeSequence(data, ref offset, isStrict, out error))
            {
                r = s = 0;
                return false;
            }
            if (!TryDecodeInteger(data, ref offset, isStrict, out r, out error))
            {
                r = s = 0;
                return false;
            }
            if (!TryDecodeInteger(data, ref offset, isStrict, out s, out error))
            {
                r = s = 0;
                return false;
            }

            error = null;
            return true;
        }

        // TODO: wherever DerInt is used, check for rare case when size is bigger than Int.Max so case may throw an exception
        private bool TryDecodeInteger(byte[] data, ref int offset, bool isStrict, out BigInteger big, out string error)
        {
            if (offset < 0)
            {
                error = "Offset can not be negative.";
                big = 0;
                return false;
            }
            if (data == null || data.Length - offset < MinIntSize)
            {
                error = "Data length is not valid.";
                big = 0;
                return false;
            }


            if (data[offset] != (byte)DERTag.Integer)
            {
                error = "Integer tag is not present.";
                big = 0;
                return false;
            }
            offset++; // Skip sequence tag after checking above

            if (!DerInt.TryReadFromBytes(data, ref offset, isStrict, out DerInt len, out error))
            {
                big = 0;
                return false;
            }

            if (data.Length - offset < len)
            {
                error = "Data length is not valid accodring to encoded integer length.";
                big = 0;
                return false;
            }
            big = data.SubArray(offset, (int)len).ToBigInt(true, false);
            offset += (int)len;

            error = null;
            return true;
        }

        private bool TryDecodeSequence(byte[] data, ref int offset, bool isStrict, out string error)
        {
            if (offset < 0)
            {
                error = "Offset can not be negative.";
                return false;
            }
            if (data == null || data.Length - offset < MinSeqSize)
            {
                error = "Data length is not valid.";
                return false;
            }


            if (data[offset] != (byte)DERTag.Sequence)
            {
                error = "Sequence tag is not present.";
                return false;
            }
            offset++; // Skip sequence tag after checking above

            if (!DerInt.TryReadFromBytes(data, ref offset, isStrict, out DerInt len, out error))
            {
                return false;
            }
            if (data.Length - offset < len)
            {
                error = "Data length is not valid accodring to encoded sequence length.";
                return false;
            }

            error = null;
            return true;
        }



        /// <summary>
        /// Converts two given integers to their equivalant DER-encoded byte array.
        /// <para/> Format = Sequence(INT(big1)|INT(big2))
        /// </summary>
        /// <param name="big1">The first number to use.</param>
        /// <param name="big2">The second number to use.</param>
        /// <returns>A DER encoded array of bytes.</returns>
        public byte[] Encode(BigInteger big1, BigInteger big2)
        {
            return EncodeSequence(ByteArray.ConcatArrays(EncodeInteger(big1), EncodeInteger(big2)));
        }


        private byte[] EncodeInteger(BigInteger big)
        {
            byte[] ba = big.ToByteArrayExt(true, false);

            return EncodeTLV(DERTag.Integer, ba);
        }

        private byte[] EncodeSequence(byte[] ba)
        {
            return EncodeTLV(DERTag.Sequence, ba);
        }

        // Encodes (Tag + Length + Value)
        private byte[] EncodeTLV(DERTag tag, byte[] value)
        {
            DerInt len = new DerInt(value.Length);
            return ByteArray.ConcatArrays(new byte[] { (byte)tag }, len.ToByteArray(), value);
        }

    }
}
