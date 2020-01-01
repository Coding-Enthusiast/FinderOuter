// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace FinderOuter.Backend.Encoders
{
    /// <summary>
    /// A checksummed base32 format for native v0-16 witness outputs. 
    /// https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
    /// </summary>
    public class Bech32
    {
        /// <summary>
        /// Maximum length of the whole Bech32 string (hrp + separator + data)
        /// </summary>
        private const int TotalMaxLength = 90;
        private const int CheckSumSize = 6;
        private const int HrpMinLength = 1;
        private const int HrpMaxLength = 83;
        private const int HrpMinValue = 33;
        private const int HrpMaxValue = 126;
        private const char Separator = '1';
        //private const int DataMinLength = 2;
        //private const int DataMaxLength = 40;
        private const string B32Chars = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
        private readonly uint[] generator = { 0x3b6a57b2u, 0x26508e6du, 0x1ea119fau, 0x3d4233ddu, 0x2a1462b3u };



        private byte[] CalculateCheckSum(string hrp, byte[] data)
        {
            // expand hrp, append data to it, and then add 6 zero bytes at the end.
            byte[] bytes = ExpandHrp(hrp).ConcatFast(data).ConcatFast(new byte[CheckSumSize]);

            // get polymod of the whole data and then flip the least significant bit.
            uint pm = Polymod(bytes) ^ 1;

            byte[] result = new byte[6];
            for (int i = 0; i < 6; i++)
            {
                result[i] = (byte)((pm >> 5 * (5 - i)) & 0b0001_1111 /*=31*/);
            }
            return result;
        }

        private uint Polymod(byte[] data)
        {
            uint chk = 1;
            foreach (byte b in data)
            {
                uint temp = chk >> 25;
                chk = ((chk & 0x1ffffff) << 5) ^ b;
                for (int i = 0; i < 5; i++)
                {
                    if (((temp >> i) & 1) == 1)
                    {
                        chk ^= generator[i];
                    }
                }
            }
            return chk;
        }

        private byte[] ExpandHrp(string hrp)
        {
            byte[] result = new byte[(2 * hrp.Length) + 1];
            for (int i = 0; i < hrp.Length; i++)
            {
                result[i] = (byte)(hrp[i] >> 5);
                result[i + hrp.Length + 1] = (byte)(hrp[i] & 0b0001_1111 /*=31*/);
            }
            return result;
        }


        private byte[] ConvertBits(byte[] data, int fromBits, int toBits, bool pad = true)
        {
            // We can use a method similar to BIP39 here to avoid the nested loop, usage of List, increase the speed,
            // and shorten this function to 3 lines.
            // Or convert to ulong[], loop through it (3 times) take 5 bits at a time or 8 bits at a time...
            int acc = 0;
            int bits = 0;
            int maxv = (1 << toBits) - 1;
            int maxacc = (1 << (fromBits + toBits - 1)) - 1;

            List<byte> result = new List<byte>();
            foreach (var b in data)
            {
                if ((b >> fromBits) > 0)// Speed doesn't matter for this class but we can skip this check for 8 to 5 conversion.
                {
                    return null;
                }
                acc = ((acc << fromBits) | b) & maxacc;
                bits += fromBits;
                while (bits >= toBits)
                {
                    bits -= toBits;
                    result.Add((byte)((acc >> bits) & maxv));
                }
            }
            if (pad)
            {
                if (bits > 0)
                {
                    result.Add((byte)((acc << (toBits - bits)) & maxv));
                }
            }
            else if (bits >= fromBits || (byte)((acc << (toBits - bits)) & maxv) != 0)
            {
                return null;
            }
            return result.ToArray();
        }


        /// <summary>
        /// Checks to see if a given string is a valid bech-32 encoded string.
        /// <para/>* Doesn't verify checksum.
        /// <para/>* Doesn't verify data length (since it requires decoding first).
        /// </summary>
        /// <param name="bech32EncodedString">Input string to check.</param>
        /// <returns>True if input was a valid bech-32 encoded string (without verifying checksum).</returns>
        private bool CheckString(string bech32EncodedString)
        {
            if (string.IsNullOrEmpty(bech32EncodedString) || bech32EncodedString.Length > TotalMaxLength)
            {
                return false;
            }

            // Reject mixed upper and lower characters.
            if (bech32EncodedString.ToLower() != bech32EncodedString && bech32EncodedString.ToUpper() != bech32EncodedString)
            {
                return false;
            }

            // Check if it has a separator
            int sepIndex = bech32EncodedString.LastIndexOf(Separator);
            if (sepIndex == -1) // no separator
            {
                return false;
            }

            // Validate human readable part
            string hrp = bech32EncodedString.Substring(0, sepIndex);
            if (hrp.Length < HrpMinLength || hrp.Length > HrpMaxLength || !hrp.All(x => (byte)x >= HrpMinValue && (byte)x <= HrpMaxValue))
            {
                return false;
            }

            // Validate data part
            string data = bech32EncodedString.Substring(sepIndex + 1);
            if (!data.All(x => B32Chars.Contains(char.ToLower(x))))
            {
                return false;
            }

            return true;
        }
        private bool IsValidHrp(string hrp)
        {
            return
                !string.IsNullOrWhiteSpace(hrp) &&
                hrp.Length >= HrpMinLength &&
                hrp.Length <= HrpMaxLength &&
                hrp.All(x => (byte)x >= HrpMinValue && (byte)x <= HrpMaxValue);
        }


        /// <summary>
        /// Checks to see if a given string is a valid bech-32 encoded string with a valid checksum.
        /// </summary>
        /// <param name="bech32EncodedString">Input string to check</param>
        /// <returns>True if input was a valid bech-32 encoded string with checksum, false if otherwise.</returns>
        public bool IsValid(string bech32EncodedString)
        {
            if (!CheckString(bech32EncodedString))
            {
                return false;
            }

            byte[] b32Arr = Bech32Decode(bech32EncodedString, out string hrp);
            if (b32Arr.Length < CheckSumSize)
            {
                return false;
            }

            return VerifyChecksum(hrp, b32Arr);
        }


        private byte[] Bech32Decode(string bech32EncodedString, out string hrp)
        {
            bech32EncodedString = bech32EncodedString.ToLower();

            int sepIndex = bech32EncodedString.LastIndexOf(Separator);
            hrp = bech32EncodedString.Substring(0, sepIndex);
            string data = bech32EncodedString.Substring(sepIndex + 1);

            byte[] b32Arr = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                b32Arr[i] = (byte)B32Chars.IndexOf(data[i]);
            }

            return b32Arr;
        }

        private bool VerifyChecksum(string hrp, byte[] data)
        {
            byte[] values = ExpandHrp(hrp).ConcatFast(data);
            return Polymod(values) == 1;
        }


        /// <summary>
        /// Converts a bech-32 encoded string back to its byte array representation.
        /// </summary>
        /// <exception cref="ArgumentException"/>
        /// <param name="bech32EncodedString">Bech-32 encoded string.</param>
        /// <param name="witVer"></param>
        /// <param name="hrp"></param>
        /// <returns>Byte array of the given string.</returns>
        public byte[] Decode(string bech32EncodedString, out byte witVer, out string hrp)
        {
            if (!CheckString(bech32EncodedString))
                throw new ArgumentException("Input is not a valid bech32 encoded string.");


            byte[] b32Arr = Bech32Decode(bech32EncodedString, out hrp);
            if (b32Arr.Length < CheckSumSize)
            {
                throw new ArgumentException("Invalid length.");
            }
            if (!IsValidHrp(hrp))
            {
                throw new ArgumentException("Invalid HRP.");
            }
            if (!VerifyChecksum(hrp, b32Arr))
            {
                throw new ArgumentException("Invalid checksum.");
            }

            byte[] b256Arr = ConvertBits(b32Arr.SubArray(1, b32Arr.Length - CheckSumSize - 1), 5, 8, false);
            if (b256Arr == null)
            {
                throw new ArgumentException("Invalid data format.");
            }

            witVer = b32Arr[0];
            return b256Arr;
        }


        /// <summary>
        /// Converts the given byte array to its equivalent string representation that is encoded with bech-32 digits,
        /// with 6 byte appended checksum.
        /// </summary>
        /// <exception cref="ArgumentException"/>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <param name="data">Byte array to encode</param>
        /// <param name="witVer"></param>
        /// <param name="hrp"></param>
        /// <returns>The string representation in bech-32 with a checksum.</returns>
        public string Encode(byte[] data, byte witVer, string hrp)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentNullException(nameof(data), "Data can not be null or empty.");
            if (!IsValidHrp(hrp))
                throw new ArgumentException("Invalid HRP.");
            if (witVer >= B32Chars.Length)
                throw new ArgumentOutOfRangeException($"Witness version can not be bigger than {B32Chars.Length - 1}.");


            byte[] b32Arr = ConvertBits(data, 8, 5, true).AppendToBeginning(witVer);
            byte[] checksum = CalculateCheckSum(hrp, b32Arr);
            b32Arr = b32Arr.ConcatFast(checksum);

            StringBuilder result = new StringBuilder(b32Arr.Length);
            foreach (var b in b32Arr)
            {
                result.Append(B32Chars[b]);
            }

            return $"{hrp}{Separator}{result.ToString()}";
        }

    }
}
