// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Newtonsoft.Json;
using System;
using System.Collections;
using System.IO;
using System.Reflection;
using System.Text;
using Xunit;

namespace Tests
{
    public class Helper
    {
        internal static JsonSerializerSettings jSetting = new JsonSerializerSettings
        {
            Converters = { new ByteArrayHexConverter() },
            ConstructorHandling = ConstructorHandling.AllowNonPublicDefaultConstructor
        };



        public static string ReadResources(string resourceName, string fileExtention = "json")
        {
            Assembly asm = Assembly.GetExecutingAssembly();
            using Stream stream = asm.GetManifestResourceStream($"Tests.TestData.{resourceName}.{fileExtention}");
            if (stream != null)
            {
                using StreamReader reader = new StreamReader(stream);
                return reader.ReadToEnd();
            }
            else
            {
                Assert.True(false, "File was not found among resources!");
                return "";
            }
        }

        public static T ReadResources<T>(string resourceName, string fileExtention = "json")
        {
            string read = ReadResources(resourceName, fileExtention);
            return JsonConvert.DeserializeObject<T>(read, jSetting);
        }


        private static readonly byte[] data =
            {
            191, 223, 147, 104, 106, 49, 205, 85, 252, 92, 27, 143, 210, 144, 254, 57, 164, 49, 225, 98, 106, 27, 65, 58, 254,
            89, 183, 16, 195, 150, 140, 217, 201, 8, 184, 159, 175, 184, 167, 26, 213, 213, 107, 123, 195, 224, 226, 215, 125, 225,
            254, 94, 147, 159, 39, 164, 157, 89, 106, 17, 122, 189, 146, 101, 208, 65, 198, 202, 215, 95, 138, 236, 137, 199, 141,
            148, 176, 198, 118, 29, 119, 223, 146, 225, 151, 45, 70, 42, 224, 20, 1, 85, 77, 150, 160, 24, 67, 5, 171, 130
            };

        /// <summary>
        /// Returns a predefined random bytes used for tests requiring a certain length byte array.
        /// </summary>
        /// <param name="size"></param>
        /// <returns></returns>
        internal static byte[] GetBytes(int size)
        {
            byte[] res = new byte[size];

            int copied = 0;
            int toCopy = (size < data.Length) ? size : data.Length;
            while (copied < size)
            {
                Buffer.BlockCopy(data, 0, res, copied, toCopy);
                copied += toCopy;
                toCopy = (size - copied < data.Length) ? size - copied : data.Length;
            }
            return res;
        }

        internal static string GetBytesHex(int size)
        {
            return BytesToHex(GetBytes(size));
        }

        internal static void FillRandomByte(byte[] data) => new Random().NextBytes(data);

        /// <summary>
        /// This is used internally by unit tests so checks are skipped.
        /// Use <see cref="CryptoCurrency.Net.Encoders.Base16.ToByteArray(string)"/> for complete functionality.
        /// </summary>
        /// <param name="hex">Hex to convert.</param>
        /// <returns></returns>
        internal static byte[] HexToBytes(string hex, bool reverse = false)
        {
            if (string.IsNullOrEmpty(hex))
            {
                return new byte[0];
            }
            if (hex.Length % 2 != 0)
            {
                throw new FormatException("Invalid hex");
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
            if (reverse)
            {
                Array.Reverse(ba);
            }
            return ba;
        }

        /// <summary>
        /// This is used internally by unit tests so checks are skipped.
        /// Use <see cref="CryptoCurrency.Net.Extensions.ByteArrayExtension.ToBase16(byte[])"/> for complete functionality.
        /// </summary>
        /// <param name="ba">Bytes to convert.</param>
        /// <returns></returns>
        internal static string BytesToHex(byte[] ba)
        {
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

    }
}
