// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.Cryptography.EllipticCurve;
using Newtonsoft.Json;
using System;
using System.IO;
using System.Reflection;

namespace Tests
{
    public static class Helper
    {
        private static readonly Calc _calc = new();
        public static Calc Calc => _calc;


        internal static JsonSerializerSettings jSetting = new()
        {
            Converters = { new ByteArrayHexConverter() },
            ConstructorHandling = ConstructorHandling.AllowNonPublicDefaultConstructor
        };


        public static void ComparePrivateField<InstanceType, FieldType>(InstanceType instance, string fieldName, FieldType expected)
        {
            FieldInfo fi = typeof(InstanceType).GetField(fieldName, BindingFlags.NonPublic | BindingFlags.Instance);
            if (fi is null)
            {
                Assert.Fail("The private field was not found.");
            }

            object fieldVal = fi.GetValue(instance);
            if (fieldVal is null)
            {
                Assert.Fail("The private field value was null.");
            }
            else if (fieldVal is FieldType actual)
            {
                Assert.Equal(expected, actual);
            }
            else
            {
                Assert.Fail($"Field value is not the same type as expected.{Environment.NewLine}" +
                            $"Actual type: {fieldVal.GetType()}{Environment.NewLine}" +
                            $"Expected type: {expected.GetType()}");
            }
        }

        public static void CallPrivateMethod<InstanceType>(this InstanceType instance, string methodName, params object[] parameters)
        {
            Type type = instance.GetType();
            BindingFlags bindingAttr = BindingFlags.NonPublic | BindingFlags.Instance;
            MethodInfo method = type.GetMethod(methodName, bindingAttr);
            if (method is null)
            {
                Assert.Fail("Method was not found.");
            }
            method.Invoke(instance, parameters);
        }

        public static TReturn CallPrivateMethod<InstanceType, TReturn>(this InstanceType instance, string methodName, params object[] parameters)
        {
            Type type = instance.GetType();
            BindingFlags bindingAttr = BindingFlags.NonPublic | BindingFlags.Instance;
            MethodInfo method = type.GetMethod(methodName, bindingAttr);
            if (method is null)
            {
                Assert.Fail("Method was not found.");
            }
            return (TReturn)method.Invoke(instance, parameters);
        }

        public static string ReadResources(string resourceName, string fileExtention = "json")
        {
            Assembly asm = Assembly.GetExecutingAssembly();
            using Stream stream = asm.GetManifestResourceStream($"Tests.TestData.{resourceName}.{fileExtention}");
            if (stream != null)
            {
                using StreamReader reader = new(stream);
                return reader.ReadToEnd();
            }
            else
            {
                Assert.Fail("File was not found among resources!");
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
                return Array.Empty<byte>();
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


        internal static unsafe void WriteToHpt(byte[] data, uint* hPt)
        {
            Assert.True(data.Length == 32);

            hPt[0] = (uint)((data[00] << 24) | (data[01] << 16) | (data[02] << 8) | data[3]);
            hPt[1] = (uint)((data[04] << 24) | (data[05] << 16) | (data[06] << 8) | data[07]);
            hPt[2] = (uint)((data[08] << 24) | (data[09] << 16) | (data[10] << 8) | data[11]);
            hPt[3] = (uint)((data[12] << 24) | (data[13] << 16) | (data[14] << 8) | data[15]);
            hPt[4] = (uint)((data[16] << 24) | (data[17] << 16) | (data[18] << 8) | data[19]);
            hPt[5] = (uint)((data[20] << 24) | (data[21] << 16) | (data[22] << 8) | data[23]);
            hPt[6] = (uint)((data[24] << 24) | (data[25] << 16) | (data[26] << 8) | data[27]);
            hPt[7] = (uint)((data[28] << 24) | (data[29] << 16) | (data[30] << 8) | data[31]);
        }

        internal static unsafe void WriteToHpt32(byte[] data, ulong* hPt)
        {
            Assert.True(data.Length == 32);

            hPt[0] = ((ulong)data[00] << 56) | ((ulong)data[01] << 48) | ((ulong)data[02] << 40) | ((ulong)data[03] << 32) |
                     ((ulong)data[04] << 24) | ((ulong)data[05] << 16) | ((ulong)data[06] << 8) | data[07];
            hPt[1] = ((ulong)data[08] << 56) | ((ulong)data[09] << 48) | ((ulong)data[10] << 40) | ((ulong)data[11] << 32) |
                     ((ulong)data[12] << 24) | ((ulong)data[13] << 16) | ((ulong)data[14] << 8) | data[15];
            hPt[2] = ((ulong)data[16] << 56) | ((ulong)data[17] << 48) | ((ulong)data[18] << 40) | ((ulong)data[19] << 32) |
                     ((ulong)data[20] << 24) | ((ulong)data[21] << 16) | ((ulong)data[22] << 8) | data[23];
            hPt[3] = ((ulong)data[24] << 56) | ((ulong)data[25] << 48) | ((ulong)data[26] << 40) | ((ulong)data[27] << 32) |
                     ((ulong)data[28] << 24) | ((ulong)data[29] << 16) | ((ulong)data[30] << 8) | data[31];
        }
    }
}
