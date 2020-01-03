// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Newtonsoft.Json;
using System;

namespace Tests
{
    internal class ByteArrayHexConverter : JsonConverter
    {
        public override bool CanConvert(Type objectType)
        {
            return objectType == typeof(byte[]);
        }


        public override bool CanRead => true;
        public override bool CanWrite => true;


        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            if (reader.TokenType == JsonToken.String)
            {
                string hex = serializer.Deserialize<string>(reader);
                return Helper.HexToBytes(hex);
            }
            return serializer.Deserialize(reader);
        }


        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            string hexString = Helper.BytesToHex((byte[])value);
            writer.WriteValue(hexString);
        }
    }
}
