// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System;

namespace FinderOuter.Backend
{
    public struct ConstantsFO
    {
        public const string LowerCase = "abcdefghijklmnopqrstuvwxyz";
        public const string UpperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        public const string Numbers = "0123456789";
        // 0x2122232425262728292a2b2c2d2e2f3a3b3c3d3e3f405b5c5d5e5f607b7c7d7e
        public const string AllSymbols = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

        public const string Base58Chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        public const string Base16Chars = "0123456789abcdef";
        public const string ArmoryChars = "asdfghjkwertuion";
        public const string MissingSymbols = "*?-_!@#$%^&+=";
        public const string MissingToolTip = "Replace missing item(s) with the selected symbol.";

        public const char PrivKeyCompChar1 = 'K';
        public const char PrivKeyCompChar2 = 'L';
        public const char PrivKeyUncompChar = '5';
        public const int PrivKeyCompWifLen = 52;
        public const int PrivKeyUncompWifLen = 51;
        public const byte PrivKeyFirstByte = 0x80;
        public const byte PrivKeyCompLastByte = 1;

        public const int PrivKeyHexLen = 64;

        public const int B58AddressMinLen = 26;
        public const int B58AddressMaxLen = 35;
        public const char B58AddressChar1 = '1';
        public const char B58AddressChar2 = '3';
        public const byte P2pkhAddrFirstByte = 0;
        public const byte P2shAddrFirstByte = 5;

        public const char MiniKeyStart = 'S';
        public const int MiniKeyLen1 = 22;
        public const int MiniKeyLen2 = 26;
        public const int MiniKeyLen3 = 30;

        public const int Bip38ByteLen = 39;
        public const int Bip38Base58Len = 58;
        public const string Bip38Start = "6P";
        public static readonly byte[] Bip38Prefix = [0x01, 0x42];
        public static readonly byte[] Bip38PrefixECMult = [0x01, 0x43];

        public static readonly string ChangedMessage = "Input is changed and the search-space needs to be re-evaluated." +
            $"{Environment.NewLine}" +
            $"Click Yes to reset search-space to use default values or click No to manually set search-space.";

        // 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz
        public static readonly char[][] SimilarBase58Chars =
        [
            ['0', 'o', 'C', 'G', 'c'],
            ['1', 'L', 'l'],
            ['5', 'S', 's'],
            ['7', 'J', 'T', 'j', 't', 'I', 'i'],
            ['8', 'B'],
            ['9', 'g', 'q', 'P', 'p', 'D', 'd', 'b'],
            ['E', 'F', 'f'],
            ['K', 'k'],
            ['M', 'm'],
            ['N', 'n'],
            ['U', 'u', 'V', 'v', 'Y', 'y'],
            ['W', 'w'],
            ['X', 'x'],
            ['Z', 'z'],
        ];
    }
}
