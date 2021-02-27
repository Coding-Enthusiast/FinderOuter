// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

namespace FinderOuter.Backend
{
    public struct ConstantsFO
    {
        public const string Base58Chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        public const string Base16Chars = "0123456789abcdef";
        public const string ArmoryChars = "asdfghjkwertuion";
        public const string Symbols = "!@#$%^&*_-+=?";
        public const string MissingToolTip = "Onlye these symbols are accepted as a missing character: !@#$%^&*_-+=?";

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
    }
}
