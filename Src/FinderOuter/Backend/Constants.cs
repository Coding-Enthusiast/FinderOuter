// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

namespace FinderOuter.Backend
{
    public struct Constants
    {
        public const string Base58Chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        public const string Base16Chars = "0123456789abcdef";
        public const string Symbols = "!@#$%^&*_-+=?";

        public const char CompPrivKeyChar1 = 'K';
        public const char CompPrivKeyChar2 = 'L';
        public const char UncompPrivKeyChar = '5';
        public const int CompPrivKeyLen = 52;
        public const int UncompPrivKeyLen = 51;
        public const byte PrivKeyFirstByte = 0x80;
        public const byte CompPrivKeyLastByte = 1;
    }
}
