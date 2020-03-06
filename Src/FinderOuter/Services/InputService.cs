// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend;
using FinderOuter.Backend.Encoders;
using System.Linq;
using System.Numerics;
using System.Text;

namespace FinderOuter.Services
{
    public class InputService
    {
        private readonly Base58 b58End = new Base58();
        private readonly Bech32 b32Enc = new Bech32();


        public bool CanBePrivateKey(string key)
        {
            return
                (key.Length == Constants.CompPrivKeyLen &&
                        (key[0] == Constants.CompPrivKeyChar1 || key[0] == Constants.CompPrivKeyChar2))
                ||
                (key.Length == Constants.UncompPrivKeyLen &&
                        (key[0] == Constants.UncompPrivKeyChar));
        }

        public bool CheckIncompletePrivateKey(string key, char missingChar, out string error)
        {
            if (!IsMissingCharValid(missingChar))
            {
                error = $"Invalid missing character. Choose one from {Constants.Symbols}";
                return false;
            }
            if (string.IsNullOrWhiteSpace(key))
            {
                error = "Key can not be null or empty.";
                return false;
            }
            if (!key.All(c => c == missingChar || Constants.Base58Chars.Contains(c)))
            {
                error = $"Key contains invalid base-58 characters (ignoring the missing char = {missingChar}).";
                return false;
            }

            if (key.Contains(missingChar))
            {
                // Both key length and its first character must be valid
                if (key.Length == Constants.CompPrivKeyLen)
                {
                    if (key[0] != Constants.CompPrivKeyChar1 && key[0] != Constants.CompPrivKeyChar2)
                    {
                        error = "Invalid first character for a compressed private key considering length.";
                        return false;
                    }
                }
                else if (key.Length == Constants.UncompPrivKeyLen)
                {
                    if (key[0] != Constants.UncompPrivKeyChar)
                    {
                        error = "Invalid first character for an uncompressed private key considering length.";
                        return false;
                    }
                }
                else
                {
                    error = "Invalid key length.";
                    return false;
                }
            }
            else
            {
                // If the key doesn't have the missing char it is either a complete key that needs to be checked properly 
                // by the caller, or it has missing characters at unkown locations which needs to be found by the caller.
                if (key.Length > Constants.CompPrivKeyLen)
                {
                    error = "Key length is too big.";
                    return false;
                }
                else if (key.Length == Constants.CompPrivKeyLen &&
                    key[0] != Constants.CompPrivKeyChar1 && key[0] != Constants.CompPrivKeyChar2)
                {
                    error = "Invalid first key character considering its length.";
                    return false;
                }
                else if (key.Length == Constants.UncompPrivKeyLen && key[0] != Constants.UncompPrivKeyChar)
                {
                    error = "Invalid first key character considering its length.";
                    return false;
                }
                else if (key[0] != Constants.CompPrivKeyChar1 && key[0] != Constants.CompPrivKeyChar2 &&
                    key[0] != Constants.UncompPrivKeyChar)
                {
                    error = "The first character of the given private key is not valid.";
                    return false;
                }
            }

            error = null;
            return true;
        }

        public bool IsMissingCharValid(char c) => Constants.Symbols.Contains(c);

        public bool IsPrivateKeyInRange(byte[] key)
        {
            if (key.Length > 32)
            {
                return false;
            }
            BigInteger val = key.ToBigInt(true, true);
            BigInteger max = BigInteger.Parse("115792089237316195423570985008687907852837564279074904382605163141518161494336");
            return val >= BigInteger.One && val <= max;
        }


        public bool IsValidAddress(string address, bool ignoreP2SH, out byte[] hash)
        {
            hash = null;
            if (string.IsNullOrWhiteSpace(address))
                return false;
            if (address.StartsWith("3") && ignoreP2SH)
                return false;

            if ((address.StartsWith("1") || address.StartsWith("3")) && b58End.IsValid(address))
            {
                byte[] decoded = b58End.DecodeWithCheckSum(address);
                if (decoded[0] != 0 || decoded.Length != 21)
                    return false;
                hash = decoded.SubArray(1);
                return true;
            }
            else if (address.StartsWith("bc1") && b32Enc.IsValid(address))
            {
                byte[] decoded = b32Enc.Decode(address, out byte witVer, out string hrp);
                if (witVer != 0 || hrp != "bc" || decoded.Length != 20)
                    return false;
                hash = decoded;
                return true;
            }
            else
            {
                return false;
            }
        }


        public bool NormalizeNFKD(string s, out string norm)
        {
            norm = s.Normalize(NormalizationForm.FormKD);
            return !s.IsNormalized(NormalizationForm.FormKD);
        }
    }
}
