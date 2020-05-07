// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.Encoders;
using FinderOuter.Backend;
using System.Linq;
using System.Numerics;
using System.Text;

namespace FinderOuter.Services
{
    public class InputService
    {
        private readonly Base58 b58Enc = new Base58();
        private readonly Bech32 b32Enc = new Bech32();


        public string CheckBase58Address(string address)
        {
            if (!b58Enc.HasValidChars(address))
            {
                return "The given address contains invalid base-58 characters.";
            }
            if (!b58Enc.IsValid(address))
            {
                return "The given address has an invalid checksum.";
            }

            byte[] addrBa = b58Enc.DecodeWithCheckSum(address);

            if (addrBa[0] != Constants.P2pkhAddrFirstByte && addrBa[0] != Constants.P2shAddrFirstByte)
            {
                return "The given address starts with an invalid byte.";
            }
            if (addrBa.Length != 21)
            {
                return "The given address byte length is invalid.";
            }

            return $"The given address is a valid base-58 encoded address used for " +
                   $"{(addrBa[0] == Constants.P2pkhAddrFirstByte ? "P2PKH" : "P2SH")} scripts.";
        }


        public bool CanBePrivateKey(string key, out string error)
        {
            if (key.Length == Constants.PrivKeyCompWifLen)
            {
                if (key[0] == Constants.PrivKeyCompChar1 || key[0] == Constants.PrivKeyCompChar2)
                {
                    error = null;
                    return true;
                }
                else
                {
                    error = $"A key with {key.Length} length is expected to start with {Constants.PrivKeyCompChar1} " +
                            $"or {Constants.PrivKeyCompChar2}.";
                    return false;
                }
            }
            else if (key.Length == Constants.PrivKeyUncompWifLen)
            {
                if (key[0] == Constants.PrivKeyUncompChar)
                {
                    error = null;
                    return true;
                }
                else
                {
                    error = $"A key with {key.Length} length is expected to start with {Constants.PrivKeyUncompChar}.";
                    return false;
                }
            }
            else
            {
                error = "Given key has an invalid length";
                return false;
            }
        }

        public string CheckPrivateKey(string key)
        {
            if (!b58Enc.HasValidChars(key))
            {
                return "The given key contains invalid base-58 characters.";
            }
            if (!b58Enc.IsValid(key))
            {
                return "The given key has an invalid checksum.";
            }

            byte[] keyBa = b58Enc.DecodeWithCheckSum(key);
            if (keyBa[0] != Constants.PrivKeyFirstByte)
            {
                return $"Invalid first key byte (actual={keyBa[0]}, expected={Constants.PrivKeyFirstByte}).";
            }

            if (keyBa.Length == 33)
            {
                if (!IsPrivateKeyInRange(keyBa.SubArray(1)))
                {
                    return "Invalid key integer value (outside of the range defined by secp256k1 curve).";
                }

                return "The given key is a valid uncompressed private key.";
            }
            else if (keyBa.Length == 34)
            {
                if (keyBa[^1] != Constants.PrivKeyCompLastByte)
                {
                    return $"Invalid compressed key last byte (actual={keyBa[^1]}, expected={Constants.PrivKeyCompLastByte}).";
                }

                if (!IsPrivateKeyInRange(keyBa.SubArray(1, 32)))
                {
                    return "Invalid key integer value (outside of the range defined by secp256k1 curve).";
                }

                return "The given key is a valid compressed private key.";
            }
            else
            {
                return $"The given key length is invalid. actual = {keyBa.Length}, expected = 33 (uncompressed) or 34 (compressed)).";
            }
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
                if (key.Length == Constants.PrivKeyCompWifLen)
                {
                    if (key[0] != Constants.PrivKeyCompChar1 && key[0] != Constants.PrivKeyCompChar2)
                    {
                        error = "Invalid first character for a compressed private key considering length.";
                        return false;
                    }
                }
                else if (key.Length == Constants.PrivKeyUncompWifLen)
                {
                    if (key[0] != Constants.PrivKeyUncompChar)
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
                if (key.Length > Constants.PrivKeyCompWifLen)
                {
                    error = "Key length is too big.";
                    return false;
                }
                else if (key.Length == Constants.PrivKeyCompWifLen &&
                    key[0] != Constants.PrivKeyCompChar1 && key[0] != Constants.PrivKeyCompChar2)
                {
                    error = "Invalid first key character considering its length.";
                    return false;
                }
                else if (key.Length == Constants.PrivKeyUncompWifLen && key[0] != Constants.PrivKeyUncompChar)
                {
                    error = "Invalid first key character considering its length.";
                    return false;
                }
                else if (key[0] != Constants.PrivKeyCompChar1 && key[0] != Constants.PrivKeyCompChar2 &&
                    key[0] != Constants.PrivKeyUncompChar)
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

            if ((address.StartsWith("1") || address.StartsWith("3")) && b58Enc.IsValid(address))
            {
                byte[] decoded = b58Enc.DecodeWithCheckSum(address);
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
