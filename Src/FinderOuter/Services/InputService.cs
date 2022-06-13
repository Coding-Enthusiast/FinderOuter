// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using Autarkysoft.Bitcoin.Cryptography.Asymmetric.KeyPairs;
using Autarkysoft.Bitcoin.Encoders;
using FinderOuter.Backend;
using FinderOuter.Models;
using FinderOuter.Services.Comparers;
using System;
using System.Linq;
using System.Numerics;
using System.Text;

namespace FinderOuter.Services
{
    public class InputService
    {
        public bool TryGetCompareService(InputType inType, string input, out ICompareService result)
        {
            result = inType switch
            {
                InputType.AddrComp => new PrvToAddrCompComparer(),
                InputType.AddrUnComp => new PrvToAddrUncompComparer(),
                InputType.AddrBoth => new PrvToAddrBothComparer(),
                InputType.AddrNested => new PrvToAddrNestedComparer(),
                InputType.Pubkey => new PrvToPubComparer(),
                InputType.PrivateKey => new PrvToPrvComparer(),
                _ => null
            };
            return !(result is null) && result.Init(input);
        }

        public string CheckMiniKey(string key)
        {
            try
            {
                using MiniPrivateKey mini = new(key);
                return $"Compressed:{Environment.NewLine}" +
                       $"       WIF: {mini.ToWif(true)}{Environment.NewLine}" +
                       $"   Address: {Address.GetP2pkh(mini.ToPublicKey(), true)}{Environment.NewLine}" +
                       $"Uncompressed:{Environment.NewLine}" +
                       $"         WIF: {mini.ToWif(false)}{Environment.NewLine}" +
                       $"     Address: {Address.GetP2pkh(mini.ToPublicKey(), false)}";
            }
            catch (Exception ex)
            {
                return ex.Message;
            }
        }

        public bool IsValidBase58Bip38(string bip38, out string message)
        {
            if (!Base58.IsValid(bip38))
            {
                message = "The given BIP-38 string contains invalid base-58 characters.";
                return false;
            }
            if (!Base58.IsValidWithChecksum(bip38))
            {
                message = "The given BIP-38 string has an invalid checksum.";
                return false;
            }

            byte[] data = Base58.DecodeWithChecksum(bip38);
            if (data.Length != ConstantsFO.Bip38ByteLen)
            {
                message = "The given BIP-38 string has an invalid byte length.";
                return false;
            }
            if (data[0] != 1 || (data[1] != 0x42 && data[1] != 0x43))
            {
                message = "The given BIP-38 string has invalid starting bytes.";
                return false;
            }

            message = "The given BIP-38 string is valid.";
            return true;
        }

        public bool IsValidBase58Address(string address, out string message)
        {
            if (!Base58.IsValid(address))
            {
                message = "The given address contains invalid base-58 characters.";
                return false;
            }
            if (!Base58.IsValidWithChecksum(address))
            {
                message = "The given address has an invalid checksum.";
                return false;
            }

            byte[] addrBa = Base58.DecodeWithChecksum(address);

            if (addrBa[0] != ConstantsFO.P2pkhAddrFirstByte && addrBa[0] != ConstantsFO.P2shAddrFirstByte)
            {
                message = "The given address starts with an invalid byte.";
                return false;
            }
            if (addrBa.Length != 21)
            {
                message = "The given address byte length is invalid.";
                return false;
            }

            message = $"The given address is a valid base-58 encoded address used for " +
                      $"{(addrBa[0] == ConstantsFO.P2pkhAddrFirstByte ? "P2PKH" : "P2SH")} scripts.";
            return true;
        }


        public bool IsValidBase16Key(string key, out string message)
        {
            if (key.Length != 64)
            {
                message = "Base-16 private keys must be 64 characters long.";
                return false;
            }

            if (!Base16.TryDecode(key, out byte[] ba))
            {
                message = "Invalid Base-16 string.";
                return false;
            }
            else if (!IsPrivateKeyInRange(ba))
            {
                message = "Out of range private key.";
                return false;
            }

            message = "Given key is valid.";
            return true;
        }


        public bool CanBePrivateKey(string key, out string error)
        {
            if (key.Length == ConstantsFO.PrivKeyCompWifLen)
            {
                if (key[0] == ConstantsFO.PrivKeyCompChar1 || key[0] == ConstantsFO.PrivKeyCompChar2)
                {
                    error = null;
                    return true;
                }
                else
                {
                    error = $"A key with {key.Length} length is expected to start with {ConstantsFO.PrivKeyCompChar1} " +
                            $"or {ConstantsFO.PrivKeyCompChar2}.";
                    return false;
                }
            }
            else if (key.Length == ConstantsFO.PrivKeyUncompWifLen)
            {
                if (key[0] == ConstantsFO.PrivKeyUncompChar)
                {
                    error = null;
                    return true;
                }
                else
                {
                    error = $"A key with {key.Length} length is expected to start with {ConstantsFO.PrivKeyUncompChar}.";
                    return false;
                }
            }
            else
            {
                error = "Given key has an invalid length";
                return false;
            }
        }

        public bool IsValidWif(string key, out string message)
        {
            if (!Base58.IsValid(key))
            {
                message = "The given key contains invalid base-58 characters.";
                return false;
            }
            if (!Base58.IsValidWithChecksum(key))
            {
                message = "The given key has an invalid checksum.";
                return false;
            }

            byte[] keyBa = Base58.DecodeWithChecksum(key);
            if (keyBa[0] != ConstantsFO.PrivKeyFirstByte)
            {
                message = $"Invalid first key byte (actual={keyBa[0]}, expected={ConstantsFO.PrivKeyFirstByte}).";
                return false;
            }

            if (keyBa.Length == 33)
            {
                if (!IsPrivateKeyInRange(keyBa.SubArray(1)))
                {
                    message = "Invalid key integer value (outside of the range defined by secp256k1 curve).";
                    return false;
                }

                message = "The given key is a valid uncompressed private key.";
                return true;
            }
            else if (keyBa.Length == 34)
            {
                if (keyBa[^1] != ConstantsFO.PrivKeyCompLastByte)
                {
                    message = $"Invalid compressed key last byte (actual={keyBa[^1]}, expected={ConstantsFO.PrivKeyCompLastByte}).";
                    return false;
                }

                if (!IsPrivateKeyInRange(keyBa.SubArray(1, 32)))
                {
                    message = "Invalid key integer value (outside of the range defined by secp256k1 curve).";
                    return false;
                }

                message = "The given key is a valid compressed private key.";
                return true;
            }
            else
            {
                message = $"The given key length is invalid. actual = {keyBa.Length}, expected = 33 (uncompressed) " +
                          $"or 34 (compressed)).";
                return false;
            }
        }

        public bool CheckIncompletePrivateKey(string key, char missingChar, out string error)
        {
            if (!IsMissingCharValid(missingChar))
            {
                error = $"Invalid missing character. Choose one from {ConstantsFO.MissingSymbols}";
                return false;
            }
            if (string.IsNullOrWhiteSpace(key))
            {
                error = "Key can not be null or empty.";
                return false;
            }
            if (!key.All(c => c == missingChar || ConstantsFO.Base58Chars.Contains(c)))
            {
                error = $"Key contains invalid base-58 characters (ignoring the missing char = {missingChar}).";
                return false;
            }

            if (key.Contains(missingChar))
            {
                // Both key length and its first character must be valid
                if (key.Length == ConstantsFO.PrivKeyCompWifLen)
                {
                    if (key[0] != ConstantsFO.PrivKeyCompChar1 && key[0] != ConstantsFO.PrivKeyCompChar2)
                    {
                        error = "Invalid first character for a compressed private key considering length.";
                        return false;
                    }
                }
                else if (key.Length == ConstantsFO.PrivKeyUncompWifLen)
                {
                    if (key[0] != ConstantsFO.PrivKeyUncompChar)
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
                if (key.Length > ConstantsFO.PrivKeyCompWifLen)
                {
                    error = "Key length is too big.";
                    return false;
                }
                else if (key.Length == ConstantsFO.PrivKeyCompWifLen &&
                    key[0] != ConstantsFO.PrivKeyCompChar1 && key[0] != ConstantsFO.PrivKeyCompChar2)
                {
                    error = "Invalid first key character considering its length.";
                    return false;
                }
                else if (key.Length == ConstantsFO.PrivKeyUncompWifLen && key[0] != ConstantsFO.PrivKeyUncompChar)
                {
                    error = "Invalid first key character considering its length.";
                    return false;
                }
                else if (key[0] != ConstantsFO.PrivKeyCompChar1 && key[0] != ConstantsFO.PrivKeyCompChar2 &&
                    key[0] != ConstantsFO.PrivKeyUncompChar)
                {
                    error = "The first character of the given private key is not valid.";
                    return false;
                }
            }

            error = null;
            return true;
        }

        public bool IsMissingCharValid(char c) => ConstantsFO.MissingSymbols.Contains(c);

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

            if ((address.StartsWith("1") || address.StartsWith("3")) && Base58.IsValidWithChecksum(address))
            {
                byte[] decoded = Base58.DecodeWithChecksum(address);
                if (decoded[0] != 0 || decoded.Length != 21)
                    return false;
                hash = decoded.SubArray(1);
                return true;
            }
            else if (address.StartsWith("bc1") && Bech32.IsValid(address, Bech32.Mode.B32))
            {
                byte[] decoded = Bech32.Decode(address, Bech32.Mode.B32, out byte witVer, out string hrp);
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

        public bool TryDecodeBip38(string bip38, out byte[] data, out byte[] salt,
                                   out bool isComp, out bool isEcMult, out bool hasLot, out string error)
        {
            isComp = false;
            salt = null;
            isEcMult = false;
            hasLot = false;
            if (!Base58.TryDecodeWithChecksum(bip38, out data))
            {
                error = "Invalid Base-58 encoding.";
                return false;
            }

            if (data.Length != ConstantsFO.Bip38ByteLen)
            {
                error = "Invalid encrypted bytes length.";
                data = null;
                return false;
            }

            Span<byte> actualPrefix = ((Span<byte>)data).Slice(0, 2);
            if (actualPrefix.SequenceEqual(ConstantsFO.Bip38PrefixECMult))
            {
                isEcMult = true;
                hasLot = (data[2] & 0b0000_0100) != 0;
            }
            else if (!actualPrefix.SequenceEqual(ConstantsFO.Bip38Prefix))
            {
                error = "Invalid prefix.";
                data = null;
                return false;
            }

            isComp = (data[2] & 0b0010_0000) != 0;
            salt = ((Span<byte>)data).Slice(3, 4).ToArray();
            data = ((Span<byte>)data).Slice(7, 32).ToArray();
            error = null;
            return true;
        }
    }
}
