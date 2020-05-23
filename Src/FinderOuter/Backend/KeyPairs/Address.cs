// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using Autarkysoft.Bitcoin.Blockchain.Scripts;
using Autarkysoft.Bitcoin.Encoders;
using FinderOuter.Backend.Cryptography.Hashing;
using System;

namespace FinderOuter.Backend.KeyPairs
{
    public class Address
    {
        public Address()
        {
            b58Encoder = new Base58();
            b32Encoder = new Bech32();
            hashFunc = new Ripemd160Sha256();
            witHashFunc = new Sha256();

            versionByte_P2pkh_MainNet = 0;
            versionByte_P2pkh_TestNet = 111;
            versionByte_P2pkh_RegTest = 0;

            versionByte_P2sh_MainNet = 5;
            versionByte_P2sh_TestNet = 196;
            versionByte_P2sh_RegTest = 5;

            hrp_MainNet = "bc";
            hrp_TestNet = "tb";
            hrp_RegTest = "bcrt";
        }



        private readonly Base58 b58Encoder;
        private readonly Bech32 b32Encoder;
        private readonly IHashFunction hashFunc;
        private readonly Sha256 witHashFunc;
        private readonly byte versionByte_P2pkh_MainNet, versionByte_P2pkh_TestNet, versionByte_P2pkh_RegTest;
        private readonly byte versionByte_P2sh_MainNet, versionByte_P2sh_TestNet, versionByte_P2sh_RegTest;
        private readonly string hrp_MainNet, hrp_TestNet, hrp_RegTest;

        public enum AddressType
        {
            /// <summary>
            /// An invalid address
            /// </summary>
            Invalid,

            /// <summary>
            /// Pay to Pubkey Hash
            /// </summary>
            P2PKH,

            /// <summary>
            /// Pay to Script Hash
            /// </summary>
            P2SH,

            /// <summary>
            /// Pay to Witness Public Key Hash
            /// </summary>
            P2WPKH,

            /// <summary>
            /// Pay to Witness Script Hash
            /// </summary>
            P2WSH
        }

        public AddressType GetAddressType(string address)
        {
            if (string.IsNullOrWhiteSpace(address))
            {
                return AddressType.Invalid;
            }

            try
            {
                byte[] decoded = b58Encoder.DecodeWithCheckSum(address);
                if (decoded.Length == hashFunc.HashByteSize + 1)
                {
                    if (decoded[0] == versionByte_P2pkh_MainNet ||
                        decoded[0] == versionByte_P2pkh_TestNet ||
                        decoded[0] == versionByte_P2pkh_RegTest)
                    {
                        return AddressType.P2PKH;
                    }
                    else if (decoded[0] == versionByte_P2sh_MainNet ||
                             decoded[0] == versionByte_P2sh_TestNet ||
                             decoded[0] == versionByte_P2sh_RegTest)
                    {
                        return AddressType.P2SH;
                    }
                }

                return AddressType.Invalid;
            }
            catch (Exception) { }

            try
            {
                byte[] decoded = b32Encoder.Decode(address, out byte witVer, out string hrp);

                if (witVer == 0 &&
                    hrp == hrp_MainNet || hrp == hrp_TestNet || hrp == hrp_RegTest)
                {
                    if (decoded.Length == hashFunc.HashByteSize)
                    {
                        return AddressType.P2WPKH;
                    }
                    else if (decoded.Length == witHashFunc.BlockByteSize)
                    {
                        return AddressType.P2WSH;
                    }
                }
            }
            catch (Exception) { }

            return AddressType.Invalid;
        }


        internal string GetAddress(PublicKey pubkey, PubkeyScriptType addrType, NetworkType netType, bool compressed)
        {
            return addrType switch
            {
                PubkeyScriptType.P2PKH => GetP2pkh(pubkey, netType, compressed),
                PubkeyScriptType.P2WPKH => GetP2wpkh(pubkey, 0, netType),
                PubkeyScriptType.P2WSH => GetP2wsh(pubkey, 0, netType),
                _ => throw new ArgumentException($"Address is not defined for {addrType.ToString()} type of script."),
            };
        }



        public string GetP2pkh(PublicKey pubk, NetworkType netType, bool useCompressed)
        {
            byte[] hash160 = hashFunc.ComputeHash(pubk.ToByteArray(useCompressed));

            hash160 = netType switch
            {
                NetworkType.MainNet => hash160.AppendToBeginning(versionByte_P2pkh_MainNet),
                NetworkType.TestNet => hash160.AppendToBeginning(versionByte_P2pkh_TestNet),
                NetworkType.RegTest => hash160.AppendToBeginning(versionByte_P2pkh_RegTest),
                _ => throw new ArgumentException($"Network type ({netType}) is not defined!"),
            };
            return b58Encoder.EncodeWithCheckSum(hash160);
        }


        public string GetP2wpkh(PublicKey pubkey, byte witVer, NetworkType netType)
        {
            byte[] hash160 = hashFunc.ComputeHash(pubkey.ToByteArray(true));
            var hrp = netType switch
            {
                NetworkType.MainNet => hrp_MainNet,
                NetworkType.TestNet => hrp_TestNet,
                NetworkType.RegTest => hrp_RegTest,
                _ => throw new ArgumentException($"Network type ({netType}) is not defined!"),
            };
            return b32Encoder.Encode(hash160, witVer, hrp);
        }

        public string GetToP2SH_P2WPKH(PublicKey pubkey, NetworkType netType)
        {
            byte[] hash = hashFunc.ComputeHash(pubkey.ToByteArray(true));
            hash = hash.AppendToBeginning(20).AppendToBeginning(0); // OP_0 <20 byte hash>
            hash = hashFunc.ComputeHash(hash);

            hash = netType switch
            {
                NetworkType.MainNet => hash.AppendToBeginning(versionByte_P2sh_MainNet),
                NetworkType.TestNet => hash.AppendToBeginning(versionByte_P2sh_TestNet),
                NetworkType.RegTest => hash.AppendToBeginning(versionByte_P2sh_RegTest),
                _ => throw new ArgumentException($"Network type ({netType}) is not defined!"),
            };
            return b58Encoder.EncodeWithCheckSum(hash);
        }


        public string GetP2wsh(PublicKey pubkey, int v, NetworkType netType)
        {
            throw new NotImplementedException();
        }

    }
}
