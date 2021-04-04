// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.Blockchain.Scripts;
using Autarkysoft.Bitcoin.Cryptography.Asymmetric.KeyPairs;
using Autarkysoft.Bitcoin.Encoders;

namespace FinderOuter.Services
{
    public class AddressService
    {
        /// <summary>
        /// Checks the given address and returns its decoded hash.
        /// Works only for P2PKH and P2WPKH addresses
        /// </summary>
        public bool CheckAndGetHash(string address, out byte[] hash)
        {
            hash = null;
            if (string.IsNullOrWhiteSpace(address))
            {
                return false;
            }

            if (address[0] == '1')
            {
                return Address.VerifyType(address, PubkeyScriptType.P2PKH, out hash);
            }
            else if (address[0] == 'b')
            {
                return Address.VerifyType(address, PubkeyScriptType.P2WPKH, out hash);
            }
            else
            {
                return false;
            }
        }

        /// <summary>
        /// Checks the given address and returns its decoded hash.
        /// Works only for P2SH addresses
        /// </summary>
        public bool CheckAndGetHash_P2sh(string address, out byte[] hash)
        {
            if (string.IsNullOrWhiteSpace(address) || address[0] != '3')
            {
                hash = null;
                return false;
            }
            else
            {
                return Address.VerifyType(address, PubkeyScriptType.P2SH, out hash);
            }
        }


        public bool Compare(string expectedAddr, InputType inType, PrivateKey prv, out string message)
        {
            var pub = prv.ToPublicKey();
            if (inType == InputType.AddrNested)
            {
                if (expectedAddr == Address.GetP2sh_P2wpkh(pub, 0))
                {
                    message = "The given address is derived from the given private key.";
                }
                else if (expectedAddr == Address.GetP2sh_P2wpkh(pub, 0, false))
                {
                    message = "The given address is derived from the given private key but it uses " +
                              "uncompressed pubkey which is non-standard.";
                }
                else
                {
                    message = "Can not derive the given address from this private key.";
                    return false;
                }
            }
            else
            {
                if (expectedAddr.StartsWith("bc"))
                {
                    if (expectedAddr == Address.GetP2wpkh(pub, 0))
                    {
                        message = "The given address is derived from the given private key.";
                    }
                    else if (expectedAddr == Address.GetP2wpkh(pub, 0, false))
                    {
                        message = "The given address is derived from the given private key but it uses " +
                                  "uncompressed pubkey which is non-standard.";
                    }
                    else
                    {
                        message = "Can not derive the given address from this private key.";
                        return false;
                    }
                }
                else if (expectedAddr.StartsWith("1"))
                {
                    string comp = Address.GetP2pkh(pub);
                    string uncomp = Address.GetP2pkh(pub, false);

                    if (inType == InputType.AddrComp)
                    {
                        if (expectedAddr == comp)
                        {
                            message = "The given address is derived from the given private key."; 
                        }
                        else if (expectedAddr == uncomp)
                        {
                            message = "The given address is derived from the given private key but uses " +
                                      "the uncompressed public key.";
                            return false;
                        }
                        else
                        {
                            message = "Can not derive the given address from this private key.";
                            return false;
                        }
                    }
                    else if (inType == InputType.AddrUnComp)
                    {
                        if (expectedAddr == uncomp)
                        {
                            message = "The given address is derived from the given private key.";
                        }
                        else if (expectedAddr == comp)
                        {
                            message = "The given address is derived from the given private key but uses " +
                                      "the compressed public key.";
                            return false;
                        }
                        else
                        {
                            message = "Can not derive the given address from this private key.";
                            return false;
                        }
                    }
                    else if (inType == InputType.AddrBoth && (expectedAddr == comp || expectedAddr == comp))
                    {
                        message = "The given address is derived from the given private key.";
                    }
                    else
                    {
                        message = "Can not derive the given address from this private key.";
                        return false;
                    }
                }
                else
                {
                    message = "Possible invalid address type.";
                    return false;
                }
            }

            return true;
        }
    }
}
