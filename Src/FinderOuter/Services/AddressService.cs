// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.Blockchain.Scripts;
using Autarkysoft.Bitcoin.Cryptography.EllipticCurve;
using Autarkysoft.Bitcoin.Encoders;
using System.Text;

namespace FinderOuter.Services
{
    public static class AddressService
    {
        /// <summary>
        /// Checks the given address and returns its decoded hash.
        /// Works only for P2PKH and P2WPKH addresses
        /// </summary>
        public static bool CheckAndGetHash(string address, out byte[] hash)
        {
            hash = null;
            if (string.IsNullOrWhiteSpace(address))
            {
                return false;
            }
            else if (address[0] == '1')
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
        public static bool CheckAndGetHash_P2sh(string address, out byte[] hash)
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


        public static string GetAllAddresses(in Point pub)
        {
            StringBuilder sb = new(4 * 64);

            sb.AppendLine($"Compressed P2PKH:   {Address.GetP2pkh(pub)}");
            sb.AppendLine($"Uncompressed P2PKH: {Address.GetP2pkh(pub, false)}");
            sb.AppendLine($"P2WPKH:             {Address.GetP2wpkh(pub)}");
            sb.AppendLine($"P2SH-P2WPKH:        {Address.GetP2sh_P2wpkh(pub)}");

            return sb.ToString();
        }
    }
}
