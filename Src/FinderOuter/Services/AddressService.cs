// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.Blockchain.Scripts;
using Autarkysoft.Bitcoin.Encoders;

namespace FinderOuter.Services
{
    public class AddressService
    {
        private readonly Address addrMan = new Address();

        /// <param name="accept3">If false, rejects P2SH addresses</param>
        public bool CheckAndGetHash(string address, bool accept3, out byte[] hash)
        {
            hash = null;
            if (string.IsNullOrWhiteSpace(address))
            {
                return false;
            }

            if (address[0] == '1')
            {
                return addrMan.VerifyType(address, PubkeyScriptType.P2PKH, out hash);
            }
            else if (address[0] == '3' && accept3)
            {
                return addrMan.VerifyType(address, PubkeyScriptType.P2SH, out hash);
            }
            else if (address[0] == 'b')
            {
                return addrMan.VerifyType(address, PubkeyScriptType.P2WPKH, out hash);
            }
            else
            {
                return false;
            }
        }
    }
}
