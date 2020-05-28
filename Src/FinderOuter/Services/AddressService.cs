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

        public bool CheckAndGetHash(string address, out byte[] hash)
        {
            hash = null;
            if (string.IsNullOrWhiteSpace(address))
            {
                return false;
            }

            return (address[0]) switch
            {
                '1' => addrMan.VerifyType(address, PubkeyScriptType.P2PKH, out hash),
                '3' => addrMan.VerifyType(address, PubkeyScriptType.P2SH, out hash),
                'b' => addrMan.VerifyType(address, PubkeyScriptType.P2WPKH, out hash),
                _ => false,
            };
        }
    }
}
