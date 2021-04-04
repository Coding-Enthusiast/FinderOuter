// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System.ComponentModel;

namespace FinderOuter.Models
{
    public enum KB
    {
        Bitcoin,
        [Description("Private key")]
        PrivateKey,
        //[Description("Public key")]
        //Pubkey,

        //Address,
        //[Description("Mnemonic or seed phrase")]
        //Mnemonic,
        //[Description("Extended private/public key")]
        //ExtendedKey,
        //[Description("BIP-32 derivation path")]
        //Bip32Path,
        [Description("Damaged input")]
        DamagedInput,
        [Description("Extra input for comparison")]
        ExtraInput,
        [Description("Types of extra inputs for comparison")]
        ExtraInputTypes,
    }
}
