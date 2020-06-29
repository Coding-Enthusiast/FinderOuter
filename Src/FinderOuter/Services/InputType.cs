// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System.ComponentModel;

namespace FinderOuter.Services
{
    public enum InputType
    {
        [Description("Address created using compressed public key")]
        AddrComp,
        [Description("Address created using uncompressed public key")]
        AddrUnComp,
        [Description("Address created using either compressed or uncompressed public key")]
        AddrBoth,
        [Description("P2SH-P2WPKH or nested SegWit starting with 3")]
        AddrNested,
        [Description("Public key in hexadecimal format")]
        Pubkey,
        [Description("Private key in WIF (Base-58) format")]
        PrivateKey,
    }
}
