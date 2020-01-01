// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

namespace FinderOuter.Backend
{
    /// <summary>
    /// Defined script types in <see cref="PubkeyScript"/>
    /// </summary>
    public enum PubkeyScriptType
    {
        /// <summary>
        /// An empty <see cref="PubkeyScript"/> instance
        /// </summary>
        Empty,
        /// <summary>
        /// Unknown or undefined script type
        /// </summary>
        Unknown,
        /// <summary>
        /// "Pay to public key" public script
        /// </summary>
        P2PK,
        /// <summary>
        /// "Pay to public key hash" public script
        /// </summary>
        P2PKH,
        /// <summary>
        /// "Pay to script hash" public script
        /// </summary>
        P2SH,
        /// <summary>
        /// "Pay to multi-sig" public script
        /// </summary>
        P2MS,
        /// <summary>
        /// <see cref="OP.CheckLocktimeVerify"/> public script
        /// </summary>
        CheckLocktimeVerify,
        /// <summary>
        /// <see cref="OP.RETURN"/> public script
        /// </summary>
        RETURN,
        /// <summary>
        /// "Pay to witness public key hash" public script
        /// </summary>
        P2WPKH,
        /// <summary>
        /// "Pay to witness script hash" public script
        /// </summary>
        P2WSH
    }
}
