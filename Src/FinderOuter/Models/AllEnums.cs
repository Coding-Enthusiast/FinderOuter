// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System;
using System.ComponentModel;

namespace FinderOuter.Models
{
    public enum Base58Type
    {
        PrivateKey,
        Address,
        Bip38
    }


    public enum CompareInputType
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


    public enum EncodingName
    {
        Base16,
        Base43,
        Base58,
        Base58Check,
        Base64,
    }


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
        [Description("BIP-32 derivation path")]
        Bip32Path,
        [Description("Damaged input")]
        DamagedInput,
        [Description("Extra input for comparison")]
        ExtraInput,
        [Description("Types of extra inputs for comparison")]
        ExtraInputTypes,
        [Description("Password recovery mode (alphanumeric)")]
        AlphanumericPass,
        [Description("Password recovery mode (custom characters)")]
        CustomCharPass,
        [Description("Number of threads used in settings")]
        ThreadCount,
    }


    public enum MessageBoxType
    {
        Ok,
        OkCancel,
        YesNo,
    }


    public enum MessageBoxResult
    {
        Ok,
        Cancel,
        Yes,
        No
    }


    public enum MnemonicTypes
    {
        BIP39,
        Electrum,
    }


    public enum PassRecoveryMode
    {
        [Description("A password consisting of random characters")]
        Alphanumeric,
        [Description("Custom password characters")]
        CustomChars
    }


    [Flags]
    public enum PasswordType : ulong
    {
        None = 0,
        UpperCase = 1 << 0,
        LowerCase = 1 << 1,
        Numbers = 1 << 2,
        Symbols = 1 << 3,
        Space = 1 << 4
    }


    public enum Possibility
    {
        Maybe,
        Possible,
        Impossible
    }


    public enum State
    {
        Ready,
        Working,
        Paused,
        Stopped,
        FinishedSuccess,
        FinishedFail
    }
}
