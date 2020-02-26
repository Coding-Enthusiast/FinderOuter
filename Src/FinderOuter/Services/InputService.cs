// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend;
using FinderOuter.Backend.Encoders;
using System.Numerics;
using System.Text;

namespace FinderOuter.Services
{
    public class InputService
    {
        private readonly Base58 b58End = new Base58();
        private readonly Bech32 b32Enc = new Bech32();


        public bool CanBePrivateKey(string key)
        {
            return
                (key.Length == Constants.CompPrivKeyLen &&
                        (key[0] == Constants.CompPrivKeyChar1 || key[0] == Constants.CompPrivKeyChar2))
                ||
                (key.Length == Constants.UncompPrivKeyLen &&
                        (key[0] == Constants.UncompPrivKeyChar));
        }


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


        public bool NormalizeNFKD(string s, out string norm)
        {
            norm = s.Normalize(NormalizationForm.FormKD);
            return !s.IsNormalized(NormalizationForm.FormKD);
        }


        public bool IsValidAddress(string address, bool ignoreP2SH, out byte[] hash)
        {
            hash = null;
            if (string.IsNullOrWhiteSpace(address))
                return false;
            if (address.StartsWith("3") && ignoreP2SH)
                return false;

            if ((address.StartsWith("1") || address.StartsWith("3")) && b58End.IsValid(address))
            {
                byte[] decoded = b58End.DecodeWithCheckSum(address);
                if (decoded[0] != 0 || decoded.Length != 21)
                    return false;
                hash = decoded.SubArray(1);
                return true;
            }
            else if (address.StartsWith("bc1") && b32Enc.IsValid(address))
            {
                byte[] decoded = b32Enc.Decode(address, out byte witVer, out string hrp);
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
    }
}
