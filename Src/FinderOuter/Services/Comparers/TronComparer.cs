// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using Autarkysoft.Bitcoin.Cryptography.Asymmetric.EllipticCurve;
using Autarkysoft.Bitcoin.Encoders;
using FinderOuter.Backend.Cryptography.Hashing;
using System;
using System.Linq;
using System.Numerics;

namespace FinderOuter.Services.Comparers
{
    public class TronComparer : ICompareService
    {
        private byte[] hash;
        protected readonly Keccak256 keccak256 = new Keccak256();


        public bool Init(string address)
        {
            if (!address.StartsWith("T"))
            {
                return false;
            }
            var enc = new Base58();
            try
            {
                var bytes = enc.DecodeWithCheckSum(address);
                if (bytes.Length != 21 || bytes[0] != 0x41)
                {
                    return false;
                }

                hash = bytes.SubArray(1, 20);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public ICompareService Clone()
        {
            throw new NotImplementedException();
        }

        public bool Compare(byte[] key)
        {
            throw new NotImplementedException();
        }

        public bool Compare(BigInteger key)
        {
            throw new NotImplementedException();
        }

        public bool Compare(in EllipticCurvePoint point)
        {
            byte[] xBytes = point.X.ToByteArray(true, true);
            byte[] yBytes = point.Y.ToByteArray(true, true);
            byte[] toHash = new byte[64]; // Tron doesn't use the initial byte 0x04 in pubkeys
            Buffer.BlockCopy(xBytes, 0, toHash, 32 - xBytes.Length, xBytes.Length);
            Buffer.BlockCopy(yBytes, 0, toHash, 64 - yBytes.Length, yBytes.Length);

            ReadOnlySpan<byte> compHash = keccak256.ComputeHash(toHash);
            return compHash.Slice(12).SequenceEqual(hash);
        }
    }
}
