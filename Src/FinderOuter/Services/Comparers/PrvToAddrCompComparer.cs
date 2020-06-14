// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.Cryptography.Asymmetric.EllipticCurve;
using FinderOuter.Backend.Cryptography.Hashing;
using System;
using System.Numerics;

namespace FinderOuter.Services.Comparers
{
    /// <summary>
    /// Converts private key to address using only compressed public key
    /// </summary>
    class PrvToAddrCompComparer : ICompareService, IDisposable
    {
        private readonly SecP256k1 curve = new SecP256k1();
        private readonly EllipticCurveCalculator calc = new EllipticCurveCalculator();
        private byte[] hash;
        private readonly Hash160 hash160 = new Hash160();


        public bool TrySetHash(string address)
        {
            AddressService serv = new AddressService();
            return serv.CheckAndGetHash(address, out hash);
        }


        public bool Compare(byte[] key)
        {
            BigInteger kVal = new BigInteger(key, true, true);
            if (kVal >= curve.N || kVal == 0)
            {
                return false;
            }

            EllipticCurvePoint point = calc.MultiplyByG(kVal);

            byte[] xBytes = point.X.ToByteArray(true, true);
            byte[] toHash = new byte[33];
            toHash[0] = point.Y.IsEven ? (byte)2 : (byte)3;
            Buffer.BlockCopy(xBytes, 0, toHash, 33 - xBytes.Length, xBytes.Length);

            ReadOnlySpan<byte> compHash = hash160.Compress33(toHash);
            return compHash.SequenceEqual(hash);
        }


        public void Dispose() => hash160.Dispose();
    }
}
