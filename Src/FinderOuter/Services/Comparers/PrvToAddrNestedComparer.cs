// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.Cryptography.Asymmetric.EllipticCurve;
using System;
using System.Numerics;

namespace FinderOuter.Services.Comparers
{
    public class PrvToAddrNestedComparer : PrvToAddrBase
    {
        public override bool Init(string address)
        {
            AddressService serv = new AddressService();
            return serv.CheckAndGetHash_P2sh(address, out hash);
        }

        public override bool Compare(BigInteger key)
        {
            EllipticCurvePoint point = calc.MultiplyByG(key);

            byte[] xBytes = point.X.ToByteArray(true, true);
            byte[] toHash = new byte[33];
            toHash[0] = point.Y.IsEven ? (byte)2 : (byte)3;
            Buffer.BlockCopy(xBytes, 0, toHash, 33 - xBytes.Length, xBytes.Length);

            ReadOnlySpan<byte> actual = hash160.Compress33_P2sh(toHash);
            return actual.SequenceEqual(hash);
        }
    }
}
