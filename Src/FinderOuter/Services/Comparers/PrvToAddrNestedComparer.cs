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

        public override bool Compare(byte[] key)
        {
            BigInteger kVal = new BigInteger(key, true, true);
            if (kVal >= order || kVal == 0)
            {
                return false;
            }

            EllipticCurvePoint point = calc.MultiplyByG(kVal);

            byte[] xBytes = point.X.ToByteArray(true, true);
            byte[] toHash = new byte[33];
            toHash[0] = point.Y.IsEven ? (byte)2 : (byte)3;
            Buffer.BlockCopy(xBytes, 0, toHash, 33 - xBytes.Length, xBytes.Length);

            byte[] firstHash = hash160.Compress33(toHash);
            // OP_0 Push<20-bytes>
            toHash = new byte[22];
            toHash[1] = 20;
            Buffer.BlockCopy(firstHash, 0, toHash, 2, 20);

            ReadOnlySpan<byte> secondHash = hash160.Compress22(toHash);

            return secondHash.SequenceEqual(hash);
        }
    }
}
