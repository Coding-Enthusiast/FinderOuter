// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.Cryptography.Asymmetric.EllipticCurve;
using System;
using System.Numerics;


namespace FinderOuter.Services.Comparers
{
    /// <summary>
    /// Converts private key to address using only uncompressed public key
    /// </summary>
    public class PrvToAddrUncompComparer : PrvToAddrBase
    {
        public override bool Compare(byte[] key)
        {
            BigInteger kVal = new BigInteger(key, true, true);
            if (kVal >= order || kVal == 0)
            {
                return false;
            }

            EllipticCurvePoint point = calc.MultiplyByG(kVal);

            byte[] xBytes = point.X.ToByteArray(true, true);
            byte[] yBytes = point.Y.ToByteArray(true, true);
            byte[] toHash = new byte[65];
            toHash[0] = 4;
            Buffer.BlockCopy(xBytes, 0, toHash, 33 - xBytes.Length, xBytes.Length);
            Buffer.BlockCopy(yBytes, 0, toHash, 65 - yBytes.Length, yBytes.Length);

            ReadOnlySpan<byte> compHash = hash160.Compress65(toHash);
            return compHash.SequenceEqual(hash);
        }
    }
}
