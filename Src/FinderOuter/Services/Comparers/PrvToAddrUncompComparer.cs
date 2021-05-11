// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using Autarkysoft.Bitcoin.Cryptography.Asymmetric.EllipticCurve;
using FinderOuter.Backend.Cryptography.Hashing;
using FinderOuter.Backend.ECC;
using System;

namespace FinderOuter.Services.Comparers
{
    /// <summary>
    /// Converts private key to address using only uncompressed public key
    /// </summary>
    public class PrvToAddrUncompComparer : PrvToAddrBase
    {
        public override ICompareService Clone()
        {
            return new PrvToAddrUncompComparer()
            {
                hash = this.hash.CloneByteArray()
            };
        }

        public override unsafe bool Compare(uint* hPt)
        {
            var key = new Scalar(hPt, out int overflow);
            if (overflow != 0)
            {
                return false;
            }

            Span<byte> toHash = calc2.GetPubkey(in key, false);

            ReadOnlySpan<byte> compHash = Hash160.Compress65(toHash);
            return compHash.SequenceEqual(hash);
        }

        public override unsafe bool Compare(ulong* hPt)
        {
            var key = new Scalar(hPt, out int overflow);
            if (overflow != 0)
            {
                return false;
            }

            Span<byte> toHash = calc2.GetPubkey(in key, false);

            ReadOnlySpan<byte> compHash = Hash160.Compress65(toHash);
            return compHash.SequenceEqual(hash);
        }

        public override bool Compare(in PointJacobian point)
        {
            Span<byte> toHash = point.ToPoint().ToByteArray(false);
            ReadOnlySpan<byte> compHash = Hash160.Compress65(toHash);
            return compHash.SequenceEqual(hash);
        }

        public override bool Compare(in EllipticCurvePoint point)
        {
            byte[] xBytes = point.X.ToByteArray(true, true);
            byte[] yBytes = point.Y.ToByteArray(true, true);
            byte[] toHash = new byte[65];
            toHash[0] = 4;
            Buffer.BlockCopy(xBytes, 0, toHash, 33 - xBytes.Length, xBytes.Length);
            Buffer.BlockCopy(yBytes, 0, toHash, 65 - yBytes.Length, yBytes.Length);

            ReadOnlySpan<byte> compHash = Hash160.Compress65(toHash);
            return compHash.SequenceEqual(hash);
        }
    }
}
