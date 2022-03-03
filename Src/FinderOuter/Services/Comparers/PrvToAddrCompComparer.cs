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
    /// Converts private key to address using only compressed public key
    /// </summary>
    public class PrvToAddrCompComparer : PrvToAddrBase
    {
        public override ICompareService Clone()
        {
            return new PrvToAddrCompComparer()
            {
                hash = this.hash.CloneByteArray()
            };
        }

        public override unsafe bool Compare(uint* hPt)
        {
            Scalar key = new(hPt, out int overflow);
            if (overflow != 0)
            {
                return false;
            }

            Span<byte> toHash = calc2.GetPubkey(in key, true);

            ReadOnlySpan<byte> actual = Hash160.Compress33(toHash);
            return actual.SequenceEqual(hash);
        }

        public override unsafe bool Compare(ulong* hPt)
        {
            Scalar key = new(hPt, out int overflow);
            if (overflow != 0)
            {
                return false;
            }

            Span<byte> toHash = calc2.GetPubkey(in key, true);

            ReadOnlySpan<byte> actual = Hash160.Compress33(toHash);
            return actual.SequenceEqual(hash);
        }

        public override bool Compare(in PointJacobian point)
        {
            Span<byte> toHash = point.ToPoint().ToByteArray(true);
            ReadOnlySpan<byte> compHash = Hash160.Compress33(toHash);
            return compHash.SequenceEqual(hash);
        }

        public override bool Compare(in EllipticCurvePoint point)
        {
            byte[] xBytes = point.X.ToByteArray(true, true);
            byte[] toHash = new byte[33];
            toHash[0] = point.Y.IsEven ? (byte)2 : (byte)3;
            Buffer.BlockCopy(xBytes, 0, toHash, 33 - xBytes.Length, xBytes.Length);

            ReadOnlySpan<byte> compHash = Hash160.Compress33(toHash);
            return compHash.SequenceEqual(hash);
        }
    }
}
