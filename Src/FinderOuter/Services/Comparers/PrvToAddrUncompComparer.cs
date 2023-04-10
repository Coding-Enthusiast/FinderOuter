// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using Autarkysoft.Bitcoin.Cryptography.EllipticCurve;
using FinderOuter.Backend.Hashing;
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
            Scalar8x32 key = new(hPt, out bool overflow);
            if (overflow)
            {
                return false;
            }

            Span<byte> toHash = _calc.GetPubkey(in key, false);

            ReadOnlySpan<byte> compHash = Hash160Fo.Compress65(toHash);
            return compHash.SequenceEqual(hash);
        }

        public override unsafe bool Compare(ulong* hPt)
        {
            Scalar8x32 key = new(hPt, out bool overflow);
            if (overflow)
            {
                return false;
            }

            Span<byte> toHash = _calc.GetPubkey(in key, false);

            ReadOnlySpan<byte> compHash = Hash160Fo.Compress65(toHash);
            return compHash.SequenceEqual(hash);
        }

        public override bool Compare(in PointJacobian point)
        {
            Span<byte> toHash = point.ToPoint().ToByteArray(false);
            ReadOnlySpan<byte> compHash = Hash160Fo.Compress65(toHash);
            return compHash.SequenceEqual(hash);
        }
    }
}
