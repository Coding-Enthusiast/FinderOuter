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
    public class PrvToAddrNestedComparer : PrvToAddrBase
    {
        public override bool Init(string address)
        {
            IsInitialized = AddressService.CheckAndGetHash_P2sh(address, out hash);
            return IsInitialized;
        }

        public override ICompareService Clone()
        {
            return new PrvToAddrNestedComparer()
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

            Span<byte> toHash = _calc.GetPubkey(in key, true);

            ReadOnlySpan<byte> actual = Hash160Fo.Compress33_P2sh(toHash);
            return actual.SequenceEqual(hash);
        }

        public override unsafe bool Compare(ulong* hPt)
        {
            Scalar8x32 key = new(hPt, out bool overflow);
            if (overflow)
            {
                return false;
            }

            Span<byte> toHash = _calc.GetPubkey(in key, true);

            ReadOnlySpan<byte> actual = Hash160Fo.Compress33_P2sh(toHash);
            return actual.SequenceEqual(hash);
        }

        public override bool Compare(in PointJacobian point)
        {
            Span<byte> toHash = point.ToPoint().ToByteArray(true);
            ReadOnlySpan<byte> compHash = Hash160Fo.Compress33_P2sh(toHash);
            return compHash.SequenceEqual(hash);
        }
    }
}
