// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using Autarkysoft.Bitcoin.Cryptography.Asymmetric.EllipticCurve;
using FinderOuter.Backend.ECC;
using System;

namespace FinderOuter.Services.Comparers
{
    public class PrvToAddrNestedComparer : PrvToAddrBase
    {
        public override bool Init(string address)
        {
            AddressService serv = new AddressService();
            return serv.CheckAndGetHash_P2sh(address, out hash);
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
            var key = new Scalar(hPt, out int overflow);
            if (overflow != 0)
            {
                return false;
            }

            Span<byte> toHash = calc2.GetPubkey(in key, true);

            ReadOnlySpan<byte> actual = hash160.Compress33_P2sh(toHash.ToArray());
            return actual.SequenceEqual(hash);
        }

        public override unsafe bool Compare(ulong* hPt)
        {
            var key = new Scalar(hPt, out int overflow);
            if (overflow != 0)
            {
                return false;
            }

            Span<byte> toHash = calc2.GetPubkey(in key, true);

            ReadOnlySpan<byte> actual = hash160.Compress33_P2sh(toHash.ToArray());
            return actual.SequenceEqual(hash);
        }

        public override bool Compare(in EllipticCurvePoint point)
        {
            byte[] xBytes = point.X.ToByteArray(true, true);
            byte[] toHash = new byte[33];
            toHash[0] = point.Y.IsEven ? (byte)2 : (byte)3;
            Buffer.BlockCopy(xBytes, 0, toHash, 33 - xBytes.Length, xBytes.Length);

            ReadOnlySpan<byte> actual = hash160.Compress33_P2sh(toHash);
            return actual.SequenceEqual(hash);
        }
    }
}
