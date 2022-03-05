// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using FinderOuter.Backend.Cryptography.Hashing;
using FinderOuter.Backend.ECC;
using System;

namespace FinderOuter.Services.Comparers
{
    /// <summary>
    /// Converts private key to address using both compressed and uncompressed public keys
    /// </summary>
    public class PrvToAddrBothComparer : PrvToAddrBase
    {
        public override ICompareService Clone()
        {
            return new PrvToAddrBothComparer()
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

            _calc.GetPubkey(in key, out Span<byte> comp, out Span<byte> uncomp);

            ReadOnlySpan<byte> compHash = Hash160.Compress33(comp);
            if (compHash.SequenceEqual(hash))
            {
                return true;
            }

            ReadOnlySpan<byte> uncompHash = Hash160.Compress65(uncomp);
            return uncompHash.SequenceEqual(hash);
        }

        public override unsafe bool Compare(ulong* hPt)
        {
            Scalar key = new(hPt, out int overflow);
            if (overflow != 0)
            {
                return false;
            }

            _calc.GetPubkey(in key, out Span<byte> comp, out Span<byte> uncomp);

            ReadOnlySpan<byte> compHash = Hash160.Compress33(comp);
            if (compHash.SequenceEqual(hash))
            {
                return true;
            }

            ReadOnlySpan<byte> uncompHash = Hash160.Compress65(uncomp);
            return uncompHash.SequenceEqual(hash);
        }

        public override bool Compare(in PointJacobian point)
        {
            Point pub = point.ToPoint();

            Span<byte> uncomp = pub.ToByteArray(out byte firstByte);
            ReadOnlySpan<byte> uncompHash = Hash160.Compress65(uncomp);
            if (uncompHash.SequenceEqual(hash))
            {
                return true;
            }

            Span<byte> comp = new byte[33];
            comp[0] = firstByte;
            uncomp.Slice(1, 32).CopyTo(comp[1..]);
            ReadOnlySpan<byte> compHash = Hash160.Compress33(comp.ToArray());
            return compHash.SequenceEqual(hash);
        }
    }
}
