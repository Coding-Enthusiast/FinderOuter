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
            var key = new Scalar(hPt, out int overflow);
            if (overflow != 0)
            {
                return false;
            }

            calc2.GetPubkey(in key, out Span<byte> comp, out Span<byte> uncomp);

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
            var key = new Scalar(hPt, out int overflow);
            if (overflow != 0)
            {
                return false;
            }

            calc2.GetPubkey(in key, out Span<byte> comp, out Span<byte> uncomp);

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

        public override bool Compare(in EllipticCurvePoint point)
        {
            byte[] xBytes = point.X.ToByteArray(true, true);
            byte[] toHash = new byte[65];
            toHash[0] = point.Y.IsEven ? (byte)2 : (byte)3;
            Buffer.BlockCopy(xBytes, 0, toHash, 33 - xBytes.Length, xBytes.Length);

            ReadOnlySpan<byte> compHash = Hash160.Compress33(toHash);
            if (compHash.SequenceEqual(hash))
            {
                return true;
            }

            byte[] yBytes = point.Y.ToByteArray(true, true);
            toHash[0] = 4;
            Buffer.BlockCopy(yBytes, 0, toHash, 65 - yBytes.Length, yBytes.Length);

            ReadOnlySpan<byte> uncompHash = Hash160.Compress65(toHash);

            return uncompHash.SequenceEqual(hash);
        }
    }
}
