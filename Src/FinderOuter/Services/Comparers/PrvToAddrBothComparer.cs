// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using Autarkysoft.Bitcoin.Cryptography.EllipticCurve;
using Autarkysoft.Bitcoin.Cryptography.EllipticCurve.Primitives;
using FinderOuter.Backend.Hashing;
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
            Scalar4x64 key = new(hPt, out bool overflow);
            if (overflow)
            {
                return false;
            }

            _calc.GetPubkey(in key, out Span<byte> comp, out Span<byte> uncomp);

            ReadOnlySpan<byte> compHash = Hash160Fo.Compress33(comp);
            if (compHash.SequenceEqual(hash))
            {
                return true;
            }

            ReadOnlySpan<byte> uncompHash = Hash160Fo.Compress65(uncomp);
            return uncompHash.SequenceEqual(hash);
        }

        public override unsafe bool Compare(ulong* hPt)
        {
            Scalar4x64 key = new(hPt, out bool overflow);
            if (overflow)
            {
                return false;
            }

            _calc.GetPubkey(in key, out Span<byte> comp, out Span<byte> uncomp);

            ReadOnlySpan<byte> compHash = Hash160Fo.Compress33(comp);
            if (compHash.SequenceEqual(hash))
            {
                return true;
            }

            ReadOnlySpan<byte> uncompHash = Hash160Fo.Compress65(uncomp);
            return uncompHash.SequenceEqual(hash);
        }

        public override bool Compare(in PointJacobian point)
        {
            Point pub = point.ToPoint();

            UInt256_5x52 xNorm = pub.x.NormalizeVar();
            UInt256_5x52 yNorm = pub.y.NormalizeVar();

            byte firstByte = yNorm.IsOdd ? (byte)3 : (byte)2;

            Span<byte> uncomp = new byte[65];
            uncomp[0] = 4;
            xNorm.WriteToSpan(uncomp[1..]);
            yNorm.WriteToSpan(uncomp[33..]);

            ReadOnlySpan<byte> uncompHash = Hash160Fo.Compress65(uncomp);
            if (uncompHash.SequenceEqual(hash))
            {
                return true;
            }

            Span<byte> comp = new byte[33];
            comp[0] = firstByte;
            uncomp.Slice(1, 32).CopyTo(comp[1..]);
            ReadOnlySpan<byte> compHash = Hash160Fo.Compress33(comp.ToArray());
            return compHash.SequenceEqual(hash);
        }
    }
}
