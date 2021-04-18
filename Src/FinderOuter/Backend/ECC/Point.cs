// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System;
using System.Diagnostics;

namespace FinderOuter.Backend.ECC
{
    /// <summary>
    /// Elliptic curve point in Affine coordinates
    /// </summary>
    public readonly struct Point
    {
        public Point(in UInt256_10x26 x26, in UInt256_10x26 y26)
        {
            x = x26;
            y = y26;
        }

        public Point(uint x0, uint x1, uint x2, uint x3, uint x4, uint x5, uint x6, uint x7,
                     uint y0, uint y1, uint y2, uint y3, uint y4, uint y5, uint y6, uint y7)
        {
            x = new UInt256_10x26(x0, x1, x2, x3, x4, x5, x6, x7);
            y = new UInt256_10x26(y0, y1, y2, y3, y4, y5, y6, y7);
        }


        public readonly UInt256_10x26 x, y;


        static readonly Point _zero = new(UInt256_10x26.Zero, UInt256_10x26.Zero);
        public static ref readonly Point Zero => ref _zero;

        static readonly Point _infinity = new(UInt256_10x26.Zero, UInt256_10x26.Zero);
        public static ref readonly Point Infinity => ref _infinity;

        public bool IsInfinity => x.IsZero && y.IsZero;


        public const byte EvenPubkey = 0x02;
        public const byte OddPubkey = 0x03;
        public const byte UncompressedPubkey = 0x04;
        public const byte EvenHybridPubkey = 0x06;
        public const byte OddHybridPubkey = 0x07;


        public Span<byte> ToByteArray(bool compressed)
        {
            UInt256_10x26 xNorm = x.NormalizeVariable();
            UInt256_10x26 yNorm = y.NormalizeVariable();

            if (compressed)
            {
                Span<byte> result = new byte[33];
                result[0] = yNorm.IsOdd ? OddPubkey : EvenPubkey;
                xNorm.WriteToSpan(result[1..]);
                return result;
            }
            else
            {
                Span<byte> result = new byte[65];
                result[0] = UncompressedPubkey;
                xNorm.WriteToSpan(result[1..]);
                yNorm.WriteToSpan(result[33..]);
                return result;
            }
        }

        public Span<byte> ToByteArray(out byte firstByte)
        {
            UInt256_10x26 xNorm = x.NormalizeVariable();
            UInt256_10x26 yNorm = y.NormalizeVariable();

            firstByte = yNorm.IsOdd ? OddPubkey : EvenPubkey;

            Span<byte> result = new byte[65];
            result[0] = UncompressedPubkey;
            xNorm.WriteToSpan(result[1..]);
            yNorm.WriteToSpan(result[33..]);
            return result;
        }



        public static void SetAllGroupElementJacobianVariable(Span<Point> r, ReadOnlySpan<PointJacobian> a, int len)
        {
            int i;
            int lastI = int.MaxValue;

            for (i = 0; i < len; i++)
            {
                if (!a[i].IsInfinity)
                {
                    /* Use destination's x coordinates as scratch space */
                    if (lastI == int.MaxValue)
                    {
                        r[i] = new Point(a[i].z, r[i].y);
                    }
                    else
                    {
                        UInt256_10x26 rx = r[lastI].x * a[i].z;
                        r[i] = new Point(rx, r[i].y);
                    }
                    lastI = i;
                }
            }
            if (lastI == int.MaxValue)
            {
                return;
            }
            UInt256_10x26 u = r[lastI].x.InverseVariable();

            i = lastI;
            while (i > 0)
            {
                i--;
                if (!a[i].IsInfinity)
                {
                    UInt256_10x26 rx = r[i].x * u;
                    r[lastI] = new Point(rx, r[lastI].y);
                    u *= a[lastI].z;
                    lastI = i;
                }
            }
            Debug.Assert(!a[lastI].IsInfinity);
            r[lastI] = new Point(u, r[lastI].y);

            for (i = 0; i < len; i++)
            {
                r[i] = new Point(r[i].x, r[i].y);
                if (!a[i].IsInfinity)
                {
                    r[i] = a[i].ToPointZInv(r[i].x);
                }
            }
        }

        public readonly PointStorage ToStorage()
        {
            Debug.Assert(!IsInfinity);
            return new PointStorage(x, y);
        }


        public readonly PointJacobian ToPointJacobian => new(x, y, new UInt256_10x26(1));


        public static bool TryCreateXQuad(UInt256_10x26 x, out Point result)
        {
            UInt256_10x26 x2 = x.Sqr();
            UInt256_10x26 x3 = x * x2;
            var c = new UInt256_10x26(Calc.CurveB);
            c += x3;
            if (!c.Sqrt(out UInt256_10x26 y))
            {
                result = Zero;
                return false;
            }

            result = new Point(x, y);
            return true;
        }

        public static bool TryCreateXOVariable(UInt256_10x26 x, bool odd, out Point result)
        {
            if (!TryCreateXQuad(x, out result))
                return false;
            var ry = result.y.NormalizeVariable();
            if (ry.IsOdd != odd)
            {
                ry = ry.Negate(1);
            }
            result = new Point(result.x, ry);
            return true;
        }
    }
}
