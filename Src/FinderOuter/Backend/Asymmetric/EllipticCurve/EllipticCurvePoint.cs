// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System;
using System.Numerics;

namespace FinderOuter.Backend.Cryptography.Asymmetric.EllipticCurve
{
    /// <summary>
    /// Represents a (X,Y) coordinate pair for elliptic curve cryptography (ECC) structures.
    /// </summary>
    public readonly struct EllipticCurvePoint : IEquatable<EllipticCurvePoint>
    {
        /// <summary>
        /// Initializes a new instance of <see cref="EllipticCurvePoint"/> with given x and y coordinates.
        /// </summary>
        /// <param name="x">x coordinate</param>
        /// <param name="y">y coordinate</param>
        public EllipticCurvePoint(BigInteger x, BigInteger y)
        {
            X = x;
            Y = y;
        }



        public BigInteger X { get; }
        public BigInteger Y { get; }



        /// <summary>
        /// Represents the point at infinity.
        /// </summary>
        public static EllipticCurvePoint InfinityPoint => new EllipticCurvePoint(0, 0);


        public static bool operator ==(EllipticCurvePoint p1, EllipticCurvePoint p2)
        {
            return p1.X == p2.X && p1.Y == p2.Y;
        }
        public static bool operator !=(EllipticCurvePoint p1, EllipticCurvePoint p2)
        {
            return !(p1 == p2);
        }
        public override bool Equals(object obj)
        {
            return obj is EllipticCurvePoint && this == (EllipticCurvePoint)obj;
        }
        public override int GetHashCode()
        {
            BigInteger sum = X + Y;
            return sum.GetHashCode();
        }

        public bool Equals(EllipticCurvePoint other)
        {
            return this == other;
        }

    }
}
