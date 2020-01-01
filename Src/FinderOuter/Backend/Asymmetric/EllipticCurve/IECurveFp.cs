// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System.Numerics;

namespace FinderOuter.Backend.Cryptography.Asymmetric.EllipticCurve
{
    public interface IECurveFp
    {
        /// <summary>
        /// Name of the curve
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Prime
        /// </summary>
        BigInteger P { get; }

        /// <summary>
        /// Curve element 'a'
        /// </summary>
        BigInteger A { get; }

        /// <summary>
        /// Curve element 'b'
        /// </summary>
        BigInteger B { get; }

        /// <summary>
        /// Order of <see cref="G"/>
        /// </summary>
        BigInteger N { get; }

        /// <summary>
        /// Base point
        /// </summary>
        EllipticCurvePoint G { get; }

        /// <summary>
        /// Cofactor
        /// </summary>
        short H { get; }

        /// <summary>
        /// [optional] seed used for creating the curve.
        /// </summary>
        byte[] Seed { get; }

        /// <summary>
        /// Size of the curve in bits. 
        /// <para/>= (int)Math.Ceiling(BigInteger.Log(p, 2));
        /// </summary>
        int SizeInBits { get; }

        /// <summary>
        /// Size of <see cref="N"/> in bits. Usually is the same as <see cref="SizeInBits"/>. 
        /// Used for calculationg of 'e' during signing process
        /// <para/>= (int)Math.Ceiling(BigInteger.Log(n, 2));
        /// </summary>
        int NSizeInBits { get; }

        /// <summary>
        /// Approximate level of security in bits that the curve offers, also known as "t". 
        /// <para/> Log2(P)/2
        /// </summary>
        int SecurityLevel { get; }

        /// <summary>
        /// Checks to see if the given point is on the elliptic curve.
        /// </summary>
        /// <param name="point">Point to check</param>
        /// <returns>True if the point is on the curve, false if otherwise.</returns>
        bool IsOnCurve(EllipticCurvePoint point);
    }
}
