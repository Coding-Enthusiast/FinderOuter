// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.Cryptography.Asymmetric.EllipticCurve;
using System.Numerics;

namespace FinderOuter.Backend.Asymmetric.EllipticCurve
{
    public class TempCurve : IECurveFp
    {
        /// <summary>
        /// Prime (FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
        /// </summary>
        public BigInteger P { get; } = BigInteger.Parse("115792089237316195423570985008687907853269984665640564039457584007908834671663");
        /// <inheritdoc/>
        public BigInteger A { get; } = BigInteger.Zero;
        /// <inheritdoc/>
        public BigInteger B { get; } = new BigInteger(7);
        /// <summary>
        /// Curve order (FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
        /// </summary>
        public BigInteger N { get; } = BigInteger.Parse("115792089237316195423570985008687907852837564279074904382605163141518161494337");
        /// <summary>
        /// Curve generator 
        /// <para/> 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        /// <para/> 483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
        /// </summary>
        public EllipticCurvePoint G { get; } = new EllipticCurvePoint(
            BigInteger.Parse("55066263022277343669578718895168534326250603453777594175500187360389116729240"),
            BigInteger.Parse("32670510020758816978083085130507043184471273380659243275938904335757337482424"));
        /// <inheritdoc/>
        public short H => 1;
        /// <inheritdoc/>
        public int SizeInBits => 256;
        /// <inheritdoc/>
        public int SecurityLevel => 128;


        /// <summary>
        /// Returns if a given <see cref="EllipticCurvePoint"/> is on this curve.
        /// </summary>
        /// <param name="point">The <see cref="EllipticCurvePoint"/> to check.</param>
        /// <returns>True if the point is on curve, false if otherwise.</returns>
        public bool IsOnCurve(EllipticCurvePoint point)
        {
            if (point == EllipticCurvePoint.InfinityPoint)
            {
                return true;
            }
            // Big*Big is faster than Pow(Big,2). Only true for 2 though.
            BigInteger rem = ((point.Y * point.Y) - BigInteger.Pow(point.X, 3) - B) % P;
            return rem == 0;
        }
    }
}
