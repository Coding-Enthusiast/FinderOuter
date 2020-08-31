// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using Autarkysoft.Bitcoin.Cryptography.Asymmetric.EllipticCurve;
using FinderOuter.Backend.Asymmetric.EllipticCurve;
using FinderOuter.Backend.Cryptography.Arithmetic;
using System;
using System.Collections.Generic;
using System.Numerics;

namespace FinderOuter.Backend.Cryptography.Asymmetric.EllipticCurve
{
    public class ECCalc
    {
        public ECCalc() : this(new TempCurve())
        {
        }

        public ECCalc(IECurveFp curve)
        {
            this.curve = curve;
        }



        private readonly IECurveFp curve;



        /// <summary>
        /// Checks to see if the given point is on the used elliptic curve.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <param name="point">Point to check</param>
        public void CheckOnCurve(EllipticCurvePoint point)
        {
            if (!curve.IsOnCurve(point))
            {
                throw new ArgumentOutOfRangeException("The given point is not on the given curve.");
            }
        }

        public EllipticCurvePoint PointNeg(EllipticCurvePoint point)
        {
            CheckOnCurve(point);

            return PointNegChecked(point);
        }

        internal EllipticCurvePoint PointNegChecked(EllipticCurvePoint point)
        {
            return (point == EllipticCurvePoint.InfinityPoint) ? point : new EllipticCurvePoint(point.X, (-point.Y).Mod(curve.P));
        }

        public EllipticCurvePoint Add(EllipticCurvePoint point1, EllipticCurvePoint point2)
        {
            CheckOnCurve(point1);
            CheckOnCurve(point2);

            return AddChecked(point1, point2);
        }

        internal EllipticCurvePoint AddChecked(EllipticCurvePoint point1, EllipticCurvePoint point2)
        {
            if (point1 == EllipticCurvePoint.InfinityPoint)
                return point2;
            if (point2 == EllipticCurvePoint.InfinityPoint)
                return point1;

            BigInteger m;

            if (point1.X == point2.X)
            {
                if (point1.Y != point2.Y) // (x,y) + (x,−y) = O
                {
                    return EllipticCurvePoint.InfinityPoint;
                }

                // Point double or (x,y) + (x,y)
                m = ((3 * point1.X * point1.X) + curve.A) * (2 * point1.Y).ModInverse(curve.P);

                // Note that since points are on a group with a prime (mod p) all of them do have multiplicative inverses.
            }
            else // point1 != point2. (x1,y1) + (x2,y2)
            {
                m = (point1.Y - point2.Y) * (point1.X - point2.X).ModInverse(curve.P);
            }

            BigInteger x3 = ((m * m) - point1.X - point2.X).Mod(curve.P);
            BigInteger y3 = (m * (point1.X - x3) - point1.Y).Mod(curve.P);

            return new EllipticCurvePoint(x3, y3);
        }

        internal EllipticCurvePoint DoubleChecked(EllipticCurvePoint point1)
        {
            if (point1 == EllipticCurvePoint.InfinityPoint)
                return point1;

            BigInteger m = 3 * point1.X * point1.X * (2 * point1.Y).ModInverse(curve.P);
            BigInteger x3 = ((m * m) - (2 * point1.X)).Mod(curve.P);
            BigInteger y3 = (m * (point1.X - x3) - point1.Y).Mod(curve.P);

            return new EllipticCurvePoint(x3, y3);
        }

        /// <summary>
        /// Returtns the result of multiplying the curve's generator with the given integer.
        /// Assumes point is on curve and k>0 and &#60;<see cref="IECurveFp.N"/>.
        /// </summary>
        /// <param name="k">The integer to multiply the point with</param>
        /// <returns>Result of multiplication</returns>
        public EllipticCurvePoint MultiplyByG(BigInteger k)
        {
            return MultiplyChecked(k, curve.G);
        }

        public EllipticCurvePoint Multiply(BigInteger k, EllipticCurvePoint point)
        {
            CheckOnCurve(point);

            if (k % curve.N == 0 || point == EllipticCurvePoint.InfinityPoint)
                return EllipticCurvePoint.InfinityPoint;

            return (k < 0) ? MultiplyChecked(-k, PointNegChecked(point)) : MultiplyChecked(k, point);
        }

        internal EllipticCurvePoint MultiplyChecked(BigInteger k, EllipticCurvePoint point)
        {
            EllipticCurvePoint result = EllipticCurvePoint.InfinityPoint;
            EllipticCurvePoint addend = point;

            while (k != 0)
            {
                if ((k & 1) == 1)
                {
                    result = AddChecked(result, addend);
                }

                addend = DoubleChecked(addend);

                k >>= 1;
            }

            return result;
        }


        public bool TryFindY(BigInteger x, byte firstByte, out BigInteger y)
        {
            if (firstByte != 2 && firstByte != 3)
            {
                y = 0;
                return false;
            }
            if (x.Sign < 1)
            {
                y = 0;
                return false;
            }


            // y2 = x3 + ax + b (mod p)
            BigInteger right = (BigInteger.Pow(x, 3) + BigInteger.Multiply(curve.A, x) + curve.B) % curve.P;
            try
            {
                y = SquareRoot.FindSquareRoot(right, curve.P);
            }
            catch (ArithmeticException)
            {
                y = 0;
                return false;
            }

            if (firstByte == 2 && !y.IsEven)
            {
                y = PointNegChecked(new EllipticCurvePoint(x, y)).Y;
                return true;
            }
            else if (firstByte == 3 && y.IsEven)
            {
                y = PointNegChecked(new EllipticCurvePoint(x, y)).Y;
                return true;
            }
            else
            {
                return true;
            }
        }


        private BigInteger CalculateE(byte[] data)
        {
            if (curve.SizeInBits >= (8 * data.Length))
            {
                return data.ToBigInt(true, true);
            }
            else
            {
                // TODO: select leftmost log(n,2) *bits* of data instead of bytes.
                // this should never happen (for bitcoin) since hashlen is equal to or smaller than log(n,2)
                return data.SubArray(0, curve.SizeInBits / 8).ToBigInt(true, true);
            }
        }

        internal bool TryRecoverPublicKeys(Signature sig, byte[] hashedData, out EllipticCurvePoint[] results)
        {
            List<EllipticCurvePoint> temp = new List<EllipticCurvePoint>(curve.H * 4);

            for (int j = 0; j <= curve.H; j++)
            {
                BigInteger x = sig.R + (j * curve.N);
                if (!TryFindY(x, 2, out BigInteger y))
                {
                    continue;
                }
                EllipticCurvePoint R = new EllipticCurvePoint(x, y);
                if (!curve.IsOnCurve(R))
                {
                    continue;
                }

                BigInteger e = CalculateE(hashedData);
                for (int k = 1; k <= 2; k++)
                {
                    // Q = r^−1(sR − eG).
                    EllipticCurvePoint Q =
                        Multiply(
                                sig.R.ModInverse(curve.N),
                                AddChecked(
                                            MultiplyChecked(sig.S, R),
                                            PointNegChecked(MultiplyChecked(e, curve.G))
                                            )
                                 );

                    if (curve.IsOnCurve(Q))
                    {
                        if (!temp.Contains(Q))
                        {
                            // TODO: we are missing step 1.6.2 (verify if this pubkey + signature is valid)
                            temp.Add(Q);
                        }
                    }

                    R = PointNegChecked(R);
                }
            }

            results = temp.ToArray();
            return results.Length != 0;
        }

    }
}
