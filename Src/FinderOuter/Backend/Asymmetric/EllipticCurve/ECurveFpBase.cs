// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System.Numerics;

namespace FinderOuter.Backend.Cryptography.Asymmetric.EllipticCurve
{
    public abstract class ECurveFpBase : IECurveFp
    {
        public abstract string Name { get; }
        public abstract BigInteger P { get; }
        public abstract BigInteger A { get; }
        public abstract BigInteger B { get; }
        public abstract BigInteger N { get; }
        public abstract EllipticCurvePoint G { get; }
        public abstract short H { get; }
        public virtual byte[] Seed => null;
        public abstract int SizeInBits { get; }
        public abstract int NSizeInBits { get; }
        public abstract int SecurityLevel { get; }


        public bool IsOnCurve(EllipticCurvePoint point)
        {
            if (point == EllipticCurvePoint.InfinityPoint)
            {
                return true;
            }
            // Big*Big is faster than Pow(Big,2). Only true for 2 though.
            BigInteger rem = ((point.Y * point.Y) - BigInteger.Pow(point.X, 3) - (A * point.X) - B) % P;
            return rem == 0;
        }

    }
}
