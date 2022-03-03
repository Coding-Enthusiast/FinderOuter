// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.Cryptography.Asymmetric.EllipticCurve;
using FinderOuter.Backend.ECC;
using System.Numerics;

namespace FinderOuter.Services.Comparers
{
    public abstract class PrvToAddrBase : ICompareService
    {
        protected readonly BigInteger order = new SecP256k1().N;
        protected readonly EllipticCurveCalculator calc = new();
        protected readonly Calc calc2 = new();
        protected byte[] hash;

        public virtual bool Init(string address)
        {
            AddressService serv = new();
            return serv.CheckAndGetHash(address, out hash);
        }

        public abstract ICompareService Clone();
        public Calc Calc => calc2;

        public abstract unsafe bool Compare(uint* hPt);
        public abstract unsafe bool Compare(ulong* hPt);
        public abstract bool Compare(in PointJacobian point);

        public bool Compare(byte[] key)
        {
            Scalar k = new(key, out int overflow);
            if (overflow != 0)
            {
                return false;
            }
            PointJacobian pt = calc2.MultiplyByG(k);
            return Compare(pt);
        }

        public bool Compare(BigInteger key) => Compare(calc.MultiplyByG(key));

        public abstract bool Compare(in EllipticCurvePoint point);
    }
}
