// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.Cryptography.Asymmetric.EllipticCurve;
using FinderOuter.Backend.Cryptography.Hashing;
using FinderOuter.Backend.ECC;
using System;
using System.Numerics;

namespace FinderOuter.Services.Comparers
{
    public abstract class PrvToAddrBase : ICompareService, IDisposable
    {
        protected readonly BigInteger order = new SecP256k1().N;
        protected readonly EllipticCurveCalculator calc = new();
        protected readonly Calc calc2 = new();
        protected byte[] hash;
        protected readonly Hash160 hash160 = new();

        public virtual bool Init(string address)
        {
            var serv = new AddressService();
            return serv.CheckAndGetHash(address, out hash);
        }

        public abstract ICompareService Clone();
        public Calc Calc2 => calc2;

        public abstract unsafe bool Compare(uint* hPt);
        public abstract unsafe bool Compare(ulong* hPt);

        public bool Compare(byte[] key)
        {
            var kVal = new BigInteger(key, true, true);
            if (kVal >= order || kVal == 0)
            {
                return false;
            }
            return Compare(kVal);
        }

        public bool Compare(BigInteger key) => Compare(calc.MultiplyByG(key));

        public abstract bool Compare(in EllipticCurvePoint point);

        public void Dispose() => hash160.Dispose();
    }
}
