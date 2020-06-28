// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.Cryptography.Asymmetric.EllipticCurve;
using FinderOuter.Backend.Cryptography.Hashing;
using System;
using System.Numerics;

namespace FinderOuter.Services.Comparers
{
    public abstract class PrvToAddrBase : ICompareService, IDisposable
    {
        public PrvToAddrBase(bool acceptP2shP2wpkh)
        {
            accept3 = acceptP2shP2wpkh;
        }

        protected readonly bool accept3;
        protected readonly BigInteger order = new SecP256k1().N;
        protected readonly EllipticCurveCalculator calc = new EllipticCurveCalculator();
        protected byte[] hash;
        protected readonly Hash160 hash160 = new Hash160();

        public bool Init(string address)
        {
            AddressService serv = new AddressService();
            return serv.CheckAndGetHash(address, accept3, out hash);
        }

        public abstract bool Compare(byte[] key);

        public void Dispose() => hash160.Dispose();
    }
}
