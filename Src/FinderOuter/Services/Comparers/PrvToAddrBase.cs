// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.Cryptography.EllipticCurve;

namespace FinderOuter.Services.Comparers
{
    public abstract class PrvToAddrBase : ICompareService
    {
        protected byte[] hash;

        public virtual bool Init(string address)
        {
            IsInitialized = AddressService.CheckAndGetHash(address, out hash);
            return IsInitialized;
        }

        public abstract ICompareService Clone();

        public string CompareType => "Address";
        public bool IsInitialized { get; protected set; }
        protected readonly Calc _calc = new();
        public Calc Calc => _calc;

        public abstract unsafe bool Compare(uint* hPt);
        public abstract unsafe bool Compare(ulong* hPt);
        public abstract bool Compare(in PointJacobian point);

        public bool Compare(byte[] key)
        {
            Scalar8x32 k = new(key, out bool overflow);
            if (overflow)
            {
                return false;
            }
            PointJacobian pt = _calc.MultiplyByG(k);
            return Compare(pt);
        }

        public bool Compare(in Scalar8x32 key) => Compare(Calc.MultiplyByG(key));
    }
}
