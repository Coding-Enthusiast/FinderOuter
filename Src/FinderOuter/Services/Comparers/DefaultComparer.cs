// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.Cryptography.EllipticCurve;

namespace FinderOuter.Services.Comparers
{
    public class DefaultComparer : ICompareService
    {
        public string CompareType => "None";
        public bool IsInitialized => true;
        public bool Init(string data) => true;
        public ICompareService Clone() => this;

        private readonly Calc _calc = new();
        public Calc Calc => _calc;

        public unsafe bool Compare(uint* hPt) => true;
        public unsafe bool Compare(ulong* hPt) => true;
        public bool Compare(in PointJacobian point) => true;
        public bool Compare(byte[] key) => true;
        public bool Compare(in Scalar8x32 key) => true;
    }
}
