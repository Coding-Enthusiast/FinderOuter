// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend.ECC;

namespace FinderOuter.Services.Comparers
{
    public class DefaultComparer : ICompareService
    {
        public bool Init(string data) => true;
        public ICompareService Clone() => this;

        private readonly Calc _calc = new();
        public Calc Calc => _calc;

        public unsafe bool Compare(uint* hPt) => true;
        public unsafe bool Compare(ulong* hPt) => true;
        public bool Compare(in PointJacobian point) => true;
        public bool Compare(byte[] key) => true;
        public bool Compare(Scalar key) => true;
    }
}
