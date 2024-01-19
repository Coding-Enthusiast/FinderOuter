// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.Cryptography.Asymmetric.EllipticCurve;
using Autarkysoft.Bitcoin.Cryptography.EllipticCurve;
using Autarkysoft.Bitcoin.Encoders;
using System;

namespace FinderOuter.Services.Comparers
{
    /// <summary>
    /// Converts private key to an <see cref="EllipticCurvePoint"/> and compares it with the pubkey (point).
    /// </summary>
    public class PrvToPubComparer : ICompareService
    {
        public string CompareType => "Public key";
        public bool IsInitialized { get; private set; }

        private byte[] pubBa;

        public bool Init(string pubHex)
        {
            IsInitialized = Base16.TryDecode(pubHex, out pubBa) && Point.TryRead(pubBa, out _);
            return IsInitialized;
        }

        public ICompareService Clone()
        {
            return new PrvToPubComparer()
            {
                pubBa = this.pubBa
            };
        }

        protected readonly Calc _calc = new();
        public Calc Calc => _calc;
        public unsafe bool Compare(uint* hPt)
        {
            Scalar8x32 key = new(hPt, out bool overflow);
            if (overflow)
            {
                return false;
            }

            Span<byte> actual = _calc.GetPubkey(key, pubBa.Length == 33);
            return actual.SequenceEqual(pubBa);
        }

        public unsafe bool Compare(ulong* hPt)
        {
            Scalar8x32 key = new(hPt, out bool overflow);
            if (overflow)
            {
                return false;
            }

            Span<byte> actual = _calc.GetPubkey(key, pubBa.Length == 33);
            return actual.SequenceEqual(pubBa);
        }

        public bool Compare(in PointJacobian point)
        {
            ReadOnlySpan<byte> actual = point.ToPoint().ToByteArray(pubBa.Length == 33);
            return actual.SequenceEqual(pubBa);
        }


        public bool Compare(byte[] key)
        {
            Scalar8x32 sc = new(key, out bool overflow);
            if (overflow)
            {
                return false;
            }

            Span<byte> actual = _calc.GetPubkey(sc, pubBa.Length == 33);
            return actual.SequenceEqual(pubBa);
        }

        public bool Compare(in Scalar8x32 key) => Compare(Calc.MultiplyByG(key));
    }
}
