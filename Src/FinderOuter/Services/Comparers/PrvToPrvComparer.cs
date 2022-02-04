// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using Autarkysoft.Bitcoin.Cryptography.Asymmetric.EllipticCurve;
using Autarkysoft.Bitcoin.Cryptography.Asymmetric.KeyPairs;
using FinderOuter.Backend;
using FinderOuter.Backend.Cryptography.Hashing;
using FinderOuter.Backend.ECC;
using System;
using System.Numerics;

namespace FinderOuter.Services.Comparers
{
    /// <summary>
    /// Compares 2 private key bytes. It is useful for HD keys where user has a single child private key.
    /// </summary>
    public class PrvToPrvComparer : ICompareService
    {
        private byte[] expected;

        public bool Init(string data)
        {
            try
            {
                using PrivateKey temp = new(data);
                expected = temp.ToBytes();
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public ICompareService Clone()
        {
            return new PrvToPrvComparer()
            {
                expected = this.expected.CloneByteArray()
            };
        }

        private readonly Calc calc2 = new();
        public Calc Calc => calc2;
        public unsafe bool Compare(uint* hPt) => ((Span<byte>)expected).SequenceEqual(Sha256Fo.GetBytes(hPt));
        public unsafe bool Compare(ulong* hPt) => ((Span<byte>)expected).SequenceEqual(Sha512Fo.GetFirst32Bytes(hPt));

        public bool Compare(byte[] key) => ((ReadOnlySpan<byte>)expected).SequenceEqual(key);

        public bool Compare(BigInteger key)
        {
            byte[] ba = key.ToByteArray(true, true);
            if (ba.Length < 32)
            {
                return (Compare(ba.PadLeft(32)));
            }
            else if (ba.Length == 32)
            {
                return Compare(ba);
            }
            else
            {
                return false;
            }
        }

        public bool Compare(in PointJacobian point) => throw new NotImplementedException();
        public bool Compare(in EllipticCurvePoint point) => throw new NotImplementedException();
    }
}
