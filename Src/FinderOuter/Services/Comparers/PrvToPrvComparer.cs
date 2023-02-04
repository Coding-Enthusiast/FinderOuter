// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using Autarkysoft.Bitcoin.Cryptography.EllipticCurve;
using FinderOuter.Backend.Hashing;
using System;

namespace FinderOuter.Services.Comparers
{
    /// <summary>
    /// Compares 2 private key bytes. It is useful for HD keys where user has a single child private key.
    /// </summary>
    public class PrvToPrvComparer : ICompareService
    {
        public string CompareType => "Privatekey";
        public bool IsInitialized { get; private set; }

        private byte[] expectedBytes;
        private Scalar8x32 expectedKey;

        public bool Init(string data)
        {
            try
            {
                using PrivateKey temp = new(data);
                expectedBytes = temp.ToBytes();
                expectedKey = new(expectedBytes, out _);
                IsInitialized = true;
            }
            catch (Exception)
            {
                IsInitialized = false;
            }

            return IsInitialized;
        }

        public ICompareService Clone()
        {
            return new PrvToPrvComparer()
            {
                expectedBytes = this.expectedBytes.CloneByteArray(),
                expectedKey = this.expectedKey
            };
        }

        private readonly Calc _calc = new();
        public Calc Calc => _calc;
        public unsafe bool Compare(uint* hPt) => ((Span<byte>)expectedBytes).SequenceEqual(Sha256Fo.GetBytes(hPt));
        public unsafe bool Compare(ulong* hPt) => ((Span<byte>)expectedBytes).SequenceEqual(Sha512Fo.GetFirst32Bytes(hPt));

        public bool Compare(byte[] key) => ((ReadOnlySpan<byte>)expectedBytes).SequenceEqual(key);

        public bool Compare(in Scalar8x32 key) => key == expectedKey;

        public bool Compare(in PointJacobian point) => throw new NotImplementedException();
    }
}
