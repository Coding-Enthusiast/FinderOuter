// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.Cryptography.Asymmetric.EllipticCurve;
using Autarkysoft.Bitcoin.Cryptography.Asymmetric.KeyPairs;
using FinderOuter.Backend;
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
                using PrivateKey temp = new PrivateKey(data);
                expected = temp.ToBytes();
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

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

        public bool Compare(in EllipticCurvePoint point) => throw new NotImplementedException();
    }
}
