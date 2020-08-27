// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.Cryptography.Asymmetric.EllipticCurve;
using Autarkysoft.Bitcoin.Cryptography.Asymmetric.KeyPairs;
using Autarkysoft.Bitcoin.Encoders;
using System;
using System.Numerics;

namespace FinderOuter.Services.Comparers
{
    /// <summary>
    /// Converts private key to an <see cref="EllipticCurvePoint"/> and compares it with the pubkey (point).
    /// </summary>
    public class PrvToPubComparer : ICompareService
    {
        private readonly SecP256k1 curve = new SecP256k1();
        private readonly EllipticCurveCalculator calc = new EllipticCurveCalculator();
        private EllipticCurvePoint point;

        public bool Init(string pubHex)
        {
            try
            {
                byte[] pubBa = Base16.Decode(pubHex);
                if (PublicKey.TryRead(pubBa, out PublicKey pubKey))
                {
                    point = pubKey.ToPoint();
                    return true;
                }
                else
                {
                    return false;
                }
            }
            catch (Exception)
            {
                return false;
            }
        }


        public bool Compare(byte[] key)
        {
            BigInteger kVal = new BigInteger(key, true, true);
            if (kVal >= curve.N || kVal == 0)
            {
                return false;
            }

            EllipticCurvePoint actual = calc.MultiplyByG(kVal);
            return actual == point;
        }

        public bool Compare(BigInteger key) => calc.MultiplyByG(key) == point;

        public bool Compare(in EllipticCurvePoint point) => point == this.point;
    }
}
