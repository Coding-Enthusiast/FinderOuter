// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend.Cryptography.Asymmetric.EllipticCurve;
using System;

namespace FinderOuter.Backend.KeyPairs
{
    public class PublicKey
    {
        public PublicKey()
        {
            addrMaker = new Address();
            IECurveFp curve = new SecP256k1();
            calc = new EllipticCurveCalculator(curve);
            byteSize = (int)Math.Ceiling((double)curve.SizeInBits / 8);
        }



        private readonly Address addrMaker;
        private EllipticCurvePoint pubKeyPoint;
        private readonly EllipticCurveCalculator calc;
        private readonly int byteSize;



        public void Initialize(EllipticCurvePoint point)
        {
            calc.CheckOnCurve(point);
            pubKeyPoint = point;
        }



        public byte[] ToByteArray(bool compressed)
        {
            byte[] xBytes = pubKeyPoint.X.ToByteArrayExt(true, true);
            if (compressed)
            {
                // we use the following method to avoid cases when numbers are smaller than 32 bytes (see tests for more info).
                byte[] result = new byte[byteSize + 1];
                result[0] = pubKeyPoint.Y.IsEven ? (byte)2 : (byte)3;
                Buffer.BlockCopy(xBytes, 0, result, 1 + byteSize - xBytes.Length, xBytes.Length);

                // TODO: make 32 and 33 into fields and calculate them based on curve instead of being a constant.
                return result;
            }
            else
            {
                byte[] result = new byte[byteSize + byteSize + 1];
                result[0] = 4;
                byte[] yBytes = pubKeyPoint.Y.ToByteArrayExt(true, true);
                Buffer.BlockCopy(xBytes, 0, result, 1 + byteSize - xBytes.Length, xBytes.Length);
                Buffer.BlockCopy(yBytes, 0, result, 1 + byteSize + byteSize - yBytes.Length, yBytes.Length);

                return result;
            }
        }

        public string ToHex(bool compressed)
        {
            return ToByteArray(compressed).ToBase16();
        }


        public EllipticCurvePoint ToPoint()
        {
            return pubKeyPoint;
        }


        public string ToAddress(PubkeyScriptType addrType, NetworkType netType, bool compressed)
        {
            return addrMaker.GetAddress(this, addrType, netType, compressed);
        }




        public override string ToString()
        {
            return $"<{pubKeyPoint.X}><{pubKeyPoint.Y}>";
        }



        public override bool Equals(object obj)
        {
            if (obj == null || GetType() != obj.GetType())
            {
                return false;
            }

            return ((PublicKey)obj).pubKeyPoint.Equals(pubKeyPoint);
        }

        public override int GetHashCode()
        {
            return pubKeyPoint.GetHashCode();
        }

    }
}
