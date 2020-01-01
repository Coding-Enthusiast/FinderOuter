// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend.Encoders;
using System.Numerics;

namespace FinderOuter.Backend.Cryptography.Asymmetric.EllipticCurve
{
    public sealed class SecP256k1 : ECurveFpBase
    {
        public override string Name => "secp256k1";
        public override BigInteger P => Base16.ToBigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", true);
        public override BigInteger A => BigInteger.Zero;
        public override BigInteger B => new BigInteger(7);
        public override BigInteger N => Base16.ToBigInt("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", true);
        public override EllipticCurvePoint G => new EllipticCurvePoint(
            Base16.ToBigInt("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", true),
            Base16.ToBigInt("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", true));
        public override short H => 1;
        public override int SizeInBits => 256;
        public override int NSizeInBits => 256;
        public override int SecurityLevel => 128;
    }
}
