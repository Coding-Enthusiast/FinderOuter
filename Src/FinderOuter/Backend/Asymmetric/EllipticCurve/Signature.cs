// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend.Encoders;
using System;
using System.Numerics;

namespace FinderOuter.Backend.Cryptography.Asymmetric.EllipticCurve
{
    public class Signature
    {
        /// <summary>
        /// Initializes a new instance of <see cref="Signature"/> using the given parameters.
        /// </summary>
        /// <param name="r">R value</param>
        /// <param name="s">S value</param>
        /// <param name="v">Recovery ID</param>
        public Signature(BigInteger r, BigInteger s, byte? v = null)
        {
            derEnc = new DER();

            R = r;
            S = s;
            RecoveryId = v;
        }


        /// <summary>
        /// Initializes a new instance of <see cref="Signature"/> using the given parameters.
        /// </summary>
        /// <param name="sigBa">Byte array containing the signature</param>
        /// <param name="encoding">Incicates encoding used in the given byte array</param>
        public Signature(byte[] sigBa, SigEncoding encoding)
        {
            derEnc = new DER();

            if (encoding == SigEncoding.Der)
            {
                int offset = 0;
                if (!derEnc.TryDecode2Integers(sigBa, ref offset, true, out _r, out _s, out string error))
                {
                    throw new FormatException(error);
                }
            }
            else if (encoding == SigEncoding.WithRecId)
            {
                if (sigBa.Length != 65)
                {
                    throw new FormatException("Invalid length.");
                }

                RecoveryId = sigBa[0];
                R = sigBa.SubArray(1, 32).ToBigInt(true, true);
                S = sigBa.SubArray(33, 32).ToBigInt(true, true);
            }
            else
            {
                throw new ArgumentException("Encoding is not defined.", nameof(encoding));
            }
        }

        public enum SigEncoding
        {
            Der,
            WithRecId
        }

        private BigInteger _r;
        public BigInteger R { get => _r; set => _r = value; }

        private BigInteger _s;
        public BigInteger S { get => _s; set => _s = value; }

        public byte? RecoveryId { get; set; }

        private readonly DER derEnc;


        public string EncodeWithRecId()
        {
            byte[] result = new byte[65];
            result[0] = RecoveryId ?? 0;
            byte[] rBa = R.ToByteArrayExt(true, true).PadLeft(32);
            byte[] sBa = S.ToByteArrayExt(true, true).PadLeft(32);
            Buffer.BlockCopy(rBa, 0, result, 1, 32);
            Buffer.BlockCopy(sBa, 0, result, 33, 32);

            return result.ToBase64();
        }

    }
}
