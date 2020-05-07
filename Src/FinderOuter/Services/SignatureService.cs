// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using Autarkysoft.Bitcoin.Cryptography.Asymmetric.EllipticCurve;
using System;

namespace FinderOuter.Services
{
    // A temporary helper class to make conversions easy until Signature class in Bitcoin.Net is improved in future versions
    public class SignatureService
    {
        public Signature CreateFromRecId(byte[] sigBa)
        {
            if (sigBa.Length != 65)
            {
                throw new FormatException("Invalid length.");
            }

            return new Signature()
            {
                R = sigBa.SubArray(1, 32).ToBigInt(true, true),
                S = sigBa.SubArray(33, 32).ToBigInt(true, true),
                RecoveryId = sigBa[0]
            };
        }

        public string EncodeWithRedId(Signature sig)
        {
            FastStream stream = new FastStream(65);
            sig.RecoveryId -= 27;
            sig.WriteToStreamWithRecId(stream, false);
            return stream.ToByteArray().ToBase64();
        }
    }
}
