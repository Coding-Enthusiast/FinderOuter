// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using Autarkysoft.Bitcoin.Cryptography;
using Autarkysoft.Bitcoin.Cryptography.Asymmetric.KeyPairs;
using Autarkysoft.Bitcoin.Cryptography.EllipticCurve;
using System;
using System.Diagnostics;
using System.Linq;
using System.Text;

namespace FinderOuter.Backend.ECC
{
    /// <summary>
    /// All implementations in this namespace are done with the help of https://github.com/bitcoin-core/secp256k1 
    /// </summary>
    public class Calc
    {
        public Calc()
        {
            // TODO: add more/different contexts here to be selected in ctor using an enum
            ECMultGenContext();
        }

        internal PointStorage[,] prec; /* prec[j][i] = 16^j * i * G + U_i */

        public static readonly Point G = new(
            0x16F81798U, 0x59F2815BU, 0x2DCE28D9U, 0x029BFCDBU, 0xCE870B07U, 0x55A06295U, 0xF9DCBBACU, 0x79BE667EU,
            0xFB10D4B8U, 0x9C47D08FU, 0xA6855419U, 0xFD17B448U, 0x0E1108A8U, 0x5DA4FBFCU, 0x26A3C465U, 0x483ADA77U);

        public const uint CurveB = 7;

        public void ECMultGenContext()
        {
            Span<Point> prec = stackalloc Point[1024];

            this.prec = new PointStorage[64, 16];
            PointJacobian gJ = G.ToPointJacobian();
            /* Construct a group element with no known corresponding scalar (nothing up my sleeve). */
            byte[] ba = Encoding.UTF8.GetBytes("The scalar for this x is unknown");
            Debug.Assert(ba.Length == 32);
            UInt256_10x26 x = new(ba, out bool b);
            Debug.Assert(b);

            b = Point.TryCreateVar(x, false, out Point nums_ge);
            Debug.Assert(b);

            PointJacobian numsGJ = nums_ge.ToPointJacobian();
            /* Add G to make the bits in x uniformly distributed. */
            numsGJ = numsGJ.AddVar(G, out _);


            /* compute prec. */
            Span<PointJacobian> preJ = stackalloc PointJacobian[1024]; /* Jacobian versions of prec. */
            PointJacobian gBase = gJ;
            PointJacobian numsBase = numsGJ;
            for (int j = 0; j < 64; j++)
            {
                /* Set precj[j*16 .. j*16+15] to (numsbase, numsbase + gbase, ..., numsbase + 15*gbase). */
                preJ[j * 16] = numsBase;
                for (int i = 1; i < 16; i++)
                {
                    preJ[j * 16 + i] = preJ[j * 16 + i - 1].AddVar(gBase, out _);
                }
                /* Multiply gbase by 16. */
                for (int i = 0; i < 4; i++)
                {
                    gBase = gBase.DoubleVar(out _);
                }
                /* Multiply numbase by 2. */
                numsBase = numsBase.DoubleVar(out _);
                if (j == 62)
                {
                    /* In the last iteration, numsbase is (1 - 2^j) * nums instead. */
                    numsBase = numsBase.Negate();
                    numsBase = numsBase.AddVar(numsGJ, out _);
                }
            }
            Point.SetAllPointsToJacobianVar(prec, preJ, 1024);

            for (int j = 0; j < 64; j++)
            {
                for (int i = 0; i < 16; i++)
                {
                    this.prec[j, i] = prec[j * 16 + i].ToStorage();
                }
            }
        }


        public PointJacobian MultiplyByG(in Scalar8x32 a)
        {
            PointStorage adds = default;
            PointJacobian result = PointJacobian.Infinity;

            uint[] temp = new uint[] { a.b0, a.b1, a.b2, a.b3, a.b4, a.b5, a.b6, a.b7 };
            for (int j = 0, k = 0; j < 64;)
            {
                uint bit = temp[k] & 0x0000000f;
                for (uint i = 0; i < 16; i++)
                {
                    adds = PointStorage.CMov(adds, prec[j, i], i == bit ? 1U : 0);
                }
                result = result.AddVar(adds.ToPoint(), out _);
                j++;

                bit = (temp[k] & 0x000000f0) >> 4;
                for (uint i = 0; i < 16; i++)
                {
                    adds = PointStorage.CMov(adds, prec[j, i], i == bit ? 1U : 0);
                }
                result = result.AddVar(adds.ToPoint(), out _);
                j++;

                bit = (temp[k] & 0x00000f00) >> 8;
                for (uint i = 0; i < 16; i++)
                {
                    adds = PointStorage.CMov(adds, prec[j, i], i == bit ? 1U : 0);
                }
                result = result.AddVar(adds.ToPoint(), out _);
                j++;

                bit = (temp[k] & 0x0000f000) >> 12;
                for (uint i = 0; i < 16; i++)
                {
                    adds = PointStorage.CMov(adds, prec[j, i], i == bit ? 1U : 0);
                }
                result = result.AddVar(adds.ToPoint(), out _);
                j++;

                bit = (temp[k] & 0x000f0000) >> 16;
                for (uint i = 0; i < 16; i++)
                {
                    adds = PointStorage.CMov(adds, prec[j, i], i == bit ? 1U : 0);
                }
                result = result.AddVar(adds.ToPoint(), out _);
                j++;

                bit = (temp[k] & 0x00f00000) >> 20;
                for (uint i = 0; i < 16; i++)
                {
                    adds = PointStorage.CMov(adds, prec[j, i], i == bit ? 1U : 0);
                }
                result = result.AddVar(adds.ToPoint(), out _);
                j++;

                bit = (temp[k] & 0x0f000000) >> 24;
                for (uint i = 0; i < 16; i++)
                {
                    adds = PointStorage.CMov(adds, prec[j, i], i == bit ? 1U : 0);
                }
                result = result.AddVar(adds.ToPoint(), out _);
                j++;

                bit = (temp[k] & 0xf0000000) >> 28;
                for (uint i = 0; i < 16; i++)
                {
                    adds = PointStorage.CMov(adds, prec[j, i], i == bit ? 1U : 0);
                }
                result = result.AddVar(adds.ToPoint(), out _);
                j++;

                k++;
            }

            return result;
        }



        public Span<byte> GetPubkey(in Scalar8x32 priv, bool compressed)
        {
            PointJacobian pubJ = MultiplyByG(priv);
            Point pub = pubJ.ToPoint();
            return pub.ToByteArray(compressed);
        }

        public void GetPubkey(in Scalar8x32 priv, out Span<byte> comp, out Span<byte> uncomp)
        {
            PointJacobian pubJ = MultiplyByG(priv);
            Point pub = pubJ.ToPoint();

            UInt256_10x26 xNorm = pub.x.NormalizeVar();
            UInt256_10x26 yNorm = pub.y.NormalizeVar();

            byte firstByte = yNorm.IsOdd ? (byte)3 : (byte)2;

            uncomp = new byte[65];
            uncomp[0] = 4;
            xNorm.WriteToSpan(uncomp[1..]);
            yNorm.WriteToSpan(uncomp[33..]);

            comp = new byte[33];
            comp[0] = firstByte;
            uncomp.Slice(1, 32).CopyTo(comp[1..]);
        }



        // This is not actually a test but a simple way of quickly checking and debugging stuff until we add actual tests
        public void Test()
        {
            using SharpRandom rng = new();
            byte[] data = new byte[32];
            rng.GetBytes(data);

            Scalar8x32 sec = new(data, out bool overflow);
            Debug.Assert(!overflow);
            PointJacobian pj = MultiplyByG(sec);
            Point p = pj.ToPoint();

            Span<byte> final = p.ToByteArray(false);

            string actual = final.ToArray().ToBase16();

            using PrivateKey key = new(data.ToArray());
            string expected = key.ToPublicKey().ToByteArray(false).ToBase16();

            Debug.Assert(actual == expected);
        }
    }
}
