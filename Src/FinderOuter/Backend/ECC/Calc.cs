// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using Autarkysoft.Bitcoin.Cryptography;
using Autarkysoft.Bitcoin.Cryptography.Asymmetric.KeyPairs;
using System;
using System.Diagnostics;
using System.Linq;

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
            PointJacobian gJ = G.ToPointJacobian;
            /* Construct a group element with no known corresponding scalar (nothing up my sleeve). */
            byte[] ba = "The scalar for this x is unknown".ToCharArray().Select(b => (byte)b).ToArray();
            Debug.Assert(ba.Length == 32);
            UInt256_10x26 x = new(ba, out bool b);
            Debug.Assert(b);

            b = Point.TryCreateXOVariable(x, false, out Point nums_ge);
            Debug.Assert(b);

            PointJacobian numsGJ = nums_ge.ToPointJacobian;
            /* Add G to make the bits in x uniformly distributed. */
            numsGJ = numsGJ.AddVariable(G, out _);


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
                    preJ[j * 16 + i] = preJ[j * 16 + i - 1].AddVariable(gBase, out _);
                }
                /* Multiply gbase by 16. */
                for (int i = 0; i < 4; i++)
                {
                    gBase = gBase.DoubleVariable();
                }
                /* Multiply numbase by 2. */
                numsBase = numsBase.DoubleVariable();
                if (j == 62)
                {
                    /* In the last iteration, numsbase is (1 - 2^j) * nums instead. */
                    numsBase = numsBase.Negate();
                    numsBase = numsBase.AddVariable(numsGJ, out _);
                }
            }
            Point.SetAllGroupElementJacobianVariable(prec, preJ, 1024);

            for (int j = 0; j < 64; j++)
            {
                for (int i = 0; i < 16; i++)
                {
                    this.prec[j, i] = prec[j * 16 + i].ToStorage();
                }
            }
        }


        public PointJacobian MultiplyByG(in Scalar a)
        {
            PointStorage adds = default;
            PointJacobian result = default;
            for (int j = 0; j < 64; j++)
            {
                uint bits = a.GetBits(j * 4, 4);
                for (int i = 0; i < 16; i++)
                {
                    PointStorage.CMov(ref adds, prec[j, i], i == bits ? 1 : 0);
                }
                Point add = adds.ToPoint();
                result += add;
            }

            return result;
        }



        public Span<byte> GetPubkey(in Scalar priv, bool compressed)
        {
            PointJacobian pubJ = MultiplyByG(priv);
            Point pub = pubJ.ToPoint();
            return pub.ToByteArray(compressed);
        }

        public void GetPubkey(in Scalar priv, out Span<byte> comp, out Span<byte> uncomp)
        {
            PointJacobian pubJ = MultiplyByG(priv);
            Point pub = pubJ.ToPoint();

            uncomp = pub.ToByteArray(out byte firstByte);

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
            Scalar sec = new(data, out int overflow);
            Debug.Assert(overflow == 0);
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
