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
    public class Calc2
    {
        public Calc2()
        {
            // TODO: add more/different contexts here to be selected in ctor using an enum
            ECMultGenContext();
        }

        private const int bits = 8;
        /// <summary>
        /// 256
        /// </summary>
        private const int g = 1 << bits;
        /// <summary>
        /// 32
        /// </summary>
        private const int n = 256 / bits; // 32

        internal PointStorage2[,] prec; /* prec[j][i] = 16^j * i * G + U_i */

        public static readonly Point2 G = new(
            0x16F81798U, 0x59F2815BU, 0x2DCE28D9U, 0x029BFCDBU, 0xCE870B07U, 0x55A06295U, 0xF9DCBBACU, 0x79BE667EU,
            0xFB10D4B8U, 0x9C47D08FU, 0xA6855419U, 0xFD17B448U, 0x0E1108A8U, 0x5DA4FBFCU, 0x26A3C465U, 0x483ADA77U);

        public const uint CurveB = 7;

        public void ECMultGenContext()
        {
            Span<Point2> prec = new Point2[n * g];

            this.prec = new PointStorage2[n, g];
            PointJacobian2 gJ = G.ToPointJacobian();
            /* Construct a group element with no known corresponding scalar (nothing up my sleeve). */
            byte[] ba = "The scalar for this x is unknown".ToCharArray().Select(b => (byte)b).ToArray();
            Debug.Assert(ba.Length == 32);
            UInt256_5x52 x = new(ba, out bool b);
            Debug.Assert(b);

            b = Point2.TryCreateXOVariable(x, false, out Point2 nums_ge);
            Debug.Assert(b);

            PointJacobian2 numsGJ = nums_ge.ToPointJacobian();
            /* Add G to make the bits in x uniformly distributed. */
            numsGJ = numsGJ.AddVariable(G, out _);


            /* compute prec. */
            Span<PointJacobian2> preJ = new PointJacobian2[n * g]; /* Jacobian versions of prec. */
            PointJacobian2 gBase = gJ;
            PointJacobian2 numsBase = numsGJ;
            for (int j = 0; j < n; j++)
            {
                preJ[j * g] = numsBase;
                for (int i = 1; i < g; i++)
                {
                    preJ[j * g + i] = preJ[j * g + i - 1].AddVariable(gBase, out _);
                }

                for (int i = 0; i < bits; i++)
                {
                    gBase = gBase.DoubleVariable();
                }

                numsBase = numsBase.DoubleVariable();
                if (j == n - 2)
                {
                    /* In the last iteration, numsbase is (1 - 2^j) * nums instead. */
                    numsBase = numsBase.Negate();
                    numsBase = numsBase.AddVariable(numsGJ, out _);
                }
            }
            Point2.SetAllGroupElementJacobianVariable(prec, preJ, n * g);

            for (int j = 0; j < n; j++)
            {
                for (int i = 0; i < g; i++)
                {
                    this.prec[j, i] = prec[j * g + i].ToStorage();
                }
            }
        }


        public PointJacobian2 MultiplyByG(in Scalar2 a)
        {
            PointStorage2 adds = default;
            PointJacobian2 result = default;
            for (int i = 0; i < n; i++)
            {
                ulong bit = a.GetBits(i * bits, bits);
                for (uint j = 0; j < g; j++)
                {
                    PointStorage2.CMov(ref adds, prec[i, j], j == bit ? 1 : 0);
                }
                Point2 add = adds.ToPoint();
                result += add;
            }

            return result;
        }



        public Span<byte> GetPubkey(in Scalar2 priv, bool compressed)
        {
            PointJacobian2 pubJ = MultiplyByG(priv);
            Point2 pub = pubJ.ToPoint();
            return pub.ToByteArray(compressed);
        }

        public void GetPubkey(in Scalar2 priv, out Span<byte> comp, out Span<byte> uncomp)
        {
            PointJacobian2 pubJ = MultiplyByG(priv);
            Point2 pub = pubJ.ToPoint();

            uncomp = pub.ToByteArray(out byte firstByte);

            comp = new byte[33];
            comp[0] = firstByte;
            uncomp.Slice(1, 32).CopyTo(comp[1..]);
        }



        // This is not actually a test but a simple way of quickly checking and debugging stuff until we add actual tests
        public bool Test()
        {
            using SharpRandom rng = new();
            byte[] data = new byte[32];
            rng.GetBytes(data);
            Scalar2 sec = new(data, out int overflow);
            Debug.Assert(overflow == 0);
            PointJacobian2 pj = MultiplyByG(sec);
            Point2 p = pj.ToPoint();

            Span<byte> final = p.ToByteArray(false);

            string actual = final.ToArray().ToBase16();

            using PrivateKey key = new(data.ToArray());
            string expected = key.ToPublicKey().ToByteArray(false).ToBase16();

            Debug.Assert(actual == expected);
            return actual == expected;
        }
    }
}
