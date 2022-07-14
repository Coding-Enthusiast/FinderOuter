// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System.Diagnostics;

namespace FinderOuter.Backend.ECC
{
    /// <summary>
    /// Elliptic curve Point2 in Jacobian coordinates
    /// </summary>
    public readonly struct PointJacobian2
    {
        public PointJacobian2(in UInt256_5x52 x26, in UInt256_5x52 y26, in UInt256_5x52 z26)
        {
            x = x26;
            y = y26;
            z = z26;
        }


        public readonly UInt256_5x52 x, y, z;


        public bool IsInfinity => x.IsZero && y.IsZero;

        static readonly PointJacobian2 _infinity = new(UInt256_5x52.Zero, UInt256_5x52.Zero, UInt256_5x52.Zero);
        public static ref readonly PointJacobian2 Infinity => ref _infinity;


        public readonly Point2 ToPoint()
        {
            UInt256_5x52 az = z.Inverse();
            UInt256_5x52 z2 = az.Sqr();
            UInt256_5x52 z3 = az * z2;
            UInt256_5x52 ax = x * z2;
            UInt256_5x52 ay = y * z3;
            return new Point2(ax, ay);
        }

        public readonly PointJacobian2 Negate()
        {
            return new PointJacobian2(x, y.NormalizeWeak().Negate(1), z);
        }

        public readonly Point2 ToPointZInv(in UInt256_5x52 zi)
        {
            ref readonly PointJacobian2 a = ref this;
            UInt256_5x52 zi2 = zi.Sqr();
            UInt256_5x52 zi3 = zi2 * zi;
            UInt256_5x52 rx = a.x * zi2;
            UInt256_5x52 ry = a.y * zi3;
            return new Point2(rx, ry);
        }

        public readonly PointJacobian2 DoubleVariable() => IsInfinity ? Infinity : Double();

        public readonly PointJacobian2 DoubleVariable(out UInt256_5x52 rzr)
        {
            /* For secp256k1, 2Q is infinity if and only if Q is infinity. This is because if 2Q = infinity,
            *  Q must equal -Q, or that Q.y == -(Q.y), or Q.y is 0. For a Point2 on y^2 = x^3 + 7 to have
            *  y=0, x^3 must be -7 mod p. However, -7 has no cube root mod p.
            *
            *  Having said this, if this function receives a Point2 on a sextic twist, e.g. by
            *  a fault attack, it is possible for y to be 0. This happens for y^2 = x^3 + 6,
            *  since -6 does have a cube root mod p. For this Point2, this function will not set
            *  the infinity flag even though the Point2 doubles to infinity, and the result
            *  Point2 will be gibberish (z = 0 but infinity = 0).
            */
            if (IsInfinity)
            {
                rzr = new UInt256_5x52(1);
                return Infinity;
            }

            rzr = y;
            rzr = rzr.NormalizeWeak();
            rzr = rzr.Multiply(2U);

            return Double();
        }

        public readonly PointJacobian2 Double()
        {
            /* Operations: 3 mul, 4 sqr, 0 normalize, 12 mul_int/add/negate.
             *
             * Note that there is an implementation described at
             *     https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
             * which trades a multiply for a square, but in practice this is actually slower,
             * mainly because it requires more normalizations.
             */
            UInt256_5x52 rx, ry, rz;
            UInt256_5x52 t1, t2, t3, t4;

            rz = z * y;
            rz *= 2U;            /* Z' = 2*Y*Z (2) */
            t1 = x.Sqr();
            t1 *= 3U;            /* T1 = 3*X^2 (3) */
            t2 = t1.Sqr();       /* T2 = 9*X^4 (1) */
            t3 = y.Sqr();
            t3 *= 2U;            /* T3 = 2*Y^2 (2) */
            t4 = t3.Sqr();
            t4 *= 2U;            /* T4 = 8*Y^4 (2) */
            t3 = t3 * x;         /* T3 = 2*X*Y^2 (1) */
            rx = t3;
            rx *= 4U;            /* X' = 8*X*Y^2 (4) */
            rx = rx.Negate(4);   /* X' = -8*X*Y^2 (5) */
            rx += t2;            /* X' = 9*X^4 - 8*X*Y^2 (6) */
            t2 = t2.Negate(1);   /* T2 = -9*X^4 (2) */
            t3 *= 6U;            /* T3 = 12*X*Y^2 (6) */
            t3 += t2;            /* T3 = 12*X*Y^2 - 9*X^4 (8) */
            ry = t1 * t3;        /* Y' = 36*X^3*Y^2 - 27*X^6 (1) */
            t2 = t4.Negate(2);   /* T2 = -8*Y^4 (3) */
            ry += t2;            /* Y' = 36*X^3*Y^2 - 27*X^6 - 8*Y^4 (4) */

            return new PointJacobian2(rx, ry, rz);
        }


        public readonly PointJacobian2 AddVariable(in Point2 b) => AddVariable(b, out _);

        public readonly PointJacobian2 AddVariable(in Point2 b, out UInt256_5x52 rzr)
        {
            /* 8 mul, 3 sqr, 4 normalize, 12 mul_int/add/negate */
            UInt256_5x52 z12, u1, u2, s1, s2, h, i, i2, h2, h3, t;
            if (IsInfinity)
            {
                rzr = default;
                return b.ToPointJacobian();
            }
            if (b.IsInfinity)
            {
                rzr = new UInt256_5x52(1U);
                return this;
            }

            z12 = z.Sqr();
            u1 = x;
            u1 = u1.NormalizeWeak();
            u2 = b.x * z12;
            s1 = y;
            s1 = s1.NormalizeWeak();
            s2 = b.y * z12;
            s2 = s2 * z;
            h = u1.Negate(1);
            h += u2;
            i = s1.Negate(1);
            i += s2;
            if (h.NormalizeToZeroVar())
            {
                if (i.NormalizeToZeroVar())
                {
                    return DoubleVariable(out rzr);
                }
                else
                {
                    rzr = new UInt256_5x52(0);
                    return Infinity;
                }
            }
            i2 = i.Sqr();
            h2 = h.Sqr();
            h3 = h * h2;
            rzr = h;
            UInt256_5x52 rz = z * h;
            t = u1 * h2;
            UInt256_5x52 rx = t;
            rx *= 2U;
            rx += h3;
            rx = rx.Negate(3);
            rx += i2;
            UInt256_5x52 ry = rx.Negate(5);
            ry += t;
            ry = ry * i;
            h3 = h3 * s1;
            h3 = h3.Negate(1);
            ry += h3;

            return new PointJacobian2(rx, ry, rz);
        }


        public readonly PointJacobian2 AddVariable(in PointJacobian2 b) => AddVariable(b, out _);

        public readonly PointJacobian2 AddVariable(in PointJacobian2 b, out UInt256_5x52 rzr)
        {
            /* Operations: 12 mul, 4 sqr, 2 normalize, 12 mul_int/add/negate */
            UInt256_5x52 z22, z12, u1, u2, s1, s2, h, i, i2, h2, h3, t;
            if (IsInfinity)
            {
                rzr = default;
                return b;
            }

            if (b.IsInfinity)
            {
                rzr = new UInt256_5x52(1);
                return this;
            }

            UInt256_5x52 rx, ry, rz;
            z22 = b.z.Sqr();
            z12 = z.Sqr();
            u1 = x * z22;
            u2 = b.x * z12;
            s1 = y * z22;
            s1 = s1 * b.z;
            s2 = b.y * z12;
            s2 = s2 * z;
            h = u1.Negate(1);
            h += u2;
            i = s1.Negate(1);
            i += s2;
            if (h.NormalizeToZeroVar())
            {
                if (i.NormalizeToZeroVar())
                {
                    return DoubleVariable(out rzr);
                }
                else
                {
                    rzr = new UInt256_5x52(0);
                    return Infinity;
                }
            }
            i2 = i.Sqr();
            h2 = h.Sqr();
            h3 = h * h2;
            h = h * b.z;
            rzr = h;
            rz = z * h;
            t = u1 * h2;
            rx = t;
            rx *= 2U;
            rx += h3;
            rx = rx.Negate(3);
            rx += i2;
            ry = rx.Negate(5);
            ry += t;
            ry = ry * i;
            h3 = h3 * s1;
            h3 = h3.Negate(1);
            ry += h3;

            return new PointJacobian2(rx, ry, rz);
        }

        private static readonly UInt256_5x52 fe_1 = new(1, 0, 0, 0, 0, 0, 0, 0);

        public readonly PointJacobian2 Add(in Point2 b)
        {
            UInt256_5x52 rx, ry, rz;
            /* Operations: 7 mul, 5 sqr, 4 normalize, 21 mul_int/add/negate/cmov */
            UInt256_5x52 zz, u1, u2, s1, s2, t, tt, m, n, q, rr;
            UInt256_5x52 m_alt, rr_alt;
            int degenerate;
            Debug.Assert(!b.IsInfinity);

            /* In:
			 *    Eric Brier and Marc Joye, Weierstrass Elliptic Curves and Side-Channel Attacks.
			 *    In D. Naccache and P. Paillier, Eds., Public Key Cryptography, vol. 2274 of Lecture Notes in Computer Science, pages 335-345. Springer-Verlag, 2002.
			 *  we find as solution for a unified addition/doubling formula:
			 *    lambda = ((x1 + x2)^2 - x1 * x2 + a) / (y1 + y2), with a = 0 for secp256k1's curve equation.
			 *    x3 = lambda^2 - (x1 + x2)
			 *    2*y3 = lambda * (x1 + x2 - 2 * x3) - (y1 + y2).
			 *
			 *  Substituting x_i = Xi / Zi^2 and yi = Yi / Zi^3, for i=1,2,3, gives:
			 *    U1 = X1*Z2^2, U2 = X2*Z1^2
			 *    S1 = Y1*Z2^3, S2 = Y2*Z1^3
			 *    Z = Z1*Z2
			 *    T = U1+U2
			 *    M = S1+S2
			 *    Q = T*M^2
			 *    R = T^2-U1*U2
			 *    X3 = 4*(R^2-Q)
			 *    Y3 = 4*(R*(3*Q-2*R^2)-M^4)
			 *    Z3 = 2*M*Z
			 *  (Note that the paper uses xi = Xi / Zi and yi = Yi / Zi instead.)
			 *
			 *  This formula has the benefit of being the same for both addition
			 *  of distinct Point2s and doubling. However, it breaks down in the
			 *  case that either Point2 is infinity, or that y1 = -y2. We handle
			 *  these cases in the following ways:
			 *
			 *    - If b is infinity we simply bail by means of a VERIFY_CHECK.
			 *
			 *    - If a is infinity, we detect this, and at the end of the
			 *      computation replace the result (which will be meaningless,
			 *      but we compute to be constant-time) with b.x : b.y : 1.
			 *
			 *    - If a = -b, we have y1 = -y2, which is a degenerate case.
			 *      But here the answer is infinity, so we simply set the
			 *      infinity flag of the result, overriding the computed values
			 *      without even needing to cmov.
			 *
			 *    - If y1 = -y2 but x1 != x2, which does occur thanks to certain
			 *      properties of our curve (specifically, 1 has nontrivial cube
			 *      roots in our field, and the curve equation has no x coefficient)
			 *      then the answer is not infinity but also not given by the above
			 *      equation. In this case, we cmov in place an alternate expression
			 *      for lambda. Specifically (y1 - y2)/(x1 - x2). Where both these
			 *      expressions for lambda are defined, they are equal, and can be
			 *      obtained from each other by multiplication by (y1 + y2)/(y1 + y2)
			 *      then substitution of x^3 + 7 for y^2 (using the curve equation).
			 *      For all pairs of nonzero Point2s (a, b) at least one is defined,
			 *      so this covers everything.
			 */

            zz = z.Sqr();                   /* z = Z1^2 */
            u1 = x;
            u1 = u1.NormalizeWeak();        /* u1 = U1 = X1*Z2^2 (1) */
            u2 = b.x * zz;                  /* u2 = U2 = X2*Z1^2 (1) */
            s1 = y;
            s1 = s1.NormalizeWeak();        /* s1 = S1 = Y1*Z2^3 (1) */
            s2 = b.y * zz;                  /* s2 = Y2*Z1^2 (1) */
            s2 = s2 * z;                    /* s2 = S2 = Y2*Z1^3 (1) */
            t = u1; t += u2;                /* t = T = U1+U2 (2) */
            m = s1; m += s2;                /* m = M = S1+S2 (2) */
            rr = t.Sqr();                   /* rr = T^2 (1) */
            m_alt = u2.Negate(1);           /* Malt = -X2*Z1^2 */
            tt = u1 * m_alt;                /* tt = -U1*U2 (2) */
            rr += tt;                       /* rr = R = T^2-U1*U2 (3) */
            /* If lambda = R/M = 0/0 we have a problem (except in the "trivial"
			 *  case that Z = z1z2 = 0, and this is special-cased later on). */
            degenerate = (m.NormalizesToZero() ? 1 : 0) & (rr.NormalizesToZero() ? 1 : 0);
            /* This only occurs when y1 == -y2 and x1^3 == x2^3, but x1 != x2.
			 * This means either x1 == beta*x2 or beta*x1 == x2, where beta is
			 * a nontrivial cube root of one. In either case, an alternate
			 * non-indeterminate expression for lambda is (y1 - y2)/(x1 - x2),
			 * so we set R/M equal to this. */
            rr_alt = s1;
            rr_alt *= 2U;         /* rr = Y1*Z2^3 - Y2*Z1^3 (2) */
            m_alt += u1;          /* Malt = X1*Z2^2 - X2*Z1^2 */

            UInt256_5x52.CMov(ref rr_alt, rr, degenerate != 0 ? 0 : 1);
            UInt256_5x52.CMov(ref m_alt, m, degenerate != 0 ? 0 : 1);
            /* Now Ralt / Malt = lambda and is guaranteed not to be 0/0.
			 * From here on out Ralt and Malt represent the numerator
			 * and denominator of lambda; R and M represent the explicit
			 * expressions x1^2 + x2^2 + x1x2 and y1 + y2. */
            n = m_alt.Sqr();                 /* n = Malt^2 (1) */
            q = n * t;                       /* q = Q = T*Malt^2 (1) */
            /* These two lines use the observation that either M == Malt or M == 0,
			 * so M^3 * Malt is either Malt^4 (which is computed by squaring), or
			 * zero (which is "computed" by cmov). So the cost is one squaring
			 * versus two multiplications. */
            n = n.Sqr();
            UInt256_5x52.CMov(ref n, m, degenerate); /* n = M^3 * Malt (2) */
            t = rr_alt.Sqr();                         /* t = Ralt^2 (1) */
            rz = z * m_alt;                           /* rz = Malt*Z (1) */

            rz *= 2U;                                 /* rz = Z3 = 2*Malt*Z (2) */
            q = q.Negate(1);                          /* q = -Q (2) */
            t += q;                                   /* t = Ralt^2-Q (3) */
            t = t.NormalizeWeak();
            rx = t;                                   /* rx = Ralt^2-Q (1) */
            t *= 2U;                                  /* t = 2*x3 (2) */
            t += q;                                   /* t = 2*x3 - Q: (4) */
            t = t * rr_alt;                           /* t = Ralt*(2*x3 - Q) (1) */
            t += n;                                   /* t = Ralt*(2*x3 - Q) + M^3*Malt (3) */
            ry = t.Negate(3);                         /* ry = Ralt*(Q - 2x3) - M^3*Malt (4) */
            ry = ry.NormalizeWeak();
            rx *= 4U;                                 /* rx = X3 = 4*(Ralt^2-Q) */
            ry *= 4U;                                 /* ry = Y3 = 4*Ralt*(Q - 2x3) - 4*M^3*Malt (4) */

            /* In case a.infinity == 1, replace r with (b.x, b.y, 1). */
            UInt256_5x52.CMov(ref rx, b.x, IsInfinity ? 1 : 0);
            UInt256_5x52.CMov(ref ry, b.y, IsInfinity ? 1 : 0);
            UInt256_5x52.CMov(ref rz, fe_1, IsInfinity ? 1 : 0);

            return new PointJacobian2(rx, ry, rz);
        }

        public static PointJacobian2 operator +(in PointJacobian2 a, in Point2 b) => a.Add(b);
    }
}
