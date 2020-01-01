// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System;
using System.Numerics;

namespace FinderOuter.Backend.Cryptography.Arithmetic
{
    /// <summary>
    /// https://en.wikipedia.org/wiki/Legendre_symbol
    /// </summary>
    public static class Legendre
    {
        /// <summary>
        /// Finds Legendre symbol for a given pair of integers (a,p) where p is an odd prime.
        /// </summary>
        /// <param name="n"></param>
        /// <param name="p"></param>
        /// <returns></returns>
        public static int Symbol(BigInteger n, BigInteger p)
        {
            if (p < 2)
            {
                throw new ArgumentOutOfRangeException(nameof(p), $"{nameof(p)} must be >= 2");
            }
            if (n == 0 || n == 1)
            {
                return (int)n;
            }

            int result;
            if (n.IsEven)
            {
                result = Symbol(n / 2, p);
                if (((p * p - 1) & 8) != 0) // instead of dividing by 8, shift the mask bit
                {
                    result = -result;
                }
            }
            else
            {
                result = Symbol(p % n, n);
                if (((n - 1) * (p - 1) & 4) != 0) // instead of dividing by 4, shift the mask bit
                {
                    result = -result;
                }
            }
            return result;
        }

    }
}
