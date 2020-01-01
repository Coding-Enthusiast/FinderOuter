// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend.Cryptography.Hashing;
using System;

namespace FinderOuter.Backend.Cryptography.KeyDerivationFunctions
{
    /// <summary>
    /// PKCS #5: Password-Based Cryptography Specification Version 2.1
    /// <para/> https://tools.ietf.org/html/rfc8018
    /// </summary>
    public class PBKDF2 : IDisposable
    {
        /// <summary>
        /// Initializes a new instance of <see cref="PBKDF2"/> with the given parameters.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <param name="iteration">
        /// Iteration (c)
        /// <para/>* RFC-8018 recommends 1,000 as minimum and 10,000,000 for non-performance critical cases
        /// </param>
        /// <param name="hmac">HMAC-SHA function (PRF)</param>
        public PBKDF2(int iteration, IHmacFunction hmac)
        {
            if (iteration <= 0)
                throw new ArgumentOutOfRangeException(nameof(iteration), "Iteration can not be negative or zero!");
            if (hmac == null)
                throw new ArgumentNullException(nameof(hmac), "HMAC function can not be null.");


            this.iteration = iteration;
            hmacFunc = hmac;
        }



        private readonly int iteration;
        private IHmacFunction hmacFunc;



        /// <summary>
        /// Returns the pseudo-random key based on given password and salt.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="ArgumentOutOfRangeException"/>
        /// <exception cref="ObjectDisposedException"/>
        /// <param name="password">Password (P)</param>
        /// <param name="salt">
        /// Salt (S)
        /// <para/>* RFC-8018 recommends salt to be at least 8 bytes unless MD2, MD5 or SHA1 is used as hash function
        /// </param>
        /// <param name="dkLen">Length of the returned derived key</param>
        /// <returns>A derived key.</returns>
        public unsafe byte[] GetBytes(byte[] password, byte[] salt, int dkLen)
        {
            if (isDisposed)
                throw new ObjectDisposedException($"{nameof(PBKDF2)} instance was disposed");
            if (password == null)
                throw new ArgumentNullException(nameof(password), "Password can not be null.");
            if (salt == null)
                throw new ArgumentNullException(nameof(salt), "Salt can not be null.");
            // Fail if dkLen > (2^32 - 1) * hLen is skipped since dkLen is already limited by size of int
            if (dkLen <= 0)
                throw new ArgumentOutOfRangeException(nameof(dkLen), "Derived key length can not be negative or zero!");


            hmacFunc.Key = password;
            byte[] saltForHmac = new byte[salt.Length + 4];
            Buffer.BlockCopy(salt, 0, saltForHmac, 0, salt.Length);

            byte[] result = new byte[dkLen];

            int blockCount = (int)Math.Ceiling((double)dkLen / hmacFunc.OutputSize);
            int remaining = dkLen;
            int offset = 0;

            fixed (byte* saltPt = &saltForHmac[salt.Length])
            {
                for (int i = 1; i <= blockCount; i++)
                {
                    // F()
                    byte[] resultOfF = new byte[hmacFunc.OutputSize];

                    // Concatinate i after salt
                    saltPt[0] = (byte)(i >> 24);
                    saltPt[1] = (byte)(i >> 16);
                    saltPt[2] = (byte)(i >> 8);
                    saltPt[3] = (byte)i;

                    // compute u1
                    byte[] u1 = hmacFunc.ComputeHash(saltForHmac);

                    Buffer.BlockCopy(u1, 0, resultOfF, 0, u1.Length);

                    // compute u2 to u(c-1) where c is iteration and each u is the hmac of previous u
                    for (int j = 1; j < iteration; j++)
                    {
                        u1 = hmacFunc.ComputeHash(u1);

                        // result of F() is XOR sum of all u arrays
                        int len = u1.Length;
                        fixed (byte* first = resultOfF, second = u1)
                        {
                            byte* fp = first;
                            byte* sp = second;

                            while (len >= 8)//sizeof(ulong)
                            {
                                *(ulong*)fp ^= *(ulong*)sp;
                                fp += 8;
                                sp += 8;
                                len -= 8;
                            }
                            if (len >= 4)
                            {
                                *(uint*)fp ^= *(uint*)sp;
                                fp += 4;
                                sp += 4;
                                len -= 4;
                            }
                            if (len >= 2)
                            {
                                *(ushort*)fp ^= *(ushort*)sp;
                                fp += 2;
                                sp += 2;
                                len -= 2;
                            }
                            if (len >= 1)
                            {
                                *fp ^= *sp;
                            }
                        }
                    }


                    if (remaining >= resultOfF.Length)
                    {
                        Buffer.BlockCopy(resultOfF, 0, result, offset, resultOfF.Length);
                        offset += resultOfF.Length;
                        remaining -= resultOfF.Length;
                    }
                    else
                    {
                        Buffer.BlockCopy(resultOfF, 0, result, offset, remaining);
                    }
                }
            }

            return result;
        }





        #region IDisposable Support
        private bool isDisposed = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!isDisposed)
            {
                if (disposing)
                {
                    if (hmacFunc != null)
                        hmacFunc.Dispose();
                    hmacFunc = null;
                }

                isDisposed = true;
            }
        }


        /// <summary>
        /// Releases all resources used by the current instance of the <see cref="PBKDF2"/> class.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
        }
        #endregion
    }
}
