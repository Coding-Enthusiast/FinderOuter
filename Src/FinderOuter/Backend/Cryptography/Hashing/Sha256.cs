// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System;
using System.Runtime.CompilerServices;

namespace FinderOuter.Backend.Cryptography.Hashing
{
    /// <summary>
    /// Implementation of 256-bit Secure Hash Algorithm (SHA) base on RFC-6234
    /// <para/> https://tools.ietf.org/html/rfc6234
    /// </summary>
    public class Sha256 : IHashFunction
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Sha256"/>.
        /// </summary>
        /// <param name="isDouble">Determines whether the hash should be performed twice.</param>
        public Sha256(bool isDouble = false)
        {
            IsDouble = isDouble;
        }



        /// <summary>
        /// Indicates whether the hash function should be performed twice on message.
        /// For example Double SHA256 that bitcoin uses.
        /// </summary>
        public bool IsDouble { get; set; }

        /// <summary>
        /// Size of the hash result in bytes (=32 bytes).
        /// </summary>
        public virtual int HashByteSize => 32;

        /// <summary>
        /// Size of the blocks used in each round (=64 bytes).
        /// </summary>
        public int BlockByteSize => 64;


        internal uint[] hashState = new uint[8];
        internal uint[] w = new uint[64];

        private readonly uint[] Ks =
        {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };



        /// <summary>
        /// Computes the hash value for the specified byte array.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="ObjectDisposedException"/>
        /// <param name="data">The byte array to compute hash for</param>
        /// <returns>The computed hash</returns>
        public byte[] ComputeHash(byte[] data)
        {
            if (disposedValue)
                throw new ObjectDisposedException("Instance was disposed.");
            if (data == null)
                throw new ArgumentNullException(nameof(data), "Data can not be null.");

            Init();

            DoHash(data, data.Length);

            return GetBytes();
        }


        /// <summary>
        /// Computes the hash value for the specified region of the specified byte array.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="IndexOutOfRangeException"/>
        /// <exception cref="ObjectDisposedException"/>
        /// <param name="buffer">The byte array to compute hash for</param>
        /// <param name="offset">The offset into the byte array from which to begin using data.</param>
        /// <param name="count">The number of bytes in the array to use as data.</param>
        /// <returns>The computed hash</returns>
        public byte[] ComputeHash(byte[] buffer, int offset, int count)
        {
            throw new NotImplementedException();
        }



        internal virtual unsafe void Init()
        {
            fixed (uint* hPt = &hashState[0])
            {
                Init(hPt);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal virtual unsafe void Init(uint* hPt)
        {
            hPt[0] = 0x6a09e667;
            hPt[1] = 0xbb67ae85;
            hPt[2] = 0x3c6ef372;
            hPt[3] = 0xa54ff53a;
            hPt[4] = 0x510e527f;
            hPt[5] = 0x9b05688c;
            hPt[6] = 0x1f83d9ab;
            hPt[7] = 0x5be0cd19;
        }


        internal unsafe byte[] GetBytes()
        {
            fixed (uint* hPt = &hashState[0])
                return GetBytes(hPt);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal unsafe byte[] GetBytes(uint* hPt)
        {
            byte[] res = new byte[HashByteSize];
            fixed (byte* bPt = &res[0])
            {
                for (int i = 0, j = 0; i < res.Length; i += 4, j++)
                {
                    bPt[i] = (byte)(hPt[j] >> 24);
                    bPt[i + 1] = (byte)(hPt[j] >> 16);
                    bPt[i + 2] = (byte)(hPt[j] >> 8);
                    bPt[i + 3] = (byte)hPt[j];
                }
            }
            return res;
        }


        internal unsafe void DoHash(byte[] data, int len)
        {
            byte[] finalBlock = new byte[64];

            fixed (byte* dPt = data, fPt = &finalBlock[0]) // If data.Length == 0 => &data[0] will throw an exception
            fixed (uint* hPt = &hashState[0], wPt = &w[0])
            {
                int remainingBytes = data.Length;
                int dIndex = 0;
                while (remainingBytes >= BlockByteSize)
                {
                    for (int i = 0; i < 16; i++, dIndex += 4)
                    {
                        wPt[i] = (uint)((dPt[dIndex] << 24) | (dPt[dIndex + 1] << 16) | (dPt[dIndex + 2] << 8) | dPt[dIndex + 3]);
                    }

                    CompressBlock(hPt, wPt);

                    remainingBytes -= BlockByteSize;
                }

                // Copy the reamaining bytes into a blockSize length buffer so that we can loop through it easily:
                Buffer.BlockCopy(data, data.Length - remainingBytes, finalBlock, 0, remainingBytes);

                // Append 1 bit followed by zeros. Since we only work with bytes, this is 1 whole byte
                fPt[remainingBytes] = 0b1000_0000;

                if (remainingBytes >= 56) // blockSize - pad2.Len = 64 - 8
                {
                    // This means we have an additional block to compress, which we do it here:

                    for (int i = 0, j = 0; i < 16; i++, j += 4)
                    {
                        wPt[i] = (uint)((fPt[j] << 24) | (fPt[j + 1] << 16) | (fPt[j + 2] << 8) | fPt[j + 3]);
                    }

                    CompressBlock(hPt, wPt);

                    // Zero out all the items in FinalBlock so it can be reused
                    for (int i = 0; i < 8; i++)
                    {
                        ((ulong*)fPt)[i] = 0;
                    }
                }

                // Add length in bits as the last 8 bytes of final block in big-endian order
                // See MessageLengthTest in Test project to understand what the following shifts are
                fPt[63] = (byte)(len << 3);
                fPt[62] = (byte)(len >> 5);
                fPt[61] = (byte)(len >> 13);
                fPt[60] = (byte)(len >> 21);
                fPt[59] = (byte)(len >> 29);
                // The remainig 3 bytes are always zero
                // The remaining 56 bytes are already set

                for (int i = 0, j = 0; i < 16; i++, j += 4)
                {
                    wPt[i] = (uint)((fPt[j] << 24) | (fPt[j + 1] << 16) | (fPt[j + 2] << 8) | fPt[j + 3]);
                }

                CompressBlock(hPt, wPt);


                if (IsDouble)
                {
                    DoSecondHash(hPt, wPt);
                }
            }
        }

        // TODO: Inlining doesn't seem to work here (big method), needs more investigation. checked with sharplab.io
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal virtual unsafe void DoSecondHash(uint* hPt, uint* wPt)
        {
            // Result of previous hash (hashState[]) is now our new block. So copy it here:
            wPt[0] = hPt[0];
            wPt[1] = hPt[1];
            wPt[2] = hPt[2];
            wPt[3] = hPt[3];
            wPt[4] = hPt[4];
            wPt[5] = hPt[5];
            wPt[6] = hPt[6];
            wPt[7] = hPt[7]; // 8*4 = 32 byte hash result

            wPt[8] = 0b10000000_00000000_00000000_00000000U; // 1 followed by 0 bits to fill pad1
            wPt[9] = 0;
            wPt[10] = 0;
            wPt[11] = 0;
            wPt[12] = 0;
            wPt[13] = 0;

            wPt[14] = 0; // Message length for pad2, since message is the 32 byte result of previous hash, length is 256 bit
            wPt[15] = 256;

            // Now initialize hashState to compute next round, since this is a new hash
            Init(hPt);

            // We only have 1 block so there is no need for a loop.
            CompressBlock(hPt, wPt);
        }


        internal unsafe void CompressBlock(uint* hPt, uint* wPt)
        {
            for (int i = 16; i < w.Length; i++)
            {
                wPt[i] = SSIG1(wPt[i - 2]) + wPt[i - 7] + SSIG0(wPt[i - 15]) + wPt[i - 16];
            }

            uint a = hPt[0];
            uint b = hPt[1];
            uint c = hPt[2];
            uint d = hPt[3];
            uint e = hPt[4];
            uint f = hPt[5];
            uint g = hPt[6];
            uint h = hPt[7];

            uint temp, aa, bb, cc, dd, ee, ff, hh, gg;

            fixed (uint* kPt = &Ks[0])
            {
                for (int j = 0; j < 64;)
                {
                    temp = h + BSIG1(e) + CH(e, f, g) + kPt[j] + wPt[j];
                    ee = d + temp;
                    aa = temp + BSIG0(a) + MAJ(a, b, c);
                    j++;

                    temp = g + BSIG1(ee) + CH(ee, e, f) + kPt[j] + wPt[j];
                    ff = c + temp;
                    bb = temp + BSIG0(aa) + MAJ(aa, a, b);
                    j++;

                    temp = f + BSIG1(ff) + CH(ff, ee, e) + kPt[j] + wPt[j];
                    gg = b + temp;
                    cc = temp + BSIG0(bb) + MAJ(bb, aa, a);
                    j++;

                    temp = e + BSIG1(gg) + CH(gg, ff, ee) + kPt[j] + wPt[j];
                    hh = a + temp;
                    dd = temp + BSIG0(cc) + MAJ(cc, bb, aa);
                    j++;

                    temp = ee + BSIG1(hh) + CH(hh, gg, ff) + kPt[j] + wPt[j];
                    h = aa + temp;
                    d = temp + BSIG0(dd) + MAJ(dd, cc, bb);
                    j++;

                    temp = ff + BSIG1(h) + CH(h, hh, gg) + kPt[j] + wPt[j];
                    g = bb + temp;
                    c = temp + BSIG0(d) + MAJ(d, dd, cc);
                    j++;

                    temp = gg + BSIG1(g) + CH(g, h, hh) + kPt[j] + wPt[j];
                    f = cc + temp;
                    b = temp + BSIG0(c) + MAJ(c, d, dd);
                    j++;

                    temp = hh + BSIG1(f) + CH(f, g, h) + kPt[j] + wPt[j];
                    e = dd + temp;
                    a = temp + BSIG0(b) + MAJ(b, c, d);
                    j++;
                }
            }

            hPt[0] += a;
            hPt[1] += b;
            hPt[2] += c;
            hPt[3] += d;
            hPt[4] += e;
            hPt[5] += f;
            hPt[6] += g;
            hPt[7] += h;
        }

        internal unsafe void CompressBlockWithWSet(uint* hPt, uint* wPt)
        {
            uint a = hPt[0];
            uint b = hPt[1];
            uint c = hPt[2];
            uint d = hPt[3];
            uint e = hPt[4];
            uint f = hPt[5];
            uint g = hPt[6];
            uint h = hPt[7];

            uint temp, aa, bb, cc, dd, ee, ff, hh, gg;

            fixed (uint* kPt = &Ks[0])
            {
                for (int j = 0; j < 64;)
                {
                    temp = h + BSIG1(e) + CH(e, f, g) + kPt[j] + wPt[j];
                    ee = d + temp;
                    aa = temp + BSIG0(a) + MAJ(a, b, c);
                    j++;

                    temp = g + BSIG1(ee) + CH(ee, e, f) + kPt[j] + wPt[j];
                    ff = c + temp;
                    bb = temp + BSIG0(aa) + MAJ(aa, a, b);
                    j++;

                    temp = f + BSIG1(ff) + CH(ff, ee, e) + kPt[j] + wPt[j];
                    gg = b + temp;
                    cc = temp + BSIG0(bb) + MAJ(bb, aa, a);
                    j++;

                    temp = e + BSIG1(gg) + CH(gg, ff, ee) + kPt[j] + wPt[j];
                    hh = a + temp;
                    dd = temp + BSIG0(cc) + MAJ(cc, bb, aa);
                    j++;

                    temp = ee + BSIG1(hh) + CH(hh, gg, ff) + kPt[j] + wPt[j];
                    h = aa + temp;
                    d = temp + BSIG0(dd) + MAJ(dd, cc, bb);
                    j++;

                    temp = ff + BSIG1(h) + CH(h, hh, gg) + kPt[j] + wPt[j];
                    g = bb + temp;
                    c = temp + BSIG0(d) + MAJ(d, dd, cc);
                    j++;

                    temp = gg + BSIG1(g) + CH(g, h, hh) + kPt[j] + wPt[j];
                    f = cc + temp;
                    b = temp + BSIG0(c) + MAJ(c, d, dd);
                    j++;

                    temp = hh + BSIG1(f) + CH(f, g, h) + kPt[j] + wPt[j];
                    e = dd + temp;
                    a = temp + BSIG0(b) + MAJ(b, c, d);
                    j++;
                }
            }

            hPt[0] += a;
            hPt[1] += b;
            hPt[2] += c;
            hPt[3] += d;
            hPt[4] += e;
            hPt[5] += f;
            hPt[6] += g;
            hPt[7] += h;
        }


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint CH(uint x, uint y, uint z)
        {
            // (x & y) ^ ((~x) & z);
            return z ^ (x & (y ^ z)); //TODO: find mathematical proof for this change
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint MAJ(uint x, uint y, uint z)
        {
            // (x & y) ^ (x & z) ^ (y & z);
            return (x & y) | (z & (x | y)); //TODO: find mathematical proof for this change
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint BSIG0(uint x)
        {
            // ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
            return (x >> 2 | x << 30) ^ (x >> 13 | x << 19) ^ (x >> 22 | x << 10);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private uint BSIG1(uint x)
        {
            // ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
            return (x >> 6 | x << 26) ^ (x >> 11 | x << 21) ^ (x >> 25 | x << 7);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal uint SSIG0(uint x)
        {
            // ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3);
            return (x >> 7 | x << 25) ^ (x >> 18 | x << 14) ^ (x >> 3);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal uint SSIG1(uint x)
        {
            // ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10);
            return (x >> 17 | x << 15) ^ (x >> 19 | x << 13) ^ (x >> 10);
        }

        //private uint ROTR(uint x, int n)
        //{
        //    return (x >> n) | (x << (32 - n));
        //}

        //private uint ROTL(uint x, int n)
        //{
        //    return (x << n) | (x >> (32 - n));
        //}



        #region IDisposable Support
        private bool disposedValue = false;

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    if (hashState != null)
                        Array.Clear(hashState, 0, hashState.Length);
                    hashState = null;

                    if (w != null)
                        Array.Clear(w, 0, w.Length);
                    w = null;
                }

                disposedValue = true;
            }
        }

        /// <summary>
        /// Releases all resources used by the current instance of the <see cref="Sha256"/> class.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
        }
        #endregion
    }
}
