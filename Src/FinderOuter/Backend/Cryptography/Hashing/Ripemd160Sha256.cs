// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System;

namespace FinderOuter.Backend.Cryptography.Hashing
{
    /// <summary>
    /// Performs RIPEMD160 hash function on the result of SHA256 also known as HASH160
    /// <para/> This is more optimized and a lot faster than using .Net functions individually 
    /// specially when computing hash for small byte arrays such as 33 bytes (bitcoin public keys used in P2PKH scripts)
    /// </summary>
    public class Ripemd160Sha256 : IHashFunction
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Ripemd160Sha256"/>.
        /// </summary>
        public Ripemd160Sha256()
        {
            rip = new Ripemd160(false);
            sha = new Sha256(false);
        }



        /// <summary>
        /// Indicates whether the hash function should be performed twice on message.
        /// <para/> * Can not be true for this class.
        /// </summary>
        /// <exception cref="NotImplementedException"/>
        public bool IsDouble
        {
            get => false;
            set { if (value == true) throw new NotImplementedException(); }
        }

        /// <summary>
        /// Size of the hash result in bytes.
        /// </summary>
        public int HashByteSize => 20;

        /// <summary>
        /// This is not a stand alone hash function so it can't have "block size"!
        /// </summary>
        /// <exception cref="NotImplementedException"/>
        public int BlockByteSize => throw new NotImplementedException();

        private Ripemd160 rip;
        private Sha256 sha;



        /// <summary>
        /// Computes the hash value for the specified byte array 
        /// by calculating its SHA256 hash first then calculating RIPEMD160 hash of that hash.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="ObjectDisposedException"/>
        /// <param name="data">The byte array to compute hash for</param>
        /// <returns>The computed hash</returns>
        public unsafe byte[] ComputeHash(byte[] data)
        {
            if (disposedValue)
                throw new ObjectDisposedException("Instance was disposed.");
            if (data == null)
                throw new ArgumentNullException(nameof(data), "Data can not be null.");


            // Since HASH160 is used in bitcoin and for 99% of cases it is performed on a public key
            // and public keys are 33 byte compressed or 65 bytes uncompressed, we write these special cases:
            fixed (byte* dPt = data)
            fixed (uint* rip_blkPt = &rip.block[0], rip_hPt = &rip.hashState[0], sh_wPt = &sha.w[0])
            {
                // Step 1: compute SHA256 of data then copy result of hash (HashState) into RIPEMD160 block
                // so we just pass RIPEMD160 block as HashState of SHA256
                sha.Init(rip_blkPt);

                // Depending on the data length SHA256 can be different but the rest is similar
                if (data.Length == 33)
                {
                    int dIndex = 0;
                    for (int i = 0; i < 8; i++, dIndex += 4)
                    {
                        sh_wPt[i] = (uint)((dPt[dIndex] << 24) | (dPt[dIndex + 1] << 16) | (dPt[dIndex + 2] << 8) | dPt[dIndex + 3]);
                    }
                    sh_wPt[8] = (uint)((dPt[dIndex] << 24) | 0b00000000_10000000_00000000_00000000U);
                    sh_wPt[9] = 0;
                    sh_wPt[10] = 0;
                    sh_wPt[11] = 0;
                    sh_wPt[12] = 0;
                    sh_wPt[13] = 0;

                    sh_wPt[14] = 0; // Message length for pad2, 33 byte or 264 bits
                    sh_wPt[15] = 264;

                    sha.CompressBlock(rip_blkPt, sh_wPt);
                }
                else if (data.Length == 65)
                {
                    // There are two blocks in SHA256: first 64 bytes and the remaining 1 byte with pads
                    int dIndex = 0;
                    for (int i = 0; i < 16; i++, dIndex += 4)
                    {
                        sh_wPt[i] = (uint)((dPt[dIndex] << 24) | (dPt[dIndex + 1] << 16) | (dPt[dIndex + 2] << 8) | dPt[dIndex + 3]);
                    }
                    sha.CompressBlock(rip_blkPt, sh_wPt);

                    sh_wPt[0] = (uint)((dPt[dIndex] << 24) | 0b00000000_10000000_00000000_00000000U);
                    sh_wPt[1] = 0;
                    sh_wPt[2] = 0;
                    sh_wPt[3] = 0;
                    sh_wPt[4] = 0;
                    sh_wPt[5] = 0;
                    sh_wPt[6] = 0;
                    sh_wPt[7] = 0;
                    sh_wPt[8] = 0;
                    sh_wPt[9] = 0;
                    sh_wPt[10] = 0;
                    sh_wPt[11] = 0;
                    sh_wPt[12] = 0;
                    sh_wPt[13] = 0;

                    sh_wPt[14] = 0; // Message length for pad2, 65 byte or 520 bits
                    sh_wPt[15] = 520;

                    sha.CompressBlock(rip_blkPt, sh_wPt);
                }
                else
                {
                    // Perform SHA256:
                    sha.Init(); // init must be called since DoHash uses SHA256 HashState
                    sha.DoHash(data, data.Length);

                    // Copy SHA256 hash result into RIPEMD160 block:
                    Buffer.BlockCopy(sha.hashState, 0, rip.block, 0, sha.hashState.Length * 4); // 32 bytes copied
                }

                // SHA256 compression is over and the result is already inside RIPEMD160 Block
                // But SHA256 endianness is reverse of RIPEMD160, so we have to do an endian swap

                // 32 byte or 8 uint items coming from SHA256
                for (int i = 0; i < 8; i++)
                {
                    // RIPEMD160 uses little-endian while SHA256 uses big-endian
                    rip_blkPt[i] =
                        (rip_blkPt[i] >> 24) | (rip_blkPt[i] << 24) |                       // Swap byte 1 and 4
                        ((rip_blkPt[i] >> 8) & 0xff00) | ((rip_blkPt[i] << 8) & 0xff0000);  // Swap byte 2 and 3
                }
                rip_blkPt[8] = 0b00000000_00000000_00000000_10000000U;
                rip_blkPt[14] = 256;
                // rip_blkPt[15] = 0;
                // There is no need to set other items in block (like 13, 12,...)
                // because they are not changed and they are always zero

                rip.Init(rip_hPt);
                rip.CompressBlock(rip_blkPt, rip_hPt);
            }


            return rip.GetBytes();
        }

        /// <summary>
        /// Computes the hash value for the specified region of the specified byte array
        /// by calculating its SHA256 hash first then calculating RIPEMD160 hash of that hash.
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
            return ComputeHash(buffer.SubArray(offset, count));
        }



        #region IDisposable Support
        private bool disposedValue = false;

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    if (rip != null)
                        rip.Dispose();
                    rip = null;

                    if (sha != null)
                        sha.Dispose();
                    sha = null;
                }

                disposedValue = true;
            }
        }


        /// <summary>
        /// Releases all resources used by the current instance of the <see cref="Ripemd160Sha256"/> class.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
        }
        #endregion
    }
}
