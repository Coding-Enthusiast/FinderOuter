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
    public class Hash160 : IDisposable
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Hash160"/>.
        /// </summary>
        public Hash160()
        {
            rip = new Ripemd160();
            sha = new Sha256Fo();
        }


        /// <summary>
        /// Size of the hash result in bytes.
        /// </summary>
        public const int HashByteSize = 20;

        private Ripemd160 rip;
        private Sha256Fo sha;


        /// <summary>
        /// Computes the hash value for the specified byte array 
        /// by calculating its SHA256 hash first then calculating RIPEMD160 hash of that hash.
        /// </summary>
        /// <exception cref="ArgumentNullException"/>
        /// <exception cref="ObjectDisposedException"/>
        /// <param name="data">The byte array to compute hash for</param>
        /// <returns>The computed hash</returns>
        public unsafe byte[] ComputeHash(Span<byte> data)
        {
            if (isDisposed)
                throw new ObjectDisposedException("Instance was disposed.");
            if (data == null)
                throw new ArgumentNullException(nameof(data), "Data can not be null.");


            if (data.Length == 33)
            {
                return Compress33(data);
            }
            else if (data.Length == 65)
            {
                return Compress65(data);
            }

            // Since HASH160 is used in bitcoin and for 99% of cases it is performed on a public key
            // and public keys are 33 byte compressed or 65 bytes uncompressed, we write these special cases:
            fixed (byte* dPt = data)
            fixed (uint* rip_blkPt = &rip.block[0], rip_hPt = &rip.hashState[0], sh_wPt = &sha.w[0])
            {
                // Step 1: compute SHA256 of data then copy result of hash (HashState) into RIPEMD160 block
                // so we just pass RIPEMD160 block as HashState of SHA256
                sha.Init();
                sha.DoHash(data, data.Length);

                // Copy SHA256 hash result into RIPEMD160 block:
                Buffer.BlockCopy(sha.hashState, 0, rip.block, 0, sha.hashState.Length * 4); // 32 bytes copied

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

                return rip.GetBytes(rip_hPt);
            }
        }

        public unsafe byte[] Compress22(Span<byte> data)
        {
            uint* pt = stackalloc uint[Sha256Fo.UBufferSize];
            fixed (byte* dPt = data)
            fixed (uint* rip_blkPt = &rip.block[0], rip_hPt = &rip.hashState[0])
            {
                // Step 1: compute SHA256 of data then copy result of hash (HashState) into RIPEMD160 block
                Sha256Fo.Init(pt);

                pt[8] = (uint)((dPt[0] << 24) | (dPt[1] << 16) | (dPt[2] << 8) | dPt[3]);
                pt[9] = (uint)((dPt[4] << 24) | (dPt[5] << 16) | (dPt[6] << 8) | dPt[7]);
                pt[10] = (uint)((dPt[8] << 24) | (dPt[9] << 16) | (dPt[10] << 8) | dPt[11]);
                pt[11] = (uint)((dPt[12] << 24) | (dPt[13] << 16) | (dPt[14] << 8) | dPt[15]);
                pt[12] = (uint)((dPt[16] << 24) | (dPt[17] << 16) | (dPt[18] << 8) | dPt[19]);
                pt[13] = (uint)((dPt[20] << 24) | (dPt[21] << 16) | 0b00000000_00000000_10000000_00000000U);
                pt[14] = 0;
                pt[15] = 0;
                pt[16] = 0;
                pt[17] = 0;
                pt[18] = 0;
                pt[19] = 0;
                pt[20] = 0;
                pt[21] = 0;
                pt[22] = 0;
                pt[23] = 176; // 22*8

                Sha256Fo.Compress22(pt);

                // SHA256 compression is over and the result is already inside RIPEMD160 Block
                // But SHA256 endianness is reverse of RIPEMD160, so we have to do an endian swap
                // RIPEMD160 hashstate has 5 items while SHA256 has 8 => w starts at index 6
                // 32 byte or 8 uint items coming from SHA256
                rip_blkPt[0] = (pt[0] >> 24) | (pt[0] << 24) |                       // Swap byte 1 and 4
                               ((pt[0] >> 8) & 0xff00) | ((pt[0] << 8) & 0xff0000);  // Swap byte 2 and 3
                rip_blkPt[1] = (pt[1] >> 24) | (pt[1] << 24) | ((pt[1] >> 8) & 0xff00) | ((pt[1] << 8) & 0xff0000);
                rip_blkPt[2] = (pt[2] >> 24) | (pt[2] << 24) | ((pt[2] >> 8) & 0xff00) | ((pt[2] << 8) & 0xff0000);
                rip_blkPt[3] = (pt[3] >> 24) | (pt[3] << 24) | ((pt[3] >> 8) & 0xff00) | ((pt[3] << 8) & 0xff0000);
                rip_blkPt[4] = (pt[4] >> 24) | (pt[4] << 24) | ((pt[4] >> 8) & 0xff00) | ((pt[4] << 8) & 0xff0000);
                rip_blkPt[5] = (pt[5] >> 24) | (pt[5] << 24) | ((pt[5] >> 8) & 0xff00) | ((pt[5] << 8) & 0xff0000);
                rip_blkPt[6] = (pt[6] >> 24) | (pt[6] << 24) | ((pt[6] >> 8) & 0xff00) | ((pt[6] << 8) & 0xff0000);
                rip_blkPt[7] = (pt[7] >> 24) | (pt[7] << 24) | ((pt[7] >> 8) & 0xff00) | ((pt[7] << 8) & 0xff0000);
                rip_blkPt[8] = 0b00000000_00000000_00000000_10000000U;
                rip_blkPt[14] = 256;
                // rip_blkPt[15] = 0;
                // There is no need to set other items in block (like 13, 12,...)
                // because they are not changed and they are always zero

                rip.Init(rip_hPt);
                rip.CompressBlock(rip_blkPt, rip_hPt);

                return rip.GetBytes(rip_hPt);
            }
        }

        /// <summary>
        /// Returns HASH160(OP_0 | Push(HASH160(33_bytes)))
        /// </summary>
        public unsafe byte[] Compress33_P2sh(Span<byte> data)
        {
            uint* pt = stackalloc uint[Sha256Fo.UBufferSize];
            fixed (byte* dPt = data)
            fixed (uint* rip_blkPt = &rip.block[0], rip_hPt = &rip.hashState[0])
            {
                pt[8] = (uint)((dPt[0] << 24) | (dPt[1] << 16) | (dPt[2] << 8) | dPt[3]);
                pt[9] = (uint)((dPt[4] << 24) | (dPt[5] << 16) | (dPt[6] << 8) | dPt[7]);
                pt[10] = (uint)((dPt[8] << 24) | (dPt[9] << 16) | (dPt[10] << 8) | dPt[11]);
                pt[11] = (uint)((dPt[12] << 24) | (dPt[13] << 16) | (dPt[14] << 8) | dPt[15]);
                pt[12] = (uint)((dPt[16] << 24) | (dPt[17] << 16) | (dPt[18] << 8) | dPt[19]);
                pt[13] = (uint)((dPt[20] << 24) | (dPt[21] << 16) | (dPt[22] << 8) | dPt[23]);
                pt[14] = (uint)((dPt[24] << 24) | (dPt[25] << 16) | (dPt[26] << 8) | dPt[27]);
                pt[15] = (uint)((dPt[28] << 24) | (dPt[29] << 16) | (dPt[30] << 8) | dPt[31]);
                pt[16] = (uint)((dPt[32] << 24) | 0b00000000_10000000_00000000_00000000U);
                pt[17] = 0;
                pt[18] = 0;
                pt[19] = 0;
                pt[20] = 0;
                pt[21] = 0;
                pt[22] = 0;
                pt[23] = 264;

                Sha256Fo.Init(pt);
                Sha256Fo.Compress33(pt);

                rip_blkPt[0] = (pt[0] >> 24) | (pt[0] << 24) |                       // Swap byte 1 and 4
                               ((pt[0] >> 8) & 0xff00) | ((pt[0] << 8) & 0xff0000);  // Swap byte 2 and 3
                rip_blkPt[1] = (pt[1] >> 24) | (pt[1] << 24) | ((pt[1] >> 8) & 0xff00) | ((pt[1] << 8) & 0xff0000);
                rip_blkPt[2] = (pt[2] >> 24) | (pt[2] << 24) | ((pt[2] >> 8) & 0xff00) | ((pt[2] << 8) & 0xff0000);
                rip_blkPt[3] = (pt[3] >> 24) | (pt[3] << 24) | ((pt[3] >> 8) & 0xff00) | ((pt[3] << 8) & 0xff0000);
                rip_blkPt[4] = (pt[4] >> 24) | (pt[4] << 24) | ((pt[4] >> 8) & 0xff00) | ((pt[4] << 8) & 0xff0000);
                rip_blkPt[5] = (pt[5] >> 24) | (pt[5] << 24) | ((pt[5] >> 8) & 0xff00) | ((pt[5] << 8) & 0xff0000);
                rip_blkPt[6] = (pt[6] >> 24) | (pt[6] << 24) | ((pt[6] >> 8) & 0xff00) | ((pt[6] << 8) & 0xff0000);
                rip_blkPt[7] = (pt[7] >> 24) | (pt[7] << 24) | ((pt[7] >> 8) & 0xff00) | ((pt[7] << 8) & 0xff0000);
                rip_blkPt[8] = 0b00000000_00000000_00000000_10000000U;
                rip_blkPt[14] = 256;

                rip.Init(rip_hPt);
                rip.CompressBlock(rip_blkPt, rip_hPt);

                // Compute second HASH160
                pt[8] = 0x00140000U | ((rip_hPt[0] << 8) & 0xff00) | ((rip_hPt[0] >> 8) & 0xff);
                pt[9] = ((rip_hPt[0] << 8) & 0xff000000) | ((rip_hPt[0] >> 8) & 0x00ff0000) |
                        ((rip_hPt[1] << 8) & 0x0000ff00) | ((rip_hPt[1] >> 8) & 0x000000ff);
                pt[10] = ((rip_hPt[1] << 8) & 0xff000000) | ((rip_hPt[1] >> 8) & 0x00ff0000) |
                         ((rip_hPt[2] << 8) & 0x0000ff00) | ((rip_hPt[2] >> 8) & 0x000000ff);
                pt[11] = ((rip_hPt[2] << 8) & 0xff000000) | ((rip_hPt[2] >> 8) & 0x00ff0000) |
                         ((rip_hPt[3] << 8) & 0x0000ff00) | ((rip_hPt[3] >> 8) & 0x000000ff);
                pt[12] = ((rip_hPt[3] << 8) & 0xff000000) | ((rip_hPt[3] >> 8) & 0x00ff0000) |
                         ((rip_hPt[4] << 8) & 0x0000ff00) | ((rip_hPt[4] >> 8) & 0x000000ff);
                pt[13] = ((rip_hPt[4] << 8) & 0xff000000) | ((rip_hPt[4] >> 8) & 0x00ff0000) |
                         0b00000000_00000000_10000000_00000000U;
                pt[14] = 0;
                pt[15] = 0;
                pt[16] = 0;
                // 9 to 14 are already 0
                pt[23] = 176; // 22*8

                Sha256Fo.Init(pt);
                Sha256Fo.Compress22(pt);

                rip_blkPt[0] = (pt[0] >> 24) | (pt[0] << 24) |                       // Swap byte 1 and 4
                               ((pt[0] >> 8) & 0xff00) | ((pt[0] << 8) & 0xff0000);  // Swap byte 2 and 3
                rip_blkPt[1] = (pt[1] >> 24) | (pt[1] << 24) | ((pt[1] >> 8) & 0xff00) | ((pt[1] << 8) & 0xff0000);
                rip_blkPt[2] = (pt[2] >> 24) | (pt[2] << 24) | ((pt[2] >> 8) & 0xff00) | ((pt[2] << 8) & 0xff0000);
                rip_blkPt[3] = (pt[3] >> 24) | (pt[3] << 24) | ((pt[3] >> 8) & 0xff00) | ((pt[3] << 8) & 0xff0000);
                rip_blkPt[4] = (pt[4] >> 24) | (pt[4] << 24) | ((pt[4] >> 8) & 0xff00) | ((pt[4] << 8) & 0xff0000);
                rip_blkPt[5] = (pt[5] >> 24) | (pt[5] << 24) | ((pt[5] >> 8) & 0xff00) | ((pt[5] << 8) & 0xff0000);
                rip_blkPt[6] = (pt[6] >> 24) | (pt[6] << 24) | ((pt[6] >> 8) & 0xff00) | ((pt[6] << 8) & 0xff0000);
                rip_blkPt[7] = (pt[7] >> 24) | (pt[7] << 24) | ((pt[7] >> 8) & 0xff00) | ((pt[7] << 8) & 0xff0000);
                rip_blkPt[8] = 0b00000000_00000000_00000000_10000000U;
                rip_blkPt[14] = 256;

                rip.Init(rip_hPt);
                rip.CompressBlock(rip_blkPt, rip_hPt);

                return rip.GetBytes(rip_hPt);
            }
        }

        public unsafe byte[] Compress33(Span<byte> data)
        {
            uint* pt = stackalloc uint[Sha256Fo.UBufferSize];
            fixed (byte* dPt = data)
            fixed (uint* rip_blkPt = &rip.block[0], rip_hPt = &rip.hashState[0])
            {
                // Step 1: compute SHA256 of data then copy result of hash (HashState) into RIPEMD160 block
                // so we just pass RIPEMD160 block as HashState of SHA256
                Sha256Fo.Init(pt);

                int dIndex = 0;
                for (int i = 8; i < 16; i++, dIndex += 4)
                {
                    pt[i] = (uint)((dPt[dIndex] << 24) | (dPt[dIndex + 1] << 16) | (dPt[dIndex + 2] << 8) | dPt[dIndex + 3]);
                }
                pt[16] = (uint)((dPt[dIndex] << 24) | 0b00000000_10000000_00000000_00000000U);
                pt[17] = 0;
                pt[18] = 0;
                pt[19] = 0;
                pt[20] = 0;
                pt[21] = 0;
                pt[22] = 0; // Message length for pad2, 33 byte or 264 bits
                pt[23] = 264;

                Sha256Fo.Compress33(pt);

                // SHA256 compression is over and the result is already inside RIPEMD160 Block
                // But SHA256 endianness is reverse of RIPEMD160, so we have to do an endian swap

                // 32 byte or 8 uint items coming from SHA256
                rip_blkPt[0] = (pt[0] >> 24) | (pt[0] << 24) |                       // Swap byte 1 and 4
                               ((pt[0] >> 8) & 0xff00) | ((pt[0] << 8) & 0xff0000);  // Swap byte 2 and 3
                rip_blkPt[1] = (pt[1] >> 24) | (pt[1] << 24) | ((pt[1] >> 8) & 0xff00) | ((pt[1] << 8) & 0xff0000);
                rip_blkPt[2] = (pt[2] >> 24) | (pt[2] << 24) | ((pt[2] >> 8) & 0xff00) | ((pt[2] << 8) & 0xff0000);
                rip_blkPt[3] = (pt[3] >> 24) | (pt[3] << 24) | ((pt[3] >> 8) & 0xff00) | ((pt[3] << 8) & 0xff0000);
                rip_blkPt[4] = (pt[4] >> 24) | (pt[4] << 24) | ((pt[4] >> 8) & 0xff00) | ((pt[4] << 8) & 0xff0000);
                rip_blkPt[5] = (pt[5] >> 24) | (pt[5] << 24) | ((pt[5] >> 8) & 0xff00) | ((pt[5] << 8) & 0xff0000);
                rip_blkPt[6] = (pt[6] >> 24) | (pt[6] << 24) | ((pt[6] >> 8) & 0xff00) | ((pt[6] << 8) & 0xff0000);
                rip_blkPt[7] = (pt[7] >> 24) | (pt[7] << 24) | ((pt[7] >> 8) & 0xff00) | ((pt[7] << 8) & 0xff0000);
                rip_blkPt[8] = 0b00000000_00000000_00000000_10000000U;
                rip_blkPt[14] = 256;
                // rip_blkPt[15] = 0;
                // There is no need to set other items in block (like 13, 12,...)
                // because they are not changed and they are always zero

                rip.Init(rip_hPt);
                rip.CompressBlock(rip_blkPt, rip_hPt);

                return rip.GetBytes(rip_hPt);
            }
        }

        public unsafe byte[] Compress65(Span<byte> data)
        {
            fixed (byte* dPt = data)
            fixed (uint* rip_blkPt = &rip.block[0], rip_hPt = &rip.hashState[0], sh_wPt = &sha.w[0])
            {
                // Step 1: compute SHA256 of data then copy result of hash (HashState) into RIPEMD160 block
                // so we just pass RIPEMD160 block as HashState of SHA256
                Sha256Fo.Init(rip_blkPt);
                sha.Compress65(dPt, rip_blkPt, sh_wPt);

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

                return rip.GetBytes(rip_hPt);
            }
        }


        private bool isDisposed = false;

        protected virtual void Dispose(bool disposing)
        {
            if (!isDisposed)
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

                isDisposed = true;
            }
        }

        /// <summary>
        /// Releases all resources used by the current instance of the <see cref="Hash160"/> class.
        /// </summary>
        public void Dispose() => Dispose(true);
    }
}
