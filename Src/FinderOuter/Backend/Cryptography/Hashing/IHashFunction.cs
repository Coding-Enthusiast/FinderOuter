// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System;

namespace FinderOuter.Backend.Cryptography.Hashing
{
    public interface IHashFunction : IDisposable
    {
        /// <summary>
        /// Indicates whether the hash function should be performed twice on message.
        /// For example Double SHA256 that bitcoin uses.
        /// </summary>
        bool IsDouble { get; set; }

        /// <summary>
        /// Size of the hash result in bytes.
        /// </summary>
        int HashByteSize { get; }

        /// <summary>
        /// Size of the blocks used in each round.
        /// </summary>
        int BlockByteSize { get; }

        /// <summary>
        /// Computes the hash value for the specified byte array.
        /// </summary>
        /// <param name="data">The byte array to compute hash for</param>
        /// <returns>The computed hash</returns>
        byte[] ComputeHash(byte[] data);

        /// <summary>
        /// Computes the hash value for the specified region of the specified byte array.
        /// </summary>
        /// <param name="buffer">The byte array to compute hash for</param>
        /// <param name="offset">The offset into the byte array from which to begin using data.</param>
        /// <param name="count">The number of bytes in the array to use as data.</param>
        /// <returns>The computed hash</returns>
        byte[] ComputeHash(byte[] buffer, int offset, int count);
    }
}
