// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System;

namespace FinderOuter.Backend.Cryptography.Hashing
{
    public interface IHmacFunction : IDisposable
    {
        /// <summary>
        /// Size of the blocks
        /// </summary>
        int BlockSize { get; }

        /// <summary>
        /// Size of the hash result in bytes.
        /// </summary>
        int OutputSize { get; }

        /// <summary>
        /// Key to use in HMAC function
        /// </summary>
        byte[] Key { get; set; }

        /// <summary>
        /// Computes HMAC hash of a given byte array with the specified hash function and the specified key data.
        /// <para/> * This function is useful for computing hash multiple times each with a differet key.
        /// </summary>
        /// <param name="data">The byte array to compute hash for</param>
        /// <param name="key">The secret key used for HMAC encryption. 
        /// Key size is best chosen based on recommended size for each function.</param>
        /// <returns>The computed hash</returns>
        byte[] ComputeHash(byte[] data, byte[] key);

        /// <summary>
        /// Computes HMAC hash of a given byte array with the specified hash function with the key that was specified in constructor.
        /// <para/> * This function is useful for computing hash multiple times with the same key.
        /// </summary>
        /// <param name="data">The byte array to compute hash for</param>
        /// <returns>The computed hash</returns>
        byte[] ComputeHash(byte[] data);
    }
}
