// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

namespace FinderOuter.Backend.Cryptography.Hashing
{
    public class Keccak256 : Sha3_256
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Keccak256"/>.
        /// </summary>
        public Keccak256()
        {
            // r = 1088
            // c = 512
            suffix = 0x01; // <-- The only difference between the two hashes
        }
    }
}
