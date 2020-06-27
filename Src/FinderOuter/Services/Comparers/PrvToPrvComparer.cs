// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.Cryptography.Asymmetric.KeyPairs;
using System;

namespace FinderOuter.Services.Comparers
{
    /// <summary>
    /// Compares 2 private key bytes. It is useful for HD keys where user has a single child private key.
    /// </summary>
    public class PrvToPrvComparer : ICompareService
    {
        private byte[] expected;

        public bool Init(string data)
        {
            try
            {
                using PrivateKey temp = new PrivateKey(data);
                expected = temp.ToBytes();
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public bool Compare(byte[] key) => ((ReadOnlySpan<byte>)expected).SequenceEqual(key);
    }
}
