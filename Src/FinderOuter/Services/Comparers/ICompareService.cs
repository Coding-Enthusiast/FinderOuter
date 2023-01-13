// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.Cryptography.EllipticCurve;

namespace FinderOuter.Services.Comparers
{
    public interface ICompareService
    {
        public string CompareType { get; }
        public bool IsInitialized { get; }
        public Calc Calc { get; }

        /// <summary>
        /// Builds the private key using the <see cref="Backend.Cryptography.Hashing.Sha256Fo.hashState"/> pointer
        /// </summary>
        /// <param name="hPt"><see cref="Backend.Cryptography.Hashing.Sha256Fo.hashState"/> pointer</param>
        /// <returns></returns>
        unsafe bool Compare(uint* hPt);
        /// <summary>
        /// Builds the private key using the <see cref="Backend.Cryptography.Hashing.Sha512Fo.hashState"/> pointer
        /// using its first 32 bytes as the key (similar to what BIP-32 works)
        /// </summary>
        /// <param name="hPt"><see cref="Backend.Cryptography.Hashing.Sha512Fo.hashState"/> pointer</param>
        /// <returns></returns>
        unsafe bool Compare(ulong* hPt);

        bool Compare(in PointJacobian point);

        bool Init(string data);
        ICompareService Clone();
        bool Compare(byte[] key);
        bool Compare(in Scalar8x32 key);
    }
}
