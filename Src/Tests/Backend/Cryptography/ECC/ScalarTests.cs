// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend.Cryptography.Hashing;
using FinderOuter.Backend.ECC;
using Xunit;

namespace Tests.Backend.Cryptography.ECC
{
    public class ScalarTests
    {
        [Fact]
        public unsafe void Constructor_FromSha256Test()
        {
            using Sha256Fo sha = new();
            byte[] data = new byte[] { 1, 2, 3 };
            byte[] hash = sha.ComputeHash(data);

            fixed (uint* hPt = &sha.hashState[0])
            {
                var val1 = new Scalar(hash, out int of1);
                var val2 = new Scalar(hPt, out int of2);

                Assert.Equal(val1, val2);
                Assert.Equal(of1, of2);
                Assert.Equal(0, of1);
            }
        }

        [Fact]
        public unsafe void Constructor_FromSha512Test()
        {
            using Sha512Fo sha = new();
            byte[] data = new byte[] { 1, 2, 3 };
            // Get hashstate ready first
            sha.ComputeHash(data);

            fixed (ulong* hPt = &sha.hashState[0])
            {
                byte[] hash = Sha512Fo.GetFirst32Bytes(hPt);
                var val1 = new Scalar(hash, out int of1);
                var val2 = new Scalar(hPt, out int of2);

                Assert.True(val1 == val2);
                Assert.Equal(of1, of2);
                Assert.Equal(0, of1);
            }
        }


    }
}
