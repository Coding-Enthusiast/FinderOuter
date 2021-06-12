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
            byte[] data = new byte[] { 1, 2, 3 };

            uint* pt = stackalloc uint[Sha256Fo.UBufferSize];
            fixed (byte* dPt = &data[0])
            {
                Sha256Fo.CompressData(dPt, data.Length, data.Length, pt);
                byte[] hash = Sha256Fo.GetBytes(pt);

                var val1 = new Scalar(hash, out int of1);
                var val2 = new Scalar(pt, out int of2);

                Assert.Equal(val1, val2);
                Assert.Equal(of1, of2);
                Assert.Equal(0, of1);
            }
        }

        [Fact]
        public unsafe void Constructor_FromSha512Test()
        {
            byte[] data = new byte[] { 1, 2, 3 };
            ulong* hPt = stackalloc ulong[Sha512Fo.UBufferSize];
            ulong* wPt = hPt + Sha512Fo.HashStateSize;
            fixed (byte* dPt = data)
            {
                // Get hashstate ready first
                Sha512Fo.CompressData(dPt, data.Length, data.Length, hPt, wPt);

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
