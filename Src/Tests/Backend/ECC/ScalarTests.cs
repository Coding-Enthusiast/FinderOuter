// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.Cryptography.EllipticCurve;
using FinderOuter.Backend.Hashing;

namespace Tests.Backend.ECC
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

                Scalar8x32 val1 = new(hash, out bool of1);
                Scalar8x32 val2 = new(pt, out bool of2);

                Assert.Equal(val1, val2);
                Assert.Equal(of1, of2);
                Assert.False(of1);
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
                Scalar8x32 val1 = new(hash, out bool of1);
                Scalar8x32 val2 = new(hPt, out bool of2);

                Assert.True(val1 == val2);
                Assert.Equal(of1, of2);
                Assert.False(of1);
            }
        }
    }
}
