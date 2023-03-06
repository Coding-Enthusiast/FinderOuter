// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

namespace FinderOuter.Backend.Cryptography.Hashing
{
    public class Sha3_256 : Keccak
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="Sha3_256"/>.
        /// </summary>
        public Sha3_256()
        {
            // r = 1088
            // c = 512
            suffix = 0x06;
        }



        public int HashByteSize => 32;
        public override int BlockByteSize => 136;



        protected override void SetSecondPadBit()
        {
            h16 ^= 0x8000000000000000; // ((ulong)0x80 << 56);
        }

        protected override unsafe void Absorb(byte* dPt)
        {
            h0 ^= ((ulong)dPt[7] << 56) | ((ulong)dPt[6] << 48) | ((ulong)dPt[5] << 40) | ((ulong)dPt[4] << 32)
                | ((ulong)dPt[3] << 24) | ((ulong)dPt[2] << 16) | ((ulong)dPt[1] << 8) | dPt[0];
            h1 ^= ((ulong)dPt[15] << 56) | ((ulong)dPt[14] << 48) | ((ulong)dPt[13] << 40) | ((ulong)dPt[12] << 32)
                | ((ulong)dPt[11] << 24) | ((ulong)dPt[10] << 16) | ((ulong)dPt[9] << 8) | dPt[8];
            h2 ^= ((ulong)dPt[23] << 56) | ((ulong)dPt[22] << 48) | ((ulong)dPt[21] << 40) | ((ulong)dPt[20] << 32)
                | ((ulong)dPt[19] << 24) | ((ulong)dPt[18] << 16) | ((ulong)dPt[17] << 8) | dPt[16];
            h3 ^= ((ulong)dPt[31] << 56) | ((ulong)dPt[30] << 48) | ((ulong)dPt[29] << 40) | ((ulong)dPt[28] << 32)
                | ((ulong)dPt[27] << 24) | ((ulong)dPt[26] << 16) | ((ulong)dPt[25] << 8) | dPt[24];
            h4 ^= ((ulong)dPt[39] << 56) | ((ulong)dPt[38] << 48) | ((ulong)dPt[37] << 40) | ((ulong)dPt[36] << 32)
                | ((ulong)dPt[35] << 24) | ((ulong)dPt[34] << 16) | ((ulong)dPt[33] << 8) | dPt[32];
            h5 ^= ((ulong)dPt[47] << 56) | ((ulong)dPt[46] << 48) | ((ulong)dPt[45] << 40) | ((ulong)dPt[44] << 32)
                | ((ulong)dPt[43] << 24) | ((ulong)dPt[42] << 16) | ((ulong)dPt[41] << 8) | dPt[40];
            h6 ^= ((ulong)dPt[55] << 56) | ((ulong)dPt[54] << 48) | ((ulong)dPt[53] << 40) | ((ulong)dPt[52] << 32)
                | ((ulong)dPt[51] << 24) | ((ulong)dPt[50] << 16) | ((ulong)dPt[49] << 8) | dPt[48];
            h7 ^= ((ulong)dPt[63] << 56) | ((ulong)dPt[62] << 48) | ((ulong)dPt[61] << 40) | ((ulong)dPt[60] << 32)
                | ((ulong)dPt[59] << 24) | ((ulong)dPt[58] << 16) | ((ulong)dPt[57] << 8) | dPt[56];
            h8 ^= ((ulong)dPt[71] << 56) | ((ulong)dPt[70] << 48) | ((ulong)dPt[69] << 40) | ((ulong)dPt[68] << 32)
                | ((ulong)dPt[67] << 24) | ((ulong)dPt[66] << 16) | ((ulong)dPt[65] << 8) | dPt[64];
            h9 ^= ((ulong)dPt[79] << 56) | ((ulong)dPt[78] << 48) | ((ulong)dPt[77] << 40) | ((ulong)dPt[76] << 32)
                | ((ulong)dPt[75] << 24) | ((ulong)dPt[74] << 16) | ((ulong)dPt[73] << 8) | dPt[72];
            h10 ^= ((ulong)dPt[87] << 56) | ((ulong)dPt[86] << 48) | ((ulong)dPt[85] << 40) | ((ulong)dPt[84] << 32)
                | ((ulong)dPt[83] << 24) | ((ulong)dPt[82] << 16) | ((ulong)dPt[81] << 8) | dPt[80];
            h11 ^= ((ulong)dPt[95] << 56) | ((ulong)dPt[94] << 48) | ((ulong)dPt[93] << 40) | ((ulong)dPt[92] << 32)
                | ((ulong)dPt[91] << 24) | ((ulong)dPt[90] << 16) | ((ulong)dPt[89] << 8) | dPt[88];
            h12 ^= ((ulong)dPt[103] << 56) | ((ulong)dPt[102] << 48) | ((ulong)dPt[101] << 40) | ((ulong)dPt[100] << 32)
                | ((ulong)dPt[99] << 24) | ((ulong)dPt[98] << 16) | ((ulong)dPt[97] << 8) | dPt[96];
            h13 ^= ((ulong)dPt[111] << 56) | ((ulong)dPt[110] << 48) | ((ulong)dPt[109] << 40) | ((ulong)dPt[108] << 32)
                | ((ulong)dPt[107] << 24) | ((ulong)dPt[106] << 16) | ((ulong)dPt[105] << 8) | dPt[104];
            h14 ^= ((ulong)dPt[119] << 56) | ((ulong)dPt[118] << 48) | ((ulong)dPt[117] << 40) | ((ulong)dPt[116] << 32)
                | ((ulong)dPt[115] << 24) | ((ulong)dPt[114] << 16) | ((ulong)dPt[113] << 8) | dPt[112];
            h15 ^= ((ulong)dPt[127] << 56) | ((ulong)dPt[126] << 48) | ((ulong)dPt[125] << 40) | ((ulong)dPt[124] << 32)
                | ((ulong)dPt[123] << 24) | ((ulong)dPt[122] << 16) | ((ulong)dPt[121] << 8) | dPt[120];
            h16 ^= ((ulong)dPt[135] << 56) | ((ulong)dPt[134] << 48) | ((ulong)dPt[133] << 40) | ((ulong)dPt[132] << 32)
                | ((ulong)dPt[131] << 24) | ((ulong)dPt[130] << 16) | ((ulong)dPt[129] << 8) | dPt[128];
        }


        protected override unsafe void DoSecondHash()
        {
            // Result of previous hash is first 32 bytes of the HashState or (h0 to h3)
            // Second hash is performed on this.
            // Keccak hash starts by "absorbing" the message by XORing it with HashState which starts as zero.
            // Since blockSize is 136 here, there is only one absorbing round and (value XOR 0) is always (value)
            // so we simply have to copy the result in new HashState which is like zeroing (h4 to h24).
            // Then pads are added and compression is performed

            // We skip setting h4 to 0 since it is set below and to skip 1 copy!
            h5 = h6 = h7 = h8 = h9 = h10 = h11 = h12
               = h13 = h14 = h15 = h16 = h17 = h18 = h19 = h20 = h21 = h22 = h23 = h24 = 0;
            // Add suffix:
            h4 = suffix; // h4 initial value should be zero and then XORed with suffix
            SetSecondPadBit();
            KeccakF1600();
        }


        protected override unsafe byte[] GetBytes()
        {
            byte[] result = new byte[32];
            fixed (byte* resPt = &result[0])
            {
                resPt[0] = (byte)h0;
                resPt[1] = (byte)(h0 >> 8);
                resPt[2] = (byte)(h0 >> 16);
                resPt[3] = (byte)(h0 >> 24);
                resPt[4] = (byte)(h0 >> 32);
                resPt[5] = (byte)(h0 >> 40);
                resPt[6] = (byte)(h0 >> 48);
                resPt[7] = (byte)(h0 >> 56);

                resPt[8] = (byte)h1;
                resPt[9] = (byte)(h1 >> 8);
                resPt[10] = (byte)(h1 >> 16);
                resPt[11] = (byte)(h1 >> 24);
                resPt[12] = (byte)(h1 >> 32);
                resPt[13] = (byte)(h1 >> 40);
                resPt[14] = (byte)(h1 >> 48);
                resPt[15] = (byte)(h1 >> 56);

                resPt[16] = (byte)h2;
                resPt[17] = (byte)(h2 >> 8);
                resPt[18] = (byte)(h2 >> 16);
                resPt[19] = (byte)(h2 >> 24);
                resPt[20] = (byte)(h2 >> 32);
                resPt[21] = (byte)(h2 >> 40);
                resPt[22] = (byte)(h2 >> 48);
                resPt[23] = (byte)(h2 >> 56);

                resPt[24] = (byte)h3;
                resPt[25] = (byte)(h3 >> 8);
                resPt[26] = (byte)(h3 >> 16);
                resPt[27] = (byte)(h3 >> 24);
                resPt[28] = (byte)(h3 >> 32);
                resPt[29] = (byte)(h3 >> 40);
                resPt[30] = (byte)(h3 >> 48);
                resPt[31] = (byte)(h3 >> 56);
            }

            return result;
        }

    }
}
