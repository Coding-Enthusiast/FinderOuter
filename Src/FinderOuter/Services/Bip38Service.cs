// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using FinderOuter.Backend;
using FinderOuter.Backend.Cryptography.Hashing;
using FinderOuter.Backend.ECC;
using FinderOuter.Models;
using FinderOuter.Services.Comparers;
using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace FinderOuter.Services
{
    public class Bip38Service
    {
        public Bip38Service(IReport rep)
        {
            report = rep;
            inputService = new();
        }


        private readonly IReport report;
        private readonly InputService inputService;
        private ICompareService comparer;


        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe bool ParallelMoveNext(int* items, int len, int max)
        {
            for (int i = len - 1; i > 0; --i)
            {
                items[i] += 1;

                if (items[i] == max)
                {
                    items[i] = 0;
                }
                else
                {
                    return true;
                }
            }

            return false;
        }

        public unsafe void MainLoop(byte[] data, byte[] salt, bool isComp, byte[] allValues, int passLength,
                                    int firstItem, ParallelLoopState loopState)
        {
            Debug.Assert(salt.Length == 4);
            Debug.Assert(passLength <= Sha256Fo.BlockByteSize);

            // The whole process:
            // dk = Scrypt(cost-param=16384, blockSizeFactor=8, parallelization=8).Derive(pass, salt, dkLen=64)
            //    dk'=PBKDF2(HMACSHA256,iteration=1).Derive(pass,salt, dkLen=8192)
            //    dk"=ROMIX(dk')
            //    dk =PBKDF2(HMACSHA256,iteration=1).Derive(pass,dk",dkLen=64)
            // decrypted = AES(key=dk[32:64]).decrypt(ECB,256,IV=null,nopadding)
            // key = decrypted ^ dk[0:32]

            using AesManaged aes = new()
            {
                KeySize = 256,
                Mode = CipherMode.ECB,
                IV = new byte[16],
                Padding = PaddingMode.None
            };

            uint saltUint = (uint)(salt[0] << 24 | salt[1] << 16 | salt[2] << 8 | salt[3]);
            var localComparer = comparer.Clone();

            int[] items = new int[passLength];
            items[0] = firstItem;
            uint[] passValues = new uint[passLength / 4 + (passLength % 4 != 0 ? 1 : 0)];

            uint[] InnerPads = Enumerable.Repeat(0x36363636U, 16).ToArray();
            uint[] OuterPads = Enumerable.Repeat(0x5c5c5c5cU, 16).ToArray();

            uint[] v = new uint[4194304];
            uint[] derivedKey = new uint[2048];

            uint* final = stackalloc uint[16];
            // hash-state | working-vector | ipad-store | opad-store
            // Total = 8+64+8+8 = 352 bytes
            uint* pt = stackalloc uint[Sha256Fo.UBufferSize + (2 * Sha256Fo.HashStateSize)];
            uint* wPt = pt + Sha256Fo.HashStateSize;
            uint* iPtStore = wPt + Sha256Fo.WorkingVectorSize;
            uint* oPtStore = iPtStore + Sha256Fo.HashStateSize;

            fixed (byte* valPt = &allValues[0])
            fixed (int* itemsPt = &items[0])
            fixed (uint* ipadSource = &InnerPads[0], opadSource = &OuterPads[0])
            fixed (uint* vPt = &v[0], dkPt = &derivedKey[0], passVal = &passValues[0])
            {
                do
                {
                    if (loopState.IsStopped)
                    {
                        return;
                    }
                    // * First PBKDF2 (blockcount=256, dkLen=8192, password=pass, salt=salt_4)
                    // With iteration=1 there is no loop, only multiple hashes to fill the dk 32 bytes at a time (256x)

                    // HMAC key (sets pads) is the password and is fixed for both PBKDF2 calls so we can set the pads
                    // and compute the hashstate after first block compression
                    int padIndex = 0; int itemIndex = 0;
                    for (; itemIndex < items.Length / 4; padIndex++, itemIndex += 4)
                    {
                        Debug.Assert(itemsPt[itemIndex] < allValues.Length);
                        Debug.Assert(itemsPt[itemIndex + 1] < allValues.Length);
                        Debug.Assert(itemsPt[itemIndex + 2] < allValues.Length);
                        Debug.Assert(itemsPt[itemIndex + 3] < allValues.Length);

                        passVal[padIndex] = (uint)((valPt[itemsPt[itemIndex]] << 24) |
                                                   (valPt[itemsPt[itemIndex + 1]] << 16) |
                                                   (valPt[itemsPt[itemIndex + 2]] << 8) |
                                                    valPt[itemsPt[itemIndex + 3]]);
                    }
                    uint val = 0;
                    int shift = 24;
                    while (itemIndex < items.Length)
                    {
                        Debug.Assert(shift > 0);
                        Debug.Assert(itemsPt[itemIndex] < allValues.Length);

                        val |= (uint)(valPt[itemsPt[itemIndex]] << shift);
                        itemIndex++;
                        shift -= 8;
                    }
                    passVal[padIndex] = val;

                    // Compress first block (64 byte inner pad)
                    Sha256Fo.Init(pt);
                    *(Block64*)wPt = *(Block64*)ipadSource;
                    for (int i = 0; i < passValues.Length; i++)
                    {
                        wPt[i] ^= passVal[i];
                    }
                    Sha256Fo.SetW(wPt);
                    Sha256Fo.CompressBlockWithWSet(pt);
                    // Store hashstate after compression of first block (inner-pad)
                    *(Block32*)iPtStore = *(Block32*)pt;

                    // Compress first block (64 byte outer pad)
                    Sha256Fo.Init(pt);
                    *(Block64*)wPt = *(Block64*)opadSource;
                    for (int i = 0; i < passValues.Length; i++)
                    {
                        wPt[i] ^= passVal[i];
                    }
                    Sha256Fo.SetW(wPt);
                    Sha256Fo.CompressBlockWithWSet(pt);
                    // Store hashstate after compression of first block (inner-pad)
                    *(Block32*)oPtStore = *(Block32*)pt;


                    uint* dPt = dkPt;
                    for (uint i = 1; i <= 256; i++)
                    {
                        // HMACSHA256(key=pass, msg=salt|i)
                        // compute u1 = hmac.ComputeHash(data=salt|i, key=pass);
                        //         u1 = SHA256(outer_pad | SHA256(inner_pad | salt | i ))
                        // result = u1 | u1 | u1 ...

                        // Set hashstate after first block compression (inner pad)
                        *(Block32*)pt = *(Block32*)iPtStore;

                        // Compress second block (4 byte salt | 4 byte i)
                        wPt[0] = saltUint;
                        wPt[1] = i;
                        wPt[2] = 0x80000000;
                        wPt[3] = 0;
                        wPt[4] = 0;
                        wPt[5] = 0;
                        wPt[6] = 0;
                        wPt[7] = 0;
                        wPt[8] = 0;
                        wPt[9] = 0;
                        wPt[10] = 0;
                        wPt[11] = 0;
                        wPt[12] = 0;
                        wPt[13] = 0;
                        wPt[14] = 0;
                        wPt[15] = (64 + 4 + 4) * 8; // = 576
                        Sha256Fo.Compress72SecondBlock(pt);

                        // Copy hashstate to wPt (to compute outer hash). **The order of following 2 lines is important**
                        *(Block32*)wPt = *(Block32*)pt;
                        // Set hashstate after first block compression (outer pad)
                        *(Block32*)pt = *(Block32*)oPtStore;
                        wPt[8] = 0x80000000;
                        wPt[9] = 0;
                        wPt[10] = 0;
                        wPt[11] = 0;
                        wPt[12] = 0;
                        wPt[13] = 0;
                        wPt[14] = 0;
                        wPt[15] = (64 + 32) * 8; // 768
                        Sha256Fo.Compress96SecondBlock(pt);

                        // Store hashstate in dk in reverse endian
                        dPt[0] = (pt[0] >> 24) | (pt[0] << 24) | ((pt[0] >> 8) & 0xff00) | ((pt[0] << 8) & 0xff0000);
                        dPt[1] = (pt[1] >> 24) | (pt[1] << 24) | ((pt[1] >> 8) & 0xff00) | ((pt[1] << 8) & 0xff0000);
                        dPt[2] = (pt[2] >> 24) | (pt[2] << 24) | ((pt[2] >> 8) & 0xff00) | ((pt[2] << 8) & 0xff0000);
                        dPt[3] = (pt[3] >> 24) | (pt[3] << 24) | ((pt[3] >> 8) & 0xff00) | ((pt[3] << 8) & 0xff0000);
                        dPt[4] = (pt[4] >> 24) | (pt[4] << 24) | ((pt[4] >> 8) & 0xff00) | ((pt[4] << 8) & 0xff0000);
                        dPt[5] = (pt[5] >> 24) | (pt[5] << 24) | ((pt[5] >> 8) & 0xff00) | ((pt[5] << 8) & 0xff0000);
                        dPt[6] = (pt[6] >> 24) | (pt[6] << 24) | ((pt[6] >> 8) & 0xff00) | ((pt[6] << 8) & 0xff0000);
                        dPt[7] = (pt[7] >> 24) | (pt[7] << 24) | ((pt[7] >> 8) & 0xff00) | ((pt[7] << 8) & 0xff0000);
                        dPt += 8;
                    }


                    // Scrypt
                    dPt = dkPt;
                    for (int i = 0; i < 8; i++)
                    {
                        ROMIX(dPt, vPt);
                        dPt += 256;
                    }


                    // * Second PBKDF2 (blockcount=2, dkLen=64, password=pass, salt=dk_8192)
                    // With iteration=1 there is no loop, only multiple hashes to fill the dk 32 bytes at a time (2x)
                    dPt = dkPt;
                    for (uint i = 1; i <= 2; i++)
                    {
                        // HMACSHA256(key=pass, msg=dk|i)
                        // compute u1 = hmac.ComputeHash(data=dk|i, key=pass);
                        //         u1 = SHA256(outer_pad | SHA256(inner_pad | dk | i ))
                        // result = u1 | u1

                        // Set hashstate after first block compression (inner pad)
                        *(Block32*)pt = *(Block32*)iPtStore;

                        // Compress next blocks (8192 byte salt | 4 byte i)
                        for (int m = 0; m < 128; m++)
                        {
                            *(Block64*)wPt = *(Block64*)(dPt + (m * 16));
                            Sha256Fo.SetW(wPt);
                            Sha256Fo.CompressBlockWithWSet(pt);
                        }
                        wPt[0] = i;
                        wPt[1] = 0x80000000;
                        wPt[2] = 0;
                        wPt[3] = 0;
                        wPt[4] = 0;
                        wPt[5] = 0;
                        wPt[6] = 0;
                        wPt[7] = 0;
                        wPt[8] = 0;
                        wPt[9] = 0;
                        wPt[10] = 0;
                        wPt[11] = 0;
                        wPt[12] = 0;
                        wPt[13] = 0;
                        wPt[14] = 0;
                        wPt[15] = (64 + 8192 + 4) * 8; // = 8260*8 = 66080
                        Sha256Fo.Compress8260FinalBlock(pt, i);

                        // Copy hashstate to wPt (to compute outer hash). **The order of following 2 lines is important**
                        *(Block32*)wPt = *(Block32*)pt;
                        // Set hashstate after first block compression (outer pad)
                        *(Block32*)pt = *(Block32*)oPtStore;
                        wPt[8] = 0x80000000;
                        wPt[9] = 0;
                        wPt[10] = 0;
                        wPt[11] = 0;
                        wPt[12] = 0;
                        wPt[13] = 0;
                        wPt[14] = 0;
                        wPt[15] = (64 + 32) * 8; // 768
                        Sha256Fo.Compress96SecondBlock(pt);

                        *(Block32*)final = *(Block32*)pt;
                        final += 8;
                    }

                    final -= 16;

                    aes.Key = new byte[32]
                    {
                        (byte)(final[8] >> 24), (byte)(final[8] >> 16), (byte)(final[8] >> 8), (byte)final[8],
                        (byte)(final[9] >> 24), (byte)(final[9] >> 16), (byte)(final[9] >> 8), (byte)final[9],
                        (byte)(final[10] >> 24), (byte)(final[10] >> 16), (byte)(final[10] >> 8), (byte)final[10],
                        (byte)(final[11] >> 24), (byte)(final[11] >> 16), (byte)(final[11] >> 8), (byte)final[11],
                        (byte)(final[12] >> 24), (byte)(final[12] >> 16), (byte)(final[12] >> 8), (byte)final[12],
                        (byte)(final[13] >> 24), (byte)(final[13] >> 16), (byte)(final[13] >> 8), (byte)final[13],
                        (byte)(final[14] >> 24), (byte)(final[14] >> 16), (byte)(final[14] >> 8), (byte)final[14],
                        (byte)(final[15] >> 24), (byte)(final[15] >> 16), (byte)(final[15] >> 8), (byte)final[15],
                    };

                    using ICryptoTransform decryptor = aes.CreateDecryptor();
                    byte[] decryptedResult = new byte[32];
                    decryptor.TransformBlock(data, 0, 16, decryptedResult, 0);
                    decryptor.TransformBlock(data, 16, 16, decryptedResult, 16);

                    for (int i = 0, j = 0; i < decryptedResult.Length; i += 4, j++)
                    {
                        decryptedResult[i] ^= (byte)(final[j] >> 24);
                        decryptedResult[i + 1] ^= (byte)(final[j] >> 16);
                        decryptedResult[i + 2] ^= (byte)(final[j] >> 8);
                        decryptedResult[i + 3] ^= (byte)final[j];
                    }

                    Scalar key = new(decryptedResult, out int overflow);
                    if (overflow == 0 && localComparer.Compare(comparer.Calc2.MultiplyByG(key)))
                    {
                        loopState.Stop();
                        report.FoundAnyResult = true;

                        char[] temp = new char[passLength];
                        for (int i = 0; i < temp.Length; i++)
                        {
                            temp[i] = (char)valPt[itemsPt[i]];
                        }

                        report.AddMessageSafe($"Password is: {new string(temp)}");
                        return;
                    }

                } while (ParallelMoveNext(itemsPt, items.Length, allValues.Length));
            }

            report.IncrementProgress();
        }

        private static unsafe void ROMIX(uint* dPt, uint* vPt)
        {
            Buffer.MemoryCopy(dPt, vPt, 1024, 1024);

            uint* srcPt = vPt;
            uint* dstPt = vPt + 256;

            // Set V1 to final V(n-1)
            for (int i = 0; i < 16383 /*=(n-1)*/; i++)
            {
                BlockMix(srcPt, dstPt);
                srcPt += 256;
                dstPt += 256;
            }

            uint[] x = new uint[256];
            uint[] xClone = new uint[256];
            fixed (uint* xPt = &x[0], xClPt = &xClone[0])
            {
                BlockMix(srcPt, xPt);

                for (int i = 0; i < 16384; i++)
                {
                    int j = (int)(xPt[x.Length - 16] & 16383);
                    XOR(xPt, vPt + (j * 256), x.Length);

                    BlockMix(xPt, xClPt);
                    Buffer.BlockCopy(xClone, 0, x, 0, 1024);
                }

                // Swap endian
                for (int i = 0; i < 256; i++)
                {
                    dPt[i] = (xPt[i] >> 24) | (xPt[i] << 24) | ((xPt[i] >> 8) & 0xff00) | ((xPt[i] << 8) & 0xff0000);
                }
            }
        }

        private static unsafe void BlockMix(uint* srcPt, uint* dstPt)
        {
            uint[] blockMixBuffer = new uint[16];
            fixed (uint* xPt = &blockMixBuffer[0])
            {
                *(Block64*)xPt = *(Block64*)(srcPt + 256 - 16);

                uint* block = srcPt;

                int i1 = 0;
                int i2 = 8 * 16;
                for (int i = 0; i < 2 * 8; i++)
                {
                    XOR(xPt, block, 16);
                    Salsa20_8(xPt);

                    if ((i & 1) == 0)
                    {
                        *(Block64*)(dstPt + i1) = *(Block64*)xPt;
                        i1 += 16;
                    }
                    else
                    {
                        *(Block64*)(dstPt + i2) = *(Block64*)xPt;
                        i2 += 16;
                    }

                    block += 16;
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe void XOR(uint* first, uint* second, int uLen)
        {
            for (int i = 0; i < uLen; i++)
            {
                first[i] ^= second[i];
            }
        }

        private static unsafe void Salsa20_8(uint* block)
        {
            uint x0 = block[0];
            uint x1 = block[1];
            uint x2 = block[2];
            uint x3 = block[3];
            uint x4 = block[4];
            uint x5 = block[5];
            uint x6 = block[6];
            uint x7 = block[7];
            uint x8 = block[8];
            uint x9 = block[9];
            uint x10 = block[10];
            uint x11 = block[11];
            uint x12 = block[12];
            uint x13 = block[13];
            uint x14 = block[14];
            uint x15 = block[15];

            for (int i = 0; i < 4; i++)
            {
                x4 ^= R(x0 + x12, 7); x8 ^= R(x4 + x0, 9);
                x12 ^= R(x8 + x4, 13); x0 ^= R(x12 + x8, 18);
                x9 ^= R(x5 + x1, 7); x13 ^= R(x9 + x5, 9);
                x1 ^= R(x13 + x9, 13); x5 ^= R(x1 + x13, 18);
                x14 ^= R(x10 + x6, 7); x2 ^= R(x14 + x10, 9);
                x6 ^= R(x2 + x14, 13); x10 ^= R(x6 + x2, 18);
                x3 ^= R(x15 + x11, 7); x7 ^= R(x3 + x15, 9);
                x11 ^= R(x7 + x3, 13); x15 ^= R(x11 + x7, 18);

                x1 ^= R(x0 + x3, 7); x2 ^= R(x1 + x0, 9);
                x3 ^= R(x2 + x1, 13); x0 ^= R(x3 + x2, 18);
                x6 ^= R(x5 + x4, 7); x7 ^= R(x6 + x5, 9);
                x4 ^= R(x7 + x6, 13); x5 ^= R(x4 + x7, 18);
                x11 ^= R(x10 + x9, 7); x8 ^= R(x11 + x10, 9);
                x9 ^= R(x8 + x11, 13); x10 ^= R(x9 + x8, 18);
                x12 ^= R(x15 + x14, 7); x13 ^= R(x12 + x15, 9);
                x14 ^= R(x13 + x12, 13); x15 ^= R(x14 + x13, 18);
            }

            block[0] += x0;
            block[1] += x1;
            block[2] += x2;
            block[3] += x3;
            block[4] += x4;
            block[5] += x5;
            block[6] += x6;
            block[7] += x7;
            block[8] += x8;
            block[9] += x9;
            block[10] += x10;
            block[11] += x11;
            block[12] += x12;
            block[13] += x13;
            block[14] += x14;
            block[15] += x15;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint R(uint a, int b) => unchecked((a << b) | (a >> (32 - b)));


        private void StartParallel(byte[] data, byte[] salt, bool isComp, byte[] allValues, int passLength)
        {
            report.SetProgressStep(allValues.Length);
            Parallel.For(0, allValues.Length,
                    (firstItem, state) => MainLoop(data, salt, isComp, allValues, passLength, firstItem, state));
        }

        private static bool TrySetAllPassValues(PasswordType type, out byte[] allValues)
        {
            string temp = string.Empty;
            if (type.HasFlag(PasswordType.UpperCase))
            {
                temp += ConstantsFO.UpperCase;
            }
            if (type.HasFlag(PasswordType.LowerCase))
            {
                temp += ConstantsFO.LowerCase;
            }
            if (type.HasFlag(PasswordType.Numbers))
            {
                temp += ConstantsFO.Numbers;
            }
            if (type.HasFlag(PasswordType.Symbols))
            {
                temp += ConstantsFO.AllSymbols;
            }
            if (type.HasFlag(PasswordType.Space))
            {
                temp += " ";
            }

            allValues = Encoding.UTF8.GetBytes(temp);

            return allValues != null && allValues.Length != 0;
        }

        public async void Find(string bip38, string extra, InputType extraType, int passLength, byte[] allValues)
        {
            report.Init();

            // I don't think anyone has a 1 char password so we take the lazy route and reject it (at least for now)
            if (passLength <= 1)
                report.Fail("Passwords smaller than 1 byte are not supported.");
            // Passwords bigger than 64 bytes need to be hashed first inside HMACSHA256 so we needa different MainLoop code
            if (passLength > Sha256Fo.BlockByteSize)
                report.Fail("Passwords bigger than 64 bytes are not supported yet.");
            if (!inputService.CheckBase58Bip38(bip38, out string msg))
                report.Fail(msg);
            if (!inputService.TryGetCompareService(extraType, extra, out comparer))
                report.Fail($"Invalid compare string or compare string type ({extraType}).");
            else if (!inputService.TryDecodeBip38(bip38, out byte[] data, out byte[] salt, out bool isComp, out string error))
                report.Fail(error);
            else
            {
                report.SetTotal(allValues.Length, passLength);
                report.Timer.Start();

                await Task.Run(() => StartParallel(data, salt, isComp, allValues, passLength));

                report.Finalize();
            }
        }
    }
}
