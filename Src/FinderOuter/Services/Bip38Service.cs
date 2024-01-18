// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using Autarkysoft.Bitcoin.Cryptography.EllipticCurve;
using FinderOuter.Backend.Hashing;
using FinderOuter.Models;
using FinderOuter.Services.Comparers;
using FinderOuter.Services.SearchSpaces;
using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace FinderOuter.Services
{
    public class Bip38Service
    {
        public Bip38Service(IReport rep)
        {
            report = rep;
        }


        private readonly IReport report;
        private ICompareService comparer;
        private PasswordSearchSpace searchSpace;


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

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static unsafe bool MoveNext(PermutationVar* items, int len)
        {
            for (int i = len - 1; i >= 0; i--)
            {
                if (items[i].Increment())
                {
                    return true;
                }
            }

            return false;
        }

        public unsafe void MainLoop(int firstItem, ParallelLoopState loopState)
        {
            Debug.Assert(searchSpace.PasswordLength <= Sha256Fo.BlockByteSize);

            // The whole process:
            // dk = Scrypt(cost-param=16384, blockSizeFactor=8, parallelization=8).Derive(pass, salt, dkLen=64)
            //    dk'=PBKDF2(HMACSHA256,iteration=1).Derive(pass,salt, dkLen=8192)
            //    dk"=ROMIX(dk')
            //    dk =PBKDF2(HMACSHA256,iteration=1).Derive(pass,dk",dkLen=64)
            // decrypted = AES(key=dk[32:64]).decrypt(ECB,256,IV=null,nopadding)
            // key = decrypted ^ dk[0:32]

            using Aes aes = Aes.Create();
            aes.KeySize = 256;
            aes.Mode = CipherMode.ECB;
            aes.IV = new byte[16];
            aes.Padding = PaddingMode.None;

            uint saltUint = searchSpace.salt;
            ICompareService localComparer = comparer.Clone();

            PermutationVar[] items = new PermutationVar[searchSpace.PasswordLength];
            Span<byte> passBa = new byte[searchSpace.MaxPasswordSize];
            Debug.Assert(passBa.Length % 4 == 0);
            Span<uint> passUa = new uint[passBa.Length / 4];

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

            fixed (byte* passBaPt = &passBa[0], allVals = &searchSpace.AllValues[0])
            fixed (int* lens = &searchSpace.PermutationLengths[0], sizePt = &searchSpace.PermutationSizes[0])
            fixed (PermutationVar* itemsPt = &items[0])
            fixed (uint* ipadSource = &InnerPads[0], opadSource = &OuterPads[0])
            fixed (uint* vPt = &v[0], dkPt = &derivedKey[0], passUaPt = &passUa[0])
            {
                byte* tvals = allVals;
                int* tlens = lens;
                for (int i = 0; i < items.Length; i++)
                {
                    int size = searchSpace.PermutationCounts[i];
                    items[i] = new PermutationVar(size, tvals, tlens);
                    tvals += sizePt[i];
                    tlens += size;
                }

                for (int i = 0; i < firstItem; i++)
                {
#if DEBUG
                    bool b =
#endif
                    itemsPt[0].Increment();
#if DEBUG
                    Debug.Assert(b);
#endif
                }

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

                    passBa.Clear();
                    passUa.Clear();
                    int totalPassLen = 0;
                    foreach (var item in items)
                    {
                        totalPassLen += item.WriteValue(passBaPt + totalPassLen, passBa.Length);
                    }
                    Debug.Assert(totalPassLen <= searchSpace.MaxPasswordSize);
                    // TODO: merge the following 2 loops? wPt[i] ^= (passBaPt[j] << 24) ...
                    for (int i = 0, j = 0; i < passUa.Length; i++, j += 4)
                    {
                        Debug.Assert(j + 3 < passBa.Length);
                        passUaPt[i] = (uint)((passBaPt[j] << 24) |
                                             (passBaPt[j + 1] << 16) |
                                             (passBaPt[j + 2] << 8) |
                                              passBaPt[j + 3]);
                    }

                    // Compress first block (64 byte inner pad)
                    Sha256Fo.Init(pt);
                    *(Block64*)wPt = *(Block64*)ipadSource;
                    for (int i = 0; i < passUa.Length; i++)
                    {
                        wPt[i] ^= passUaPt[i];
                    }
                    Sha256Fo.SetW(wPt);
                    Sha256Fo.CompressBlockWithWSet(pt);
                    // Store hashstate after compression of first block (inner-pad)
                    *(Block32*)iPtStore = *(Block32*)pt;

                    // Compress first block (64 byte outer pad)
                    Sha256Fo.Init(pt);
                    *(Block64*)wPt = *(Block64*)opadSource;
                    for (int i = 0; i < passUa.Length; i++)
                    {
                        wPt[i] ^= passUaPt[i];
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


                    // * Scrypt
                    dPt = dkPt;
                    for (int i = 0; i < 8; i++)
                    {
                        ROMIX_16384(dPt, vPt);
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
                    decryptor.TransformBlock(searchSpace.encryptedBA, 0, 16, decryptedResult, 0);
                    decryptor.TransformBlock(searchSpace.encryptedBA, 16, 16, decryptedResult, 16);

                    for (int i = 0, j = 0; i < decryptedResult.Length; i += 4, j++)
                    {
                        decryptedResult[i] ^= (byte)(final[j] >> 24);
                        decryptedResult[i + 1] ^= (byte)(final[j] >> 16);
                        decryptedResult[i + 2] ^= (byte)(final[j] >> 8);
                        decryptedResult[i + 3] ^= (byte)final[j];
                    }

                    Scalar8x32 key = new(decryptedResult, out bool overflow);
                    if (!overflow && localComparer.Compare(comparer.Calc.MultiplyByG(key)))
                    {
                        loopState.Stop();
                        report.FoundAnyResult = true;

                        char[] temp = new char[totalPassLen];
                        for (int i = 0; i < temp.Length; i++)
                        {
                            temp[i] = (char)passBaPt[i];
                        }

                        report.AddMessageSafe($"Password is: {new string(temp)}");
                        return;
                    }

                } while (MoveNext(itemsPt + 1, items.Length - 1));
            }

            report.IncrementProgress();
        }


        public unsafe void MainLoopECLot(int firstItem, ParallelLoopState loopState)
        {
            Debug.Assert(searchSpace.PasswordLength <= Sha256Fo.BlockByteSize);

            // The whole process:
            // dk1 = Scrypt(cost-param=16384, blockSizeFactor=8, parallelization=8).Derive(pass, data[0:4], dkLen=32)
            //     dk'=PBKDF2(HMACSHA256,iteration=1).Derive(pass,salt_4, dkLen=8192)
            //     dk"=ROMIX(dk')
            //     dk =PBKDF2(HMACSHA256,iteration=1).Derive(pass,dk",dkLen=32)
            // passFactor = SHA256(SHA256(dk1 | data[0:8]))
            // ****** The rest is similar with or without Lot/sequence
            // passPoint = passFactor * G
            // dk2 = Scrypt(cost-param=1024, blockSizeFactor=1, parallelization=1).Derive(passPoint, salt(4)|data[0:8], dkLen=64)
            //     dk'=PBKDF2(HMACSHA256,iteration=1).Derive(passPoint_33,salt_12, dkLen=128)
            //     dk"=ROMIX(dk')
            //     dk =PBKDF2(HMACSHA256,iteration=1).Derive(passPoint_33,dk",dkLen=64)
            // AES.key = dk2[32:64]
            // decrypted1 = AES.decrypt(data[16:32])                  XOR   dk2[16:32]
            // decrypted2 = AES.decrypt(data[8:16] | decrypted1[0:8]) XOR   dk2[0:16]
            // seedb = decrypted2[0:16] | decrypted1[8:16]
            // factorb = SHA256(SHA256(seedb_24))
            // key = (passFactor * factorb) % n

            using Aes aes = Aes.Create();
            aes.KeySize = 256;
            aes.Mode = CipherMode.ECB;
            aes.IV = new byte[16];
            aes.Padding = PaddingMode.None;


            uint saltUint0 = searchSpace.salt;
            uint saltUint1 = (uint)(searchSpace.encryptedBA[0] << 24 | searchSpace.encryptedBA[1] << 16 |
                                    searchSpace.encryptedBA[2] << 8 | searchSpace.encryptedBA[3]);
            uint saltUint2 = (uint)(searchSpace.encryptedBA[4] << 24 | searchSpace.encryptedBA[5] << 16 |
                                    searchSpace.encryptedBA[6] << 8 | searchSpace.encryptedBA[7]);
            ICompareService localComparer = comparer.Clone();

            PermutationVar[] items = new PermutationVar[searchSpace.PasswordLength];
            Span<byte> passBa = new byte[searchSpace.MaxPasswordSize];
            Debug.Assert(passBa.Length % 4 == 0);
            Span<uint> passUa = new uint[passBa.Length / 4];

            // TODO: should these 2 arrays be merged?
            uint[] v = new uint[4194304];
            uint[] derivedKey = new uint[2048];

            // hashState(8)|workVector(64)|ipadSource(16)|opadSource(16)|ipadStore(8)|opadStore(8)|ipadStore2(8)|opadStore2(8)|final(16)
            // Total = 8+64+16+16+8+8+8+8+16 = 152*4 = 608 bytes
            uint* pt = stackalloc uint[Sha256Fo.UBufferSize + (2 * 16) + (4 * Sha256Fo.HashStateSize) + 16];
            uint* wPt = pt + Sha256Fo.HashStateSize;
            uint* ipadSource = wPt + Sha256Fo.WorkingVectorSize;
            uint* opadSource = ipadSource + 16;
            uint* iPtStore = opadSource + 16;
            uint* oPtStore = iPtStore + Sha256Fo.HashStateSize;
            uint* iPtStore2 = oPtStore + Sha256Fo.HashStateSize;
            uint* oPtStore2 = iPtStore2 + Sha256Fo.HashStateSize;
            uint* final = oPtStore2 + Sha256Fo.HashStateSize;

            for (int i = 0; i < 16; i++)
            {
                ipadSource[i] = 0x36363636U;
                opadSource[i] = 0x5c5c5c5cU;
            }

            fixed (byte* passBaPt = &passBa[0], allVals = &searchSpace.AllValues[0])
            fixed (int* lens = &searchSpace.PermutationLengths[0], sizePt = &searchSpace.PermutationSizes[0])
            fixed (PermutationVar* itemsPt = &items[0])
            fixed (uint* vPt = &v[0], dkPt = &derivedKey[0], passUaPt = &passUa[0])
            {
                byte* tvals = allVals;
                int* tlens = lens;
                for (int i = 0; i < items.Length; i++)
                {
                    int size = searchSpace.PermutationCounts[i];
                    items[i] = new PermutationVar(size, tvals, tlens);
                    tvals += sizePt[i];
                    tlens += size;
                }

                for (int i = 0; i < firstItem; i++)
                {
#if DEBUG
                    bool b =
#endif
                    itemsPt[0].Increment();
#if DEBUG
                    Debug.Assert(b);
#endif
                }

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
                    passBa.Clear();
                    passUa.Clear();
                    int totalPassLen = 0;
                    foreach (var item in items)
                    {
                        totalPassLen += item.WriteValue(passBaPt + totalPassLen, passBa.Length);
                    }
                    Debug.Assert(totalPassLen <= searchSpace.MaxPasswordSize);
                    // TODO: merge the following 2 loops? wPt[i] ^= (passBaPt[j] << 24) ...
                    for (int i = 0, j = 0; i < passUa.Length; i++, j += 4)
                    {
                        Debug.Assert(j + 3 < passBa.Length);
                        passUaPt[i] = (uint)((passBaPt[j] << 24) |
                                             (passBaPt[j + 1] << 16) |
                                             (passBaPt[j + 2] << 8) |
                                              passBaPt[j + 3]);
                    }

                    // Compress first block (64 byte inner pad)
                    Sha256Fo.Init(pt);
                    *(Block64*)wPt = *(Block64*)ipadSource;
                    for (int i = 0; i < passUa.Length; i++)
                    {
                        wPt[i] ^= passUaPt[i];
                    }
                    Sha256Fo.SetW(wPt);
                    Sha256Fo.CompressBlockWithWSet(pt);
                    // Store hashstate after compression of first block (inner-pad)
                    *(Block32*)iPtStore = *(Block32*)pt;

                    // Compress first block (64 byte outer pad)
                    Sha256Fo.Init(pt);
                    *(Block64*)wPt = *(Block64*)opadSource;
                    for (int i = 0; i < passUa.Length; i++)
                    {
                        wPt[i] ^= passUaPt[i];
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
                        wPt[0] = saltUint1;
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


                    // * Scrypt 1
                    dPt = dkPt;
                    for (int i = 0; i < 8; i++)
                    {
                        ROMIX_16384(dPt, vPt);
                        dPt += 256;
                    }


                    // * Second PBKDF2 (blockcount=1, dkLen=32, password=pass, salt=dk_8192)
                    // With iteration=1 there is no loop, with 1 block only 1 hash to fill the dk 32 bytes
                    dPt = dkPt;
                    // HMACSHA256(key=pass, msg=dk|i)
                    // compute u1 = hmac.ComputeHash(data=dk|i, key=pass);
                    //         u1 = SHA256(outer_pad | SHA256(inner_pad | dk | i ))
                    // result = u1

                    // Set hashstate after first block compression (inner pad)
                    *(Block32*)pt = *(Block32*)iPtStore;

                    // Compress next blocks (8192 byte salt | 4 byte i)
                    for (int m = 0; m < 128; m++)
                    {
                        *(Block64*)wPt = *(Block64*)(dPt + (m * 16));
                        Sha256Fo.SetW(wPt);
                        Sha256Fo.CompressBlockWithWSet(pt);
                    }
                    wPt[0] = 1;
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
                    Sha256Fo.Compress8260FinalBlock_1(pt);

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

                    // passFactor is double SHA256 of (pt | data[0:8])
                    *(Block32*)wPt = *(Block32*)pt;
                    wPt[8] = saltUint1;
                    wPt[9] = saltUint2;
                    wPt[10] = 0x80000000;
                    wPt[11] = 0;
                    wPt[12] = 0;
                    wPt[13] = 0;
                    wPt[14] = 0;
                    wPt[15] = (32 + 8) * 8; // 320
                    Sha256Fo.Init(pt);
                    Sha256Fo.CompressDouble40(pt);

                    // pt is now passFactor
                    // pt is now passFactor
                    Scalar8x32 passFactor = new(pt, out bool overflow);
                    if (overflow)
                    {
                        continue;
                    }
                    Span<byte> passPoint = localComparer.Calc.MultiplyByG(passFactor).ToPoint().ToByteArray(true);


                    // * Third PBKDF2 (blockcount=4, dkLen=128, password=passPoint_33, salt=salt_12)
                    // With iteration=1 there is no loop, only multiple hashes to fill the dk 32 bytes at a time (4x)
                    fixed (byte* temp = &passPoint[0])
                    {
                        // Like before HMAC key (sets pads) is fixed (33 byte passPoint) and is fixed for both PBKDF2 calls.
                        // HashStates are stored in second storages (the first one is going to be reused in the main loop).
                        uint u0 = (uint)((temp[0] << 24) | (temp[1] << 16) | (temp[2] << 8) | temp[3]);
                        uint u1 = (uint)((temp[4] << 24) | (temp[5] << 16) | (temp[6] << 8) | temp[7]);
                        uint u2 = (uint)((temp[8] << 24) | (temp[9] << 16) | (temp[10] << 8) | temp[11]);
                        uint u3 = (uint)((temp[12] << 24) | (temp[13] << 16) | (temp[14] << 8) | temp[15]);
                        uint u4 = (uint)((temp[16] << 24) | (temp[17] << 16) | (temp[18] << 8) | temp[19]);
                        uint u5 = (uint)((temp[20] << 24) | (temp[21] << 16) | (temp[22] << 8) | temp[23]);
                        uint u6 = (uint)((temp[24] << 24) | (temp[25] << 16) | (temp[26] << 8) | temp[27]);
                        uint u7 = (uint)((temp[28] << 24) | (temp[29] << 16) | (temp[30] << 8) | temp[31]);
                        uint u8 = (uint)temp[32] << 24;

                        // Compress first block (64 byte inner pad)
                        Sha256Fo.Init(pt);
                        *(Block64*)wPt = *(Block64*)ipadSource;
                        wPt[0] ^= u0;
                        wPt[1] ^= u1;
                        wPt[2] ^= u2;
                        wPt[3] ^= u3;
                        wPt[4] ^= u4;
                        wPt[5] ^= u5;
                        wPt[6] ^= u6;
                        wPt[7] ^= u7;
                        wPt[8] ^= u8;
                        Sha256Fo.SetW(wPt);
                        Sha256Fo.CompressBlockWithWSet(pt);
                        // Store hashstate after compression of first block (inner-pad)
                        *(Block32*)iPtStore2 = *(Block32*)pt;

                        // Compress first block (64 byte outer pad)
                        Sha256Fo.Init(pt);
                        *(Block64*)wPt = *(Block64*)opadSource;
                        wPt[0] ^= u0;
                        wPt[1] ^= u1;
                        wPt[2] ^= u2;
                        wPt[3] ^= u3;
                        wPt[4] ^= u4;
                        wPt[5] ^= u5;
                        wPt[6] ^= u6;
                        wPt[7] ^= u7;
                        wPt[8] ^= u8;
                        Sha256Fo.SetW(wPt);
                        Sha256Fo.CompressBlockWithWSet(pt);
                        // Store hashstate after compression of first block (inner-pad)
                        *(Block32*)oPtStore2 = *(Block32*)pt;
                    }

                    dPt = dkPt;
                    for (uint i = 1; i <= 4; i++)
                    {
                        // HMACSHA256(key=passPoint_33, msg=salt_12|i)
                        // compute u1 = hmac.ComputeHash(data=salt_12|i, key=passPoint_33);
                        //         u1 = SHA256(outer_pad | SHA256(inner_pad | salt_12 | i ))
                        // result = u1 | u1 | u1 | u1

                        // Set hashstate after first block compression (inner pad)
                        *(Block32*)pt = *(Block32*)iPtStore2;

                        // Compress second block (12 byte salt | 4 byte i)
                        wPt[0] = saltUint0;
                        wPt[1] = saltUint1;
                        wPt[2] = saltUint2;
                        wPt[3] = i;
                        wPt[4] = 0x80000000;
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
                        wPt[15] = (64 + 12 + 4) * 8; // = 640
                        Sha256Fo.Compress80SecondBlock(pt);

                        // Copy hashstate to wPt (to compute outer hash). **The order of following 2 lines is important**
                        *(Block32*)wPt = *(Block32*)pt;
                        // Set hashstate after first block compression (outer pad)
                        *(Block32*)pt = *(Block32*)oPtStore2;
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


                    // * Scrypt 2
                    dPt = dkPt;
                    ROMIX_1024(dPt, vPt);


                    // * Fourth PBKDF2 (blockcount=2, dkLen=64, password=pass, salt=dk_128)
                    // With iteration=1 there is no loop, only multiple hashes to fill the dk 32 bytes at a time (2x)
                    dPt = dkPt;
                    for (uint i = 1; i <= 2; i++)
                    {
                        // HMACSHA256(key=pass, msg=dk|i)
                        // compute u1 = hmac.ComputeHash(data=dk|i, key=pass);
                        //         u1 = SHA256(outer_pad | SHA256(inner_pad | dk | i ))
                        // result = u1 | u1

                        // Set hashstate after first block compression (inner pad)
                        *(Block32*)pt = *(Block32*)iPtStore2;

                        // Compress next blocks (128 byte salt | 4 byte i)
                        for (int m = 0; m < 2; m++)
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
                        wPt[15] = (64 + 128 + 4) * 8; // = 196*8 = 1568
                        Sha256Fo.Compress196FinalBlock(pt, i);

                        // Copy hashstate to wPt (to compute outer hash). **The order of following 2 lines is important**
                        *(Block32*)wPt = *(Block32*)pt;
                        // Set hashstate after first block compression (outer pad)
                        *(Block32*)pt = *(Block32*)oPtStore2;
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

                    // TODO: decryptedResult, encryptedPart1, decryptedPart1 and seedb should be allocated outside
                    //       the loop if possible
                    using ICryptoTransform decryptor = aes.CreateDecryptor();
                    byte[] decryptedResult = new byte[16];
                    decryptor.TransformBlock(searchSpace.encryptedBA, 16, 16, decryptedResult, 0);

                    for (int i = 0, j = 4; i < decryptedResult.Length; i += 4, j++)
                    {
                        decryptedResult[i] ^= (byte)(final[j] >> 24);
                        decryptedResult[i + 1] ^= (byte)(final[j] >> 16);
                        decryptedResult[i + 2] ^= (byte)(final[j] >> 8);
                        decryptedResult[i + 3] ^= (byte)final[j];
                    }

                    byte[] encryptedPart1 = new byte[16];
                    Buffer.BlockCopy(searchSpace.encryptedBA, 8, encryptedPart1, 0, 8);
                    Buffer.BlockCopy(decryptedResult, 0, encryptedPart1, 8, 8);

                    byte[] decryptedPart1 = new byte[16];
                    decryptor.TransformBlock(encryptedPart1, 0, 16, decryptedPart1, 0);

                    for (int i = 0, j = 0; i < decryptedPart1.Length; i += 4, j++)
                    {
                        decryptedPart1[i] ^= (byte)(final[j] >> 24);
                        decryptedPart1[i + 1] ^= (byte)(final[j] >> 16);
                        decryptedPart1[i + 2] ^= (byte)(final[j] >> 8);
                        decryptedPart1[i + 3] ^= (byte)final[j];
                    }

                    byte[] seedb = new byte[24];
                    Array.Copy(decryptedPart1, 0, seedb, 0, 16);
                    Array.Copy(decryptedResult, 8, seedb, 16, 8);

                    Sha256Fo.Init(pt);
                    wPt[0] = (uint)((seedb[0] << 24) | (seedb[1] << 16) | (seedb[2] << 8) | seedb[3]);
                    wPt[1] = (uint)((seedb[4] << 24) | (seedb[5] << 16) | (seedb[6] << 8) | seedb[7]);
                    wPt[2] = (uint)((seedb[8] << 24) | (seedb[9] << 16) | (seedb[10] << 8) | seedb[11]);
                    wPt[3] = (uint)((seedb[12] << 24) | (seedb[13] << 16) | (seedb[14] << 8) | seedb[15]);
                    wPt[4] = (uint)((seedb[16] << 24) | (seedb[17] << 16) | (seedb[18] << 8) | seedb[19]);
                    wPt[5] = (uint)((seedb[20] << 24) | (seedb[21] << 16) | (seedb[22] << 8) | seedb[23]);
                    wPt[6] = 0b10000000_00000000_00000000_00000000U;
                    wPt[7] = 0;
                    wPt[8] = 0;
                    wPt[9] = 0;
                    wPt[10] = 0;
                    wPt[11] = 0;
                    wPt[12] = 0;
                    wPt[13] = 0;
                    wPt[14] = 0;
                    wPt[15] = 24 * 8;
                    Sha256Fo.CompressDouble24(pt);

                    // pt is factorb
                    Scalar8x32 key = new Scalar8x32(pt, out _).Multiply(passFactor);

                    if (localComparer.Compare(localComparer.Calc.MultiplyByG(key)))
                    {
                        loopState.Stop();
                        report.FoundAnyResult = true;

                        char[] temp = new char[totalPassLen];
                        for (int i = 0; i < temp.Length; i++)
                        {
                            temp[i] = (char)passBaPt[i];
                        }

                        report.AddMessageSafe($"Password is: {new string(temp)}");
                        return;
                    }

                } while (MoveNext(itemsPt + 1, items.Length - 1));
            }

            report.IncrementProgress();
        }

        public unsafe void MainLoopECNoLot(int firstItem, ParallelLoopState loopState)
        {
            Debug.Assert(searchSpace.PasswordLength <= Sha256Fo.BlockByteSize);

            // The whole process:
            // dk1 = Scrypt(cost-param=16384, blockSizeFactor=8, parallelization=8).Derive(pass, data[0:8], dkLen=32)
            //     dk'=PBKDF2(HMACSHA256,iteration=1).Derive(pass,salt_8, dkLen=8192)
            //     dk"=ROMIX(dk')
            //     dk =PBKDF2(HMACSHA256,iteration=1).Derive(pass,dk",dkLen=32)
            // passFactor = dk1
            // ****** The rest is similar with or without Lot/sequence
            // passPoint = passFactor * G
            // dk2 = Scrypt(cost-param=1024, blockSizeFactor=1, parallelization=1).Derive(passPoint, salt(4)|data[0:8], dkLen=64)
            //     dk'=PBKDF2(HMACSHA256,iteration=1).Derive(passPoint_33,salt_12, dkLen=128)
            //     dk"=ROMIX(dk')
            //     dk =PBKDF2(HMACSHA256,iteration=1).Derive(passPoint_33,dk",dkLen=64)
            // AES.key = dk2[32:64]
            // decrypted1 = AES.decrypt(data[16:32])                  XOR   dk2[16:32]
            // decrypted2 = AES.decrypt(data[8:16] | decrypted1[0:8]) XOR   dk2[0:16]
            // seedb = decrypted2[0:16] | decrypted1[8:16]
            // factorb = SHA256(SHA256(seedb_24))
            // key = (passFactor * factorb) % n

            using Aes aes = Aes.Create();
            aes.KeySize = 256;
            aes.Mode = CipherMode.ECB;
            aes.IV = new byte[16];
            aes.Padding = PaddingMode.None;

            uint saltUint0 = searchSpace.salt;
            uint saltUint1 = (uint)(searchSpace.encryptedBA[0] << 24 | searchSpace.encryptedBA[1] << 16 |
                                    searchSpace.encryptedBA[2] << 8 | searchSpace.encryptedBA[3]);
            uint saltUint2 = (uint)(searchSpace.encryptedBA[4] << 24 | searchSpace.encryptedBA[5] << 16 |
                                    searchSpace.encryptedBA[6] << 8 | searchSpace.encryptedBA[7]);
            ICompareService localComparer = comparer.Clone();

            PermutationVar[] items = new PermutationVar[searchSpace.PasswordLength];
            Span<byte> passBa = new byte[searchSpace.MaxPasswordSize];
            Debug.Assert(passBa.Length % 4 == 0);
            Span<uint> passUa = new uint[passBa.Length / 4];

            // TODO: should these 2 arrays be merged?
            uint[] v = new uint[4194304];
            uint[] derivedKey = new uint[2048];

            // hashState(8)|workVector(64)|ipadSource(16)|opadSource(16)|ipadStore(8)|opadStore(8)|ipadStore2(8)|opadStore2(8)|final(16)
            // Total = 8+64+16+16+8+8+8+8+16 = 152*4 = 608 bytes
            uint* pt = stackalloc uint[Sha256Fo.UBufferSize + (2 * 16) + (4 * Sha256Fo.HashStateSize) + 16];
            uint* wPt = pt + Sha256Fo.HashStateSize;
            uint* ipadSource = wPt + Sha256Fo.WorkingVectorSize;
            uint* opadSource = ipadSource + 16;
            uint* iPtStore = opadSource + 16;
            uint* oPtStore = iPtStore + Sha256Fo.HashStateSize;
            uint* iPtStore2 = oPtStore + Sha256Fo.HashStateSize;
            uint* oPtStore2 = iPtStore2 + Sha256Fo.HashStateSize;
            uint* final = oPtStore2 + Sha256Fo.HashStateSize;

            for (int i = 0; i < 16; i++)
            {
                ipadSource[i] = 0x36363636U;
                opadSource[i] = 0x5c5c5c5cU;
            }

            fixed (byte* passBaPt = &passBa[0], allVals = &searchSpace.AllValues[0])
            fixed (int* lens = &searchSpace.PermutationLengths[0], sizePt = &searchSpace.PermutationSizes[0])
            fixed (PermutationVar* itemsPt = &items[0])
            fixed (uint* vPt = &v[0], dkPt = &derivedKey[0], passUaPt = &passUa[0])
            {
                byte* tvals = allVals;
                int* tlens = lens;
                for (int i = 0; i < items.Length; i++)
                {
                    int size = searchSpace.PermutationCounts[i];
                    items[i] = new PermutationVar(size, tvals, tlens);
                    tvals += sizePt[i];
                    tlens += size;
                }

                for (int i = 0; i < firstItem; i++)
                {
#if DEBUG
                    bool b =
#endif
                    itemsPt[0].Increment();
#if DEBUG
                    Debug.Assert(b);
#endif
                }


                do
                {
                    if (loopState.IsStopped)
                    {
                        return;
                    }
                    // * First PBKDF2 (blockcount=256, dkLen=8192, password=pass, salt=salt_8)
                    // With iteration=1 there is no loop, only multiple hashes to fill the dk 32 bytes at a time (256x)

                    // HMAC key (sets pads) is the password and is fixed for both PBKDF2 calls so we can set the pads
                    // and compute the hashstate after first block compression
                    passBa.Clear();
                    passUa.Clear();
                    int totalPassLen = 0;
                    foreach (var item in items)
                    {
                        totalPassLen += item.WriteValue(passBaPt + totalPassLen, passBa.Length);
                    }
                    Debug.Assert(totalPassLen <= searchSpace.MaxPasswordSize);
                    // TODO: merge the following 2 loops? wPt[i] ^= (passBaPt[j] << 24) ...
                    for (int i = 0, j = 0; i < passUa.Length; i++, j += 4)
                    {
                        Debug.Assert(j + 3 < passBa.Length);
                        passUaPt[i] = (uint)((passBaPt[j] << 24) |
                                             (passBaPt[j + 1] << 16) |
                                             (passBaPt[j + 2] << 8) |
                                              passBaPt[j + 3]);
                    }

                    // Compress first block (64 byte inner pad)
                    Sha256Fo.Init(pt);
                    *(Block64*)wPt = *(Block64*)ipadSource;
                    for (int i = 0; i < passUa.Length; i++)
                    {
                        wPt[i] ^= passUaPt[i];
                    }
                    Sha256Fo.SetW(wPt);
                    Sha256Fo.CompressBlockWithWSet(pt);
                    // Store hashstate after compression of first block (inner-pad)
                    *(Block32*)iPtStore = *(Block32*)pt;

                    // Compress first block (64 byte outer pad)
                    Sha256Fo.Init(pt);
                    *(Block64*)wPt = *(Block64*)opadSource;
                    for (int i = 0; i < passUa.Length; i++)
                    {
                        wPt[i] ^= passUaPt[i];
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

                        // Compress second block (8 byte salt | 4 byte i)
                        wPt[0] = saltUint1;
                        wPt[1] = saltUint2;
                        wPt[2] = i;
                        wPt[3] = 0x80000000;
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
                        wPt[15] = (64 + 8 + 4) * 8; // = 608
                        Sha256Fo.Compress76SecondBlock(pt);

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


                    // * Scrypt 1
                    dPt = dkPt;
                    for (int i = 0; i < 8; i++)
                    {
                        ROMIX_16384(dPt, vPt);
                        dPt += 256;
                    }


                    // * Second PBKDF2 (blockcount=1, dkLen=32, password=pass, salt=dk_8192)
                    // With iteration=1 there is no loop, with 1 block only 1 hash to fill the dk 32 bytes
                    dPt = dkPt;
                    // HMACSHA256(key=pass, msg=dk|i)
                    // compute u1 = hmac.ComputeHash(data=dk|i, key=pass);
                    //         u1 = SHA256(outer_pad | SHA256(inner_pad | dk | i ))
                    // result = u1

                    // Set hashstate after first block compression (inner pad)
                    *(Block32*)pt = *(Block32*)iPtStore;

                    // Compress next blocks (8192 byte salt | 4 byte i)
                    for (int m = 0; m < 128; m++)
                    {
                        *(Block64*)wPt = *(Block64*)(dPt + (m * 16));
                        Sha256Fo.SetW(wPt);
                        Sha256Fo.CompressBlockWithWSet(pt);
                    }
                    wPt[0] = 1;
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
                    Sha256Fo.Compress8260FinalBlock_1(pt);

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

                    // pt is now passFactor
                    Scalar8x32 passFactor = new(pt, out bool overflow);
                    if (overflow)
                    {
                        continue;
                    }
                    Span<byte> passPoint = localComparer.Calc.MultiplyByG(passFactor).ToPoint().ToByteArray(true);


                    // * Third PBKDF2 (blockcount=4, dkLen=128, password=passPoint_33, salt=salt_12)
                    // With iteration=1 there is no loop, only multiple hashes to fill the dk 32 bytes at a time (4x)
                    fixed (byte* temp = &passPoint[0])
                    {
                        // Like before HMAC key (sets pads) is fixed (33 byte passPoint) and is fixed for both PBKDF2 calls.
                        // HashStates are stored in second storages (the first one is going to be reused in the main loop).
                        uint u0 = (uint)((temp[0] << 24) | (temp[1] << 16) | (temp[2] << 8) | temp[3]);
                        uint u1 = (uint)((temp[4] << 24) | (temp[5] << 16) | (temp[6] << 8) | temp[7]);
                        uint u2 = (uint)((temp[8] << 24) | (temp[9] << 16) | (temp[10] << 8) | temp[11]);
                        uint u3 = (uint)((temp[12] << 24) | (temp[13] << 16) | (temp[14] << 8) | temp[15]);
                        uint u4 = (uint)((temp[16] << 24) | (temp[17] << 16) | (temp[18] << 8) | temp[19]);
                        uint u5 = (uint)((temp[20] << 24) | (temp[21] << 16) | (temp[22] << 8) | temp[23]);
                        uint u6 = (uint)((temp[24] << 24) | (temp[25] << 16) | (temp[26] << 8) | temp[27]);
                        uint u7 = (uint)((temp[28] << 24) | (temp[29] << 16) | (temp[30] << 8) | temp[31]);
                        uint u8 = (uint)temp[32] << 24;

                        // Compress first block (64 byte inner pad)
                        Sha256Fo.Init(pt);
                        *(Block64*)wPt = *(Block64*)ipadSource;
                        wPt[0] ^= u0;
                        wPt[1] ^= u1;
                        wPt[2] ^= u2;
                        wPt[3] ^= u3;
                        wPt[4] ^= u4;
                        wPt[5] ^= u5;
                        wPt[6] ^= u6;
                        wPt[7] ^= u7;
                        wPt[8] ^= u8;
                        Sha256Fo.SetW(wPt);
                        Sha256Fo.CompressBlockWithWSet(pt);
                        // Store hashstate after compression of first block (inner-pad)
                        *(Block32*)iPtStore2 = *(Block32*)pt;

                        // Compress first block (64 byte outer pad)
                        Sha256Fo.Init(pt);
                        *(Block64*)wPt = *(Block64*)opadSource;
                        wPt[0] ^= u0;
                        wPt[1] ^= u1;
                        wPt[2] ^= u2;
                        wPt[3] ^= u3;
                        wPt[4] ^= u4;
                        wPt[5] ^= u5;
                        wPt[6] ^= u6;
                        wPt[7] ^= u7;
                        wPt[8] ^= u8;
                        Sha256Fo.SetW(wPt);
                        Sha256Fo.CompressBlockWithWSet(pt);
                        // Store hashstate after compression of first block (inner-pad)
                        *(Block32*)oPtStore2 = *(Block32*)pt;
                    }

                    dPt = dkPt;
                    for (uint i = 1; i <= 4; i++)
                    {
                        // HMACSHA256(key=passPoint_33, msg=salt_12|i)
                        // compute u1 = hmac.ComputeHash(data=salt_12|i, key=passPoint_33);
                        //         u1 = SHA256(outer_pad | SHA256(inner_pad | salt_12 | i ))
                        // result = u1 | u1 | u1 | u1

                        // Set hashstate after first block compression (inner pad)
                        *(Block32*)pt = *(Block32*)iPtStore2;

                        // Compress second block (12 byte salt | 4 byte i)
                        wPt[0] = saltUint0;
                        wPt[1] = saltUint1;
                        wPt[2] = saltUint2;
                        wPt[3] = i;
                        wPt[4] = 0x80000000;
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
                        wPt[15] = (64 + 12 + 4) * 8; // = 640
                        Sha256Fo.Compress80SecondBlock(pt);

                        // Copy hashstate to wPt (to compute outer hash). **The order of following 2 lines is important**
                        *(Block32*)wPt = *(Block32*)pt;
                        // Set hashstate after first block compression (outer pad)
                        *(Block32*)pt = *(Block32*)oPtStore2;
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


                    // * Scrypt 2
                    dPt = dkPt;
                    ROMIX_1024(dPt, vPt);


                    // * Fourth PBKDF2 (blockcount=2, dkLen=64, password=pass, salt=dk_128)
                    // With iteration=1 there is no loop, only multiple hashes to fill the dk 32 bytes at a time (2x)
                    dPt = dkPt;
                    for (uint i = 1; i <= 2; i++)
                    {
                        // HMACSHA256(key=pass, msg=dk|i)
                        // compute u1 = hmac.ComputeHash(data=dk|i, key=pass);
                        //         u1 = SHA256(outer_pad | SHA256(inner_pad | dk | i ))
                        // result = u1 | u1

                        // Set hashstate after first block compression (inner pad)
                        *(Block32*)pt = *(Block32*)iPtStore2;

                        // Compress next blocks (128 byte salt | 4 byte i)
                        for (int m = 0; m < 2; m++)
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
                        wPt[15] = (64 + 128 + 4) * 8; // = 196*8 = 1568
                        Sha256Fo.Compress196FinalBlock(pt, i);

                        // Copy hashstate to wPt (to compute outer hash). **The order of following 2 lines is important**
                        *(Block32*)wPt = *(Block32*)pt;
                        // Set hashstate after first block compression (outer pad)
                        *(Block32*)pt = *(Block32*)oPtStore2;
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

                    // TODO: decryptedResult, encryptedPart1, decryptedPart1 and seedb should be allocated outside
                    //       the loop if possible
                    using ICryptoTransform decryptor = aes.CreateDecryptor();
                    byte[] decryptedResult = new byte[16];
                    decryptor.TransformBlock(searchSpace.encryptedBA, 16, 16, decryptedResult, 0);

                    for (int i = 0, j = 4; i < decryptedResult.Length; i += 4, j++)
                    {
                        decryptedResult[i] ^= (byte)(final[j] >> 24);
                        decryptedResult[i + 1] ^= (byte)(final[j] >> 16);
                        decryptedResult[i + 2] ^= (byte)(final[j] >> 8);
                        decryptedResult[i + 3] ^= (byte)final[j];
                    }

                    byte[] encryptedPart1 = new byte[16];
                    Buffer.BlockCopy(searchSpace.encryptedBA, 8, encryptedPart1, 0, 8);
                    Buffer.BlockCopy(decryptedResult, 0, encryptedPart1, 8, 8);

                    byte[] decryptedPart1 = new byte[16];
                    decryptor.TransformBlock(encryptedPart1, 0, 16, decryptedPart1, 0);

                    for (int i = 0, j = 0; i < decryptedPart1.Length; i += 4, j++)
                    {
                        decryptedPart1[i] ^= (byte)(final[j] >> 24);
                        decryptedPart1[i + 1] ^= (byte)(final[j] >> 16);
                        decryptedPart1[i + 2] ^= (byte)(final[j] >> 8);
                        decryptedPart1[i + 3] ^= (byte)final[j];
                    }

                    byte[] seedb = new byte[24];
                    Array.Copy(decryptedPart1, 0, seedb, 0, 16);
                    Array.Copy(decryptedResult, 8, seedb, 16, 8);

                    Sha256Fo.Init(pt);
                    wPt[0] = (uint)((seedb[0] << 24) | (seedb[1] << 16) | (seedb[2] << 8) | seedb[3]);
                    wPt[1] = (uint)((seedb[4] << 24) | (seedb[5] << 16) | (seedb[6] << 8) | seedb[7]);
                    wPt[2] = (uint)((seedb[8] << 24) | (seedb[9] << 16) | (seedb[10] << 8) | seedb[11]);
                    wPt[3] = (uint)((seedb[12] << 24) | (seedb[13] << 16) | (seedb[14] << 8) | seedb[15]);
                    wPt[4] = (uint)((seedb[16] << 24) | (seedb[17] << 16) | (seedb[18] << 8) | seedb[19]);
                    wPt[5] = (uint)((seedb[20] << 24) | (seedb[21] << 16) | (seedb[22] << 8) | seedb[23]);
                    wPt[6] = 0b10000000_00000000_00000000_00000000U;
                    wPt[7] = 0;
                    wPt[8] = 0;
                    wPt[9] = 0;
                    wPt[10] = 0;
                    wPt[11] = 0;
                    wPt[12] = 0;
                    wPt[13] = 0;
                    wPt[14] = 0;
                    wPt[15] = 24 * 8;
                    Sha256Fo.CompressDouble24(pt);

                    // pt is factorb
                    Scalar8x32 key = new Scalar8x32(pt, out _).Multiply(passFactor);

                    if (localComparer.Compare(localComparer.Calc.MultiplyByG(key)))
                    {
                        loopState.Stop();
                        report.FoundAnyResult = true;

                        char[] temp = new char[totalPassLen];
                        for (int i = 0; i < temp.Length; i++)
                        {
                            temp[i] = (char)passBaPt[i];
                        }

                        report.AddMessageSafe($"Password is: {new string(temp)}");
                        return;
                    }

                } while (MoveNext(itemsPt + 1, items.Length - 1));
            }

            report.IncrementProgress();
        }

        private static unsafe void ROMIX_16384(uint* dPt, uint* vPt)
        {
            Buffer.MemoryCopy(dPt, vPt, 1024, 1024);

            uint* srcPt = vPt;
            uint* dstPt = vPt + 256;

            // Set V1 to final V(n-1)
            for (int i = 0; i < 16383 /*=(n-1)*/; i++)
            {
                BlockMix_16384(srcPt, dstPt);
                srcPt += 256;
                dstPt += 256;
            }

            uint[] x = new uint[256];
            uint[] xClone = new uint[256];
            fixed (uint* xPt = &x[0], xClPt = &xClone[0])
            {
                BlockMix_16384(srcPt, xPt);

                for (int i = 0; i < 16384; i++)
                {
                    int j = (int)(xPt[x.Length - 16] & 16383);
                    XOR(xPt, vPt + (j * 256), x.Length);

                    BlockMix_16384(xPt, xClPt);
                    Buffer.BlockCopy(xClone, 0, x, 0, 1024);
                }

                // Swap endian
                for (int i = 0; i < 256; i++)
                {
                    dPt[i] = (xPt[i] >> 24) | (xPt[i] << 24) | ((xPt[i] >> 8) & 0xff00) | ((xPt[i] << 8) & 0xff0000);
                }
            }
        }

        private static unsafe void BlockMix_16384(uint* srcPt, uint* dstPt)
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

        private static unsafe void ROMIX_1024(uint* dPt, uint* vPt)
        {
            Buffer.MemoryCopy(dPt, vPt, 128, 128);

            uint* srcPt = vPt;
            uint* dstPt = vPt + 32;

            // Set V1 to final V(n-1)
            for (int i = 0; i < 1023 /*=(n-1)*/; i++)
            {
                BlockMix_1024(srcPt, dstPt);
                srcPt += 32;
                dstPt += 32;
            }

            uint[] x = new uint[32];
            uint[] xClone = new uint[32];
            fixed (uint* xPt = &x[0], xClPt = &xClone[0])
            {
                BlockMix_1024(srcPt, xPt);

                for (int i = 0; i < 1024; i++)
                {
                    int j = (int)(xPt[x.Length - 16] & 1023);
                    XOR(xPt, vPt + (j * 32), x.Length);

                    BlockMix_1024(xPt, xClPt);
                    Buffer.BlockCopy(xClone, 0, x, 0, 128);
                }

                // Swap endian
                for (int i = 0; i < 128; i++)
                {
                    dPt[i] = (xPt[i] >> 24) | (xPt[i] << 24) | ((xPt[i] >> 8) & 0xff00) | ((xPt[i] << 8) & 0xff0000);
                }
            }
        }

        private static unsafe void BlockMix_1024(uint* srcPt, uint* dstPt)
        {
            uint[] blockMixBuffer = new uint[16];
            fixed (uint* xPt = &blockMixBuffer[0])
            {
                *(Block64*)xPt = *(Block64*)(srcPt + 32 - 16);

                uint* block = srcPt;

                int i1 = 0;
                int i2 = 1 * 16;
                for (int i = 0; i < 2 * 1; i++)
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


        private void StartParallel()
        {
            int max = searchSpace.PermutationCounts[0];
            report.SetProgressStep(max);
            ParallelOptions opts = report.BuildParallelOptions();
            Parallel.For(0, max, opts, (firstItem, state) => MainLoop(firstItem, state));
        }

        private void StartParallelEC()
        {
            report.SetProgressStep(searchSpace.AllValues.Length);
            ParallelOptions opts = report.BuildParallelOptions();
            if (searchSpace.hasLot)
            {
                report.AddMessageSafe("EC mult mode with LOT/Sequence");
                int max = searchSpace.PermutationCounts[0];
                report.SetProgressStep(max);
                Parallel.For(0, max, opts, (firstItem, state) => MainLoopECLot(firstItem, state));
            }
            else
            {
                report.AddMessageSafe("EC mult mode with no LOT/Sequence");
                int max = searchSpace.PermutationCounts[0];
                report.SetProgressStep(max);
                Parallel.For(0, max, opts, (firstItem, state) => MainLoopECNoLot(firstItem, state));
            }
        }


        public async void Find(PasswordSearchSpace ss, string comp, CompareInputType compType)
        {
            report.Init();

            if (!InputService.TryGetCompareService(compType, comp, out comparer))
            {
                report.Fail($"Invalid compare string or compare string type ({compType}).");
            }
            else
            {
                searchSpace = ss;
                report.SetTotal(searchSpace.GetTotal());
                report.Timer.Start();

                if (searchSpace.isEc)
                {
                    await Task.Run(() => StartParallelEC());
                }
                else
                {
                    await Task.Run(() => StartParallel());
                }

                report.Finalize();
            }
        }
    }
}
