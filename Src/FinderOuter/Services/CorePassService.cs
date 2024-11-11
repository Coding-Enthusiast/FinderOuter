// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin;
using FinderOuter.Backend.Hashing;
using FinderOuter.Models;
using FinderOuter.Services.SearchSpaces;
using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace FinderOuter.Services
{
    public class CorePassService
    {
        public CorePassService(IReport rep)
        {
            report = rep;
        }


        private readonly IReport report;
        private CorePassSearchSpace searchSpace;


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
            // Compute SHA512(pass | salt) iteration times
            // AES key is first 32 bytes of hash state
            // If decrypted result ^ XOR == 16 the password was correct

            using Aes aes = Aes.Create();
            aes.KeySize = 256;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;

            PermutationVar[] items = new PermutationVar[searchSpace.PasswordLength];

            Debug.Assert(searchSpace.Salt != null);
            Debug.Assert(searchSpace.Salt.Length == 8);
            Span<byte> passBa = new byte[searchSpace.MaxPasswordSize + searchSpace.Salt.Length];

            ulong* ptr = stackalloc ulong[Sha512Fo.UBufferSize];
            ulong* wPt = ptr + 8;

            fixed (byte* passBaPt = &passBa[0], allVals = &searchSpace.AllValues[0], saltPt = &searchSpace.Salt[0])
            fixed (int* lens = &searchSpace.PermutationLengths[0], sizePt = &searchSpace.PermutationSizes[0])
            fixed (PermutationVar* itemsPt = &items[0])
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

                    passBa.Clear();
                    int totalPassLen = 0;
                    foreach (var item in items)
                    {
                        totalPassLen += item.WriteValue(passBaPt + totalPassLen, passBa.Length);
                    }
                    Debug.Assert(totalPassLen <= searchSpace.MaxPasswordSize);
                    Buffer.MemoryCopy(saltPt, passBaPt + totalPassLen, passBa.Length, searchSpace.Salt.Length);
                    totalPassLen += searchSpace.Salt.Length;

                    Sha512Fo.Init(ptr);
                    Sha512Fo.CompressData(passBaPt, totalPassLen, totalPassLen, ptr, wPt);

                    wPt[08] = 0b10000000_00000000_00000000_00000000_00000000_00000000_00000000_00000000UL; // 1 followed by 0 bits: pad1
                    wPt[09] = 0;
                    wPt[10] = 0;
                    wPt[11] = 0;
                    wPt[12] = 0;
                    wPt[13] = 0;
                    wPt[14] = 0;
                    wPt[15] = 512; // Message length is 64 byte previous hash or 512 bits
                    for (int i = 0; i < searchSpace.Iteration - 1; i++)
                    {
                        // Previous hash is now our working vector
                        *(Block64*)wPt = *(Block64*)ptr;

                        // Now initialize hashState to compute next round
                        Sha512Fo.Init(ptr);
                        Sha512Fo.Compress64(ptr, wPt);
                    }

                    aes.Key = new byte[32]
                    {
                        (byte)(ptr[0] >> 56), (byte)(ptr[0] >> 48), (byte)(ptr[0] >> 40), (byte)(ptr[0] >> 32),
                        (byte)(ptr[0] >> 24), (byte)(ptr[0] >> 16), (byte)(ptr[0] >> 8), (byte)ptr[0],

                        (byte)(ptr[1] >> 56), (byte)(ptr[1] >> 48), (byte)(ptr[1] >> 40), (byte)(ptr[1] >> 32),
                        (byte)(ptr[1] >> 24), (byte)(ptr[1] >> 16), (byte)(ptr[1] >> 8), (byte)ptr[1],

                        (byte)(ptr[2] >> 56), (byte)(ptr[2] >> 48), (byte)(ptr[2] >> 40), (byte)(ptr[2] >> 32),
                        (byte)(ptr[2] >> 24), (byte)(ptr[2] >> 16), (byte)(ptr[2] >> 8), (byte)ptr[2],

                        (byte)(ptr[3] >> 56), (byte)(ptr[3] >> 48), (byte)(ptr[3] >> 40), (byte)(ptr[3] >> 32),
                        (byte)(ptr[3] >> 24), (byte)(ptr[3] >> 16), (byte)(ptr[3] >> 8), (byte)ptr[3]
                    };

                    using ICryptoTransform decryptor = aes.CreateDecryptor();
                    byte[] decryptedResult = new byte[16];
                    decryptor.TransformBlock(searchSpace.Encrypted, 0, 16, decryptedResult, 0);

                    bool isCorrect = true;
                    for (int i = 0; i < searchSpace.XOR.Length; i++)
                    {
                        if ((searchSpace.XOR[i] ^ decryptedResult[i]) != 16)
                        {
                            isCorrect = false;
                            break;
                        }
                    }

                    if (isCorrect)
                    {
                        loopState.Stop();
                        report.FoundAnyResult = true;

                        char[] temp = new char[totalPassLen - searchSpace.Salt.Length];
                        for (int i = 0; i < temp.Length; i++)
                        {
                            temp[i] = (char)passBaPt[i];
                        }

                        report.AddMessageSafe($"Password is: {new string(temp)}");
                        return;
                    }

                } while (MoveNext(itemsPt + 1, items.Length - 1));
            }
        }


        private void StartParallel()
        {
            int max = searchSpace.PermutationCounts[0];
            report.SetProgressStep(max);
            ParallelOptions opts = report.BuildParallelOptions();
            Parallel.For(0, max, opts, (firstItem, state) => MainLoop(firstItem, state));
        }


        public async void Find(CorePassSearchSpace ss)
        {
            report.Init();

            searchSpace = ss;
            report.SetTotal(searchSpace.GetTotal());
            report.Timer.Start();

            await Task.Run(StartParallel);

            report.Finalize();
        }
    }
}
