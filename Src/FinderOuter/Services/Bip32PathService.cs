// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.Cryptography.EllipticCurve;
using Autarkysoft.Bitcoin.ImprovementProposals;
using FinderOuter.Models;
using FinderOuter.Services.Comparers;
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Threading.Tasks;

namespace FinderOuter.Services
{
    public class Bip32PathService
    {
        public Bip32PathService(IReport rep)
        {
            report = rep;
        }


        private readonly IReport report;
        private ICompareService comparer;

        public enum SeedType
        {
            [Description("BIP-39 mnemonic (seed phrase)")]
            BIP39,
            [Description("Electrum mnemonic (seed phrase)")]
            Electrum,
            [Description("Extended private key (base-58 encoded string starting with 'xprv')")]
            XPRV,
            //[Description("Extended public key (base-58 encoded string starting with 'xpub')")]
            //XPUB
        }

        private static readonly BIP0032Path[] AllPaths = new BIP0032Path[]
        {
            new BIP0032Path("m/0"),
            new BIP0032Path("m/0'"),
            // BIP-44 xprv/xpub P2PKH
            new BIP0032Path("m/44'/0'/0'/0"),
            // BIP-49 yprv/upub P2SH-P2WPKH
            new BIP0032Path("m/49'/0'/0'/0"),
            // BIP-84 zprv/zpub P2WPKH
            new BIP0032Path("m/84'/0'/0'/0"),
        };


        public void Loop(BIP0032 bip32, uint count)
        {
            BIP0032Path[] allPaths = new BIP0032Path[]
            {
                new BIP0032Path("m/0"),
                new BIP0032Path("m/0'"),
                new BIP0032Path("m/0'/0/"),
                new BIP0032Path("m/0'/0'"),
                // BIP-44 xprv/xpub P2PKH
                new BIP0032Path("m/44'/0'/0'/0"),
                new BIP0032Path("m/44'/0'/0'"),
                // BIP-49 yprv/upub P2SH-P2WPKH
                new BIP0032Path("m/49'/0'/0'/0"),
                new BIP0032Path("m/49'/0'/0'"),
                // BIP-84 zprv/zpub P2WPKH
                new BIP0032Path("m/84'/0'/0'/0"),
                new BIP0032Path("m/84'/0'/0'/"),
                new BIP0032Path("m/84'/0'/2147483644'/0"),
                new BIP0032Path("m/84'/0'/2147483645'/0"),
                new BIP0032Path("m/84'/0'/2147483646'/0"),
                new BIP0032Path("m/84'/0'/2147483647'/0"),
                new BIP0032Path("m/49'/0'/2147483647'/0"),
                new BIP0032Path("m/44'/0'/2147483647'/0"),
                new BIP0032Path("m/141'/0'/0'/0"),
            };


            foreach (BIP0032Path path in allPaths)
            {
                PrivateKey[] keys = bip32.GetPrivateKeys(path, count);
                for (int i = 0; i < keys.Length; i++)
                {
                    if (comparer.Compare(keys[i].ToBytes()))
                    {
                        report.AddMessageSafe($"The correct key path is: {path}/{i}");
                        report.FoundAnyResult = true;
                        return;
                    }
                }
            }

            report.AddMessageSafe("Could not find any correct paths.");
        }



        public async void FindPath(string input, SeedType inputType, BIP0039.WordLists wl, string pass,
                                   string comp, CompareInputType compType, uint count)
        {
            report.Init();

            if (!InputService.TryGetCompareService(compType, comp, out comparer))
            {
                report.Fail($"Invalid extra input or extra input type: {compType}");
                return;
            }

            BIP0032 bip32;
            if (inputType == SeedType.BIP39)
            {
                try
                {
                    bip32 = new BIP0039(input, wl, pass);
                }
                catch (Exception ex)
                {
                    report.Fail($"Could not instantiate BIP-39 instance. Error: {ex.Message}");
                    return;
                }
            }
            else if (inputType == SeedType.Electrum)
            {
                try
                {
                    bip32 = new ElectrumMnemonic(input, wl, pass);
                }
                catch (Exception ex)
                {
                    try
                    {
                        if (ElectrumMnemonic.IsOld(input))
                        {
                            report.Fail("This is an old ElectrumMnemonic. They are not supported yet.");
                        }
                    }
                    catch
                    {
                    }

                    report.Fail($"Could not instantiate ElectrumMnemonic instance. Error: {ex.Message}");
                    return;
                }
            }
            else if (inputType == SeedType.XPRV)
            {
                try
                {
                    bip32 = new BIP0032(input);
                }
                catch (Exception ex)
                {
                    report.Fail($"Could not instantiate BIP-32 instance. Error: {ex.Message}");
                    return;
                }
            }
            else
            {
                report.Fail("Undefined input type.");
                return;
            }

            Debug.Assert(bip32 is not null);

            await Task.Run(() => Loop(bip32, count));

            report.Finalize();
        }
    }
}
