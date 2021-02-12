// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.ImprovementProposals;
using FinderOuter.Backend.Cryptography.Asymmetric.EllipticCurve;
using FinderOuter.Models;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FinderOuter.Services
{
    public class Bip32PathService
    {
        public Bip32PathService(IReport rep)
        {
            report = rep;
            inputService = new InputService();
            calc = new ECCalc();
        }


        private readonly IReport report;
        private readonly InputService inputService;
        private readonly ECCalc calc;

        public enum SeedType
        {
            [Description("BIP-39 mnemonic (seed phrase)")]
            BIP39,
            [Description("Electrum mnemonic (seed phrase)")]
            Electrum,
            [Description("Extended private key (base-58 encoded string starting with 'xprv')")]
            XPRV,
            [Description("Extended public key (base-58 encoded string starting with 'xpub')")]
            XPUB
        }

        public async void FindPath(string input, SeedType inputType, BIP0039.WordLists wl, string pass, 
                                   string extra, InputType extraType)
        {
            report.Init();

            BIP0032 bip32 = null;
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
                    report.Fail($"Could not instantiate ElectrumMnemonic instance. Error: {ex.Message}");
                    return;
                }
            }
            else if (inputType == SeedType.XPRV || inputType == SeedType.XPUB)
            {
                try
                {
                    bip32 = new BIP0032(input);
                    return;
                }
                catch (Exception ex)
                {
                    report.Fail($"Could not instantiate BIP-32 instance. Error: {ex.Message}");
                }
            }
            else
            {
                report.Fail("Undefined input type.");
                return;
            }

            Debug.Assert(bip32 is not null);

            // TODO: Derive child keys at different known paths to see which one matches the extra input

            report.Finalize();
        }
    }
}
