// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Models;
using ReactiveUI;
using System;
using System.Collections.Generic;
using System.ComponentModel;

namespace FinderOuter.ViewModels
{
    public enum HelpInputTypes
    {
        [Description("Wallet import format (WIF)")]
        Wif,
        [Description("Base-58 encoded private key")]
        Base58Prv,
        [Description("P2PKH address starting with 1")]
        P2pkhAddr,
        [Description("P2SH address starting with 3")]
        P2shAddr,
        [Description("BIP-38 encrypted private key starting with 6P")]
        Bip38,
        [Description("Hexadeciman (Base-16) encoded private key")]
        Base16Prv,
        [Description("Mini private key starting with S")]
        MiniKey,
        [Description("BIP-39 mnemonic (seed) phrase")]
        Bip39Seed,
        [Description("Electrum mnemonic (seed) phrase")]
        ElecSeed,
        [Description("Extended private key starting with xprv")]
        Xprv,
        [Description("Extended public key starting with xpub")]
        Xpub,
        [Description("Armory recovery phrase")]
        Armory
    }

    public enum HelpSecondInputTypes
    {
        [Description("missing some characters at known positions")]
        CharMissing,
        [Description("missing some characters at unknown positions")]
        CharMissingUnknown,

        [Description("missing some words at known positions")]
        WordMissing,
        [Description("missing some words at unknown positions")]
        WordMissingUnknown,

        [Description("missing encryption password")]
        PasswordMissing,

        [Description("missing BIP-32 derivation path")]
        PathMissing,

        [Description("missing BIP-39 extension word (passphrase)")]
        Bip39PassMissing,
    }

    public class HelpViewModel : ViewModelBase
    {
        public HelpViewModel()
        {
            AllInputs = ListHelper.GetEnumDescHelpInput();
        }



        public string Description => $"Choose an option from the list on the left and follow the instructions in that option." +
                                     $"{Environment.NewLine}" +
                                     $"If you are unsure which option to use, fill in the blanks below for help.";


        public IEnumerable<DescriptiveHelpInput> AllInputs { get; }

        private DescriptiveHelpInput _selInput;
        public DescriptiveHelpInput SelectedInput
        {
            get => _selInput;
            set
            {
                this.RaiseAndSetIfChanged(ref _selInput, value);
                this.RaisePropertyChanged(nameof(IndefiniteArticle));
                SecondaryItems = GetSecondary(value.Value);
            }
        }


        private IEnumerable<DescriptiveHelpInput2> _items2;
        public IEnumerable<DescriptiveHelpInput2> SecondaryItems
        {
            get => _items2;
            set => this.RaiseAndSetIfChanged(ref _items2, value);
        }

        private DescriptiveItem<HelpSecondInputTypes> _selInput2;
        public DescriptiveItem<HelpSecondInputTypes> SelectedSecondary
        {
            get => _selInput2;
            set
            {
                if (value != _selInput2)
                {
                    this.RaiseAndSetIfChanged(ref _selInput2, value);
                    this.RaisePropertyChanged(nameof(Result));
                }
            }
        }


        /// <param name="extra">
        /// <para/>0 -> extra input is not used
        /// <para/>1 -> extra input could help
        /// <para/>2 -> extra input is mandatory
        /// </param>
        private static string BuildStr(string option, string key, string missType, int extra, bool unknownPos)
        {
            string temp = "Having the corresponding publickey or address";
            return $"Choose {option} option, enter your {key}" +
                   $"{(!unknownPos ? $" replacing its missing {missType}(s) with a symbol such as *" : string.Empty)}, " +
                   $"fill in any other required textbox(es) and click Find.{Environment.NewLine}" +
                   $"{(extra == 0 ? string.Empty : extra == 1 ? $"{temp} is optional but helpful." : $"{temp} is mandatory.")}";
        }

        private static string BuildPassStr(string option, string key)
        {
            return $"Choose {option} option, enter your {key} and choose a password recovery mode. " +
                   $"Enter some information about your password and click Find.";
        }

        private static string BuildNotAvailable()
        {
            return "This option is not yet available.";
        }

        public string Result
        {
            get
            {
                if (SelectedInput is null || SelectedSecondary is null)
                {
                    return string.Empty;
                }

                switch (SelectedInput.Value)
                {
                    case HelpInputTypes.Wif:
                    case HelpInputTypes.Base58Prv:
                        if (SelectedSecondary.Value == HelpSecondInputTypes.CharMissing)
                        {
                            return BuildStr("Missing Base58", "private key", "character", 0, false);
                        }
                        else if (SelectedSecondary.Value == HelpSecondInputTypes.CharMissingUnknown)
                        {
                            return BuildStr("Missing Base58", "private key", "character", 0, true);
                        }
                        break;
                    case HelpInputTypes.P2pkhAddr:
                    case HelpInputTypes.P2shAddr:
                        if (SelectedSecondary.Value == HelpSecondInputTypes.CharMissing)
                        {
                            return BuildStr("Missing Base58", "address", "character", 0, false);
                        }
                        else if (SelectedSecondary.Value == HelpSecondInputTypes.CharMissingUnknown)
                        {
                            return BuildNotAvailable();
                        }
                        break;
                    case HelpInputTypes.Bip38:
                        if (SelectedSecondary.Value == HelpSecondInputTypes.CharMissing)
                        {
                            return BuildStr("Missing Base58", "BIP38 encrypted key", "character", 1, false);
                        }
                        else if (SelectedSecondary.Value == HelpSecondInputTypes.CharMissingUnknown)
                        {
                            return BuildNotAvailable();
                        }
                        else if (SelectedSecondary.Value == HelpSecondInputTypes.PasswordMissing)
                        {
                            return BuildPassStr("Missing BIP38 Pass", "BIP38 encrypted key");
                        }
                        break;
                    case HelpInputTypes.Base16Prv:
                        if (SelectedSecondary.Value == HelpSecondInputTypes.CharMissing)
                        {
                            return BuildStr("Missing Base16", "hexadecimal private key", "character", 2, false);
                        }
                        else if (SelectedSecondary.Value == HelpSecondInputTypes.CharMissingUnknown)
                        {
                            return BuildNotAvailable();
                        }
                        break;
                    case HelpInputTypes.MiniKey:
                        if (SelectedSecondary.Value == HelpSecondInputTypes.CharMissing)
                        {
                            return BuildStr("Missing mini private key", "mini private key", "character", 2, false);
                        }
                        else if (SelectedSecondary.Value == HelpSecondInputTypes.CharMissingUnknown)
                        {
                            return BuildNotAvailable();
                        }
                        break;
                    case HelpInputTypes.Bip39Seed:
                        if (SelectedSecondary.Value == HelpSecondInputTypes.WordMissing)
                        {
                            return BuildStr("Missing Mnemonic", "BIP39 seed phrase", "word", 2, false);
                        }
                        else if (SelectedSecondary.Value == HelpSecondInputTypes.WordMissingUnknown)
                        {
                            return BuildNotAvailable();
                        }
                        else if (SelectedSecondary.Value == HelpSecondInputTypes.PathMissing)
                        {
                            return BuildStr("Missing BIP32 Path", "BIP39 seed phrase", "word", 2, true);
                        }
                        else if (SelectedSecondary.Value == HelpSecondInputTypes.Bip39PassMissing)
                        {
                            return BuildPassStr("Missing Mnemonic Pass", "Mnemonic, derivation path and child key"); ;
                        }
                        break;
                    case HelpInputTypes.ElecSeed:
                        if (SelectedSecondary.Value == HelpSecondInputTypes.WordMissing)
                        {
                            return BuildStr("Missing mnemonic", "Electrum seed phrase", "word", 2, false);
                        }
                        else if (SelectedSecondary.Value == HelpSecondInputTypes.WordMissingUnknown)
                        {
                            return BuildNotAvailable();
                        }
                        else if (SelectedSecondary.Value == HelpSecondInputTypes.PathMissing)
                        {
                            return BuildStr("Missing BIP32 path", "Electrum seed phrase", "word", 2, true);
                        }
                        else if (SelectedSecondary.Value == HelpSecondInputTypes.Bip39PassMissing)
                        {
                            return BuildNotAvailable();
                        }
                        break;
                    case HelpInputTypes.Xprv:
                    case HelpInputTypes.Xpub:
                        if (SelectedSecondary.Value == HelpSecondInputTypes.CharMissing)
                        {
                            return BuildNotAvailable();
                        }
                        else if (SelectedSecondary.Value == HelpSecondInputTypes.CharMissingUnknown)
                        {
                            return BuildNotAvailable();
                        }
                        else if (SelectedSecondary.Value == HelpSecondInputTypes.PathMissing)
                        {
                            return BuildStr("Missing BIP32 path", "extended key", "word", 2, true);
                        }
                        break;
                    case HelpInputTypes.Armory:
                        if (SelectedSecondary.Value == HelpSecondInputTypes.CharMissing)
                        {
                            return BuildStr("Missing Armory", "Armory recovery phrase", "character", 2, false);
                        }
                        else if (SelectedSecondary.Value == HelpSecondInputTypes.CharMissingUnknown)
                        {
                            return BuildNotAvailable();
                        }
                        break;
                }


                return "Undefined.";
            }
        }


        private static IEnumerable<DescriptiveHelpInput2> ToDescItems(params HelpSecondInputTypes[] values)
        {
            foreach (var item in values)
            {
                yield return new DescriptiveHelpInput2(item);
            }
        }

        private static IEnumerable<DescriptiveHelpInput2> GetSecondary(HelpInputTypes value)
        {
            if (value == HelpInputTypes.Wif || value == HelpInputTypes.Base58Prv ||
                value == HelpInputTypes.P2pkhAddr || value == HelpInputTypes.P2shAddr ||
                value == HelpInputTypes.Base16Prv ||
                value == HelpInputTypes.MiniKey ||
                value == HelpInputTypes.Armory)
            {
                return ToDescItems(HelpSecondInputTypes.CharMissing, HelpSecondInputTypes.CharMissingUnknown);
            }
            else if (value == HelpInputTypes.Bip38)
            {
                return ToDescItems(HelpSecondInputTypes.CharMissing, HelpSecondInputTypes.CharMissingUnknown,
                                   HelpSecondInputTypes.PasswordMissing);
            }
            else if (value == HelpInputTypes.Bip39Seed || value == HelpInputTypes.ElecSeed)
            {
                return ToDescItems(HelpSecondInputTypes.WordMissing, HelpSecondInputTypes.WordMissingUnknown,
                                   HelpSecondInputTypes.PathMissing, HelpSecondInputTypes.Bip39PassMissing);
            }
            else if (value == HelpInputTypes.Xprv || value == HelpInputTypes.Xpub)
            {
                return ToDescItems(HelpSecondInputTypes.CharMissing, HelpSecondInputTypes.CharMissingUnknown,
                                   HelpSecondInputTypes.PathMissing);
            }
            else
            {
                return null;
            }
        }

        private static bool IsVowel(HelpInputTypes? t) =>
            t.HasValue &&
            t == HelpInputTypes.Armory ||
            t == HelpInputTypes.ElecSeed ||
            t == HelpInputTypes.Xprv ||
            t == HelpInputTypes.Xpub;

        public string IndefiniteArticle => IsVowel(SelectedInput?.Value) ? "an" : "a";

    }
}
