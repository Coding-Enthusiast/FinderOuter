// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend;
using FinderOuter.Models;
using System;
using System.Collections.Generic;
using System.Text;

namespace FinderOuter.Services
{
    public class InputService : ServiceBase
    {
        public InputService(Report rep) : base(rep)
        {
        }


        public bool CanBePrivateKey(string key)
        {
            return
                (key.Length == Constants.CompPrivKeyLen &&
                        (key[0] == Constants.CompPrivKeyChar1 || key[0] == Constants.CompPrivKeyChar2))
                ||
                (key.Length == Constants.UncompPrivKeyLen &&
                        (key[0] == Constants.UncompPrivKeyChar));
        }


        public bool NormalizeNFKD(string s, out string norm)
        {
            norm = s.Normalize(NormalizationForm.FormKD);
            return !s.IsNormalized(NormalizationForm.FormKD);
        }

    }
}
