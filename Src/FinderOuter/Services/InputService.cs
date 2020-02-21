// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend;
using FinderOuter.Models;
using System.Numerics;
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


        public bool IsPrivateKeyInRange(byte[] key)
        {
            if (key.Length > 32)
            {
                return false;
            }
            BigInteger val = key.ToBigInt(true, true);
            BigInteger max = BigInteger.Parse("115792089237316195423570985008687907852837564279074904382605163141518161494336");
            return val >= BigInteger.One && val <= max;
        }


        public bool NormalizeNFKD(string s, out string norm)
        {
            norm = s.Normalize(NormalizationForm.FormKD);
            return !s.IsNormalized(NormalizationForm.FormKD);
        }

    }
}
