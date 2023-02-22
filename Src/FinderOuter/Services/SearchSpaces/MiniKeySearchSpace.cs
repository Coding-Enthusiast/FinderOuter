// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend;
using System.Linq;
using System.Text;

namespace FinderOuter.Services.SearchSpaces
{
    public class MiniKeySearchSpace : SearchSpaceBase
    {
        public static readonly char[] AllChars = ConstantsFO.Base58Chars.ToCharArray();
        public static readonly byte[] AllBytes = Encoding.UTF8.GetBytes(ConstantsFO.Base58Chars);
        public byte[] preComputed;

        private void PreCompute(char missingChar)
        {
            int mis = 0;
            for (int i = 0; i < Input.Length; i++)
            {
                if (Input[i] == missingChar)
                {
                    MissingIndexes[mis++] = i;
                }
                else
                {
                    preComputed[i] = (byte)Input[i];
                }
            }
        }

        public bool Process(string input, char missingChar, out string error)
        {
            Input = input;

            if (!InputService.IsMissingCharValid(missingChar))
            {
                error = $"Invalid missing character. Choose one from {ConstantsFO.MissingSymbols}";
                return false;
            }
            else if (string.IsNullOrEmpty(input))
            {
                error = "Input can not be null or empty.";
                return false;
            }
            else if (!Input.StartsWith(ConstantsFO.MiniKeyStart))
            {
                error = $"Minikey must start with {ConstantsFO.MiniKeyStart}.";
                return false;
            }
            else if (!InputService.CheckChars(input, AllChars, missingChar, out error))
            {
                return false;
            }
            else
            {
                MissCount = Input.Count(c => c == missingChar);
                if (MissCount == 0)
                {
                    error = null;
                    return true;
                }

                MissingIndexes = new int[MissCount];
                switch (Input.Length)
                {
                    case ConstantsFO.MiniKeyLen1:
                        preComputed = new byte[ConstantsFO.MiniKeyLen1];
                        break;
                    case ConstantsFO.MiniKeyLen2:
                        preComputed = new byte[ConstantsFO.MiniKeyLen2];
                        break;
                    case ConstantsFO.MiniKeyLen3:
                        preComputed = new byte[ConstantsFO.MiniKeyLen3];
                        break;
                    default:
                        error = $"Minikey length must be {ConstantsFO.MiniKeyLen1} or {ConstantsFO.MiniKeyLen2} or " +
                                $"{ConstantsFO.MiniKeyLen3}.";
                        return false;
                }

                PreCompute(missingChar);
                error = null;
                return true;
            }
        }


        public bool ProcessNoMissing(out string message)
        {
            if (MissCount != 0)
            {
                message = "This method should not be called with missing characters.";
                return false;
            }

            return InputService.IsValidMinikey(Input, out message);
        }


        public bool SetValues(string[][] array, out string error)
        {
            uint[] all = AllBytes.Select(i => (uint)i).ToArray();
            return ProcessValues(array, out error) && ProcessCharValues(array, AllChars, all, out error);
        }
    }
}
