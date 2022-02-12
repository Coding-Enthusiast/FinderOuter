// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Backend;
using FinderOuter.Models;
using System.Linq;
using System.Text;

namespace FinderOuter.Services
{
    public class PasswordService : IPasswordService
    {
        public bool TryGetAllValues(PasswordType type, out byte[] allValues, out string error)
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

            if (allValues.Length == 0)
            {
                error = type == PasswordType.None ? "At least one password character type has to be selected." :
                                                    "Password character type is not defined (this is a bug).";
                return false;
            }
            else
            {
                error = null;
                return true;
            }
        }


        public bool TryGetAllValues(string possibleChars, out byte[] allValues, out string error)
        {
            if (string.IsNullOrEmpty(possibleChars))
            {
                error = "Please enter at least 1 possible character.";
                allValues = null;
                return false;
            }

            allValues = Encoding.UTF8.GetBytes(possibleChars.Normalize(NormalizationForm.FormC));
            if (allValues.Distinct().Count() == allValues.Length)
            {
                error = null;
                return true;
            }
            else
            {
                error = "Remove the duplicate character(s) from possible password characters.";
                allValues = null;
                return false;
            }
        }
    }
}
