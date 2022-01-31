// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Models;

namespace FinderOuter.Services
{
    public interface IPasswordService
    {
        bool TryGetAllValues(PasswordType type, out byte[] allValues, out string error);
        bool TryGetAllValues(string possibleChars, out byte[] allValues, out string error);
    }
}
