// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System.Runtime.InteropServices;

namespace FinderOuter
{
    [StructLayout(LayoutKind.Sequential, Size = 32)]
    internal struct Block32 { }

    [StructLayout(LayoutKind.Sequential, Size = 64)]
    internal struct Block64 { }
}
