// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using ReactiveUI;
using System;

namespace FinderOuter.Models
{
    public class Settings : ReactiveObject
    {
        public Settings()
        {
            MaxCoreCount = Environment.ProcessorCount;
            _coreCount = MaxCoreCount;
        }

        public int MaxCoreCount { get; }

        private int _coreCount;
        public int CoreCount
        {
            get => _coreCount;
            set
            {
                if (value < 1)
                {
                    value = 1;
                }
                this.RaiseAndSetIfChanged(ref _coreCount, value);
            }
        }

        public bool IsMax => CoreCount >= MaxCoreCount;
    }
}
