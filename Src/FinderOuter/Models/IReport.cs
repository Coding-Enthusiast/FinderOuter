// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Numerics;
using System.Threading.Tasks;

namespace FinderOuter.Models
{
    public interface IReport : INotifyPropertyChanged
    {
        Settings Settings { get; set; }
        State CurrentState { get; set; }
        string Message { get; set; }
        bool IsProgressVisible { get; set; }
        double Progress { get; set; }
        bool FoundAnyResult { get; set; }
        double Speed { get; set; }
        double TotalChecked { get; set; }
        TimeSpan Remaining { get; set; }
        Stopwatch Timer { get; }
        BigInteger Total { get; }

        ParallelOptions BuildParallelOptions();

        void SetTotal(BigInteger value);
        void SetTotal(int value, int exponent);

        void Init();
        bool Finalize(bool success);
        bool Finalize();

        void AddMessage(string msg);
        void AddMessageSafe(string msg);

        bool Fail(string msg);
        bool Pass(string msg);

        void SetKeyPerSec(BigInteger totalKeys, double totalSecond);
        void SetKeyPerSecSafe(BigInteger totalKeys, double totalSecond);

        /// <param name="splitSize">Number of keys checked in each round that completes</param>
        void SetProgressStep(int splitSize);
        void IncrementProgress();
    }
}
