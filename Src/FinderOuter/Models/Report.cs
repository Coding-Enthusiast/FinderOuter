// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Avalonia.Threading;
using ReactiveUI;
using System;
using System.Diagnostics;
using System.Numerics;
using System.Threading.Tasks;

namespace FinderOuter.Models
{
    public class Report : ReactiveObject, IReport
    {
        public Report() : this(Dispatcher.UIThread)
        {
        }

        public Report(IDispatcher dispatcher)
        {
            UIThread = dispatcher;

            updateTimer = new System.Timers.Timer(TimeSpan.FromSeconds(3).TotalMilliseconds);
            updateTimer.Elapsed += UpdateTimer_Elapsed;
        }


        public IDispatcher UIThread { get; set; }
        public Settings Settings { get; set; }

        private State _state;
        public State CurrentState
        {
            get => _state;
            set => this.RaiseAndSetIfChanged(ref _state, value);
        }

        private string _msg = string.Empty;
        public string Message
        {
            get => _msg;
            set => this.RaiseAndSetIfChanged(ref _msg, value);
        }

        private bool _progVis;
        public bool IsProgressVisible
        {
            get => _progVis;
            set => this.RaiseAndSetIfChanged(ref _progVis, value);
        }

        private double _prog;
        public double Progress
        {
            get => _prog;
            set => this.RaiseAndSetIfChanged(ref _prog, value);
        }

        public bool FoundAnyResult { get; set; }

        public Stopwatch Timer { get; } = new();

        public BigInteger Total { get; private set; }

        public void SetTotal(BigInteger value)
        {
            Total = value;
            AddMessageSafe($"Total number of permutations to check: {Total:n0}");
        }

        public void SetTotal(int value, int exponent)
        {
            SetTotal(BigInteger.Pow(value, exponent));
        }

        public ParallelOptions BuildParallelOptions()
        {
            ParallelOptions result = new();
            if (Settings is not null)
            {
                Debug.Assert(Settings.CoreCount > 0);
                result.MaxDegreeOfParallelism = Settings.CoreCount;
            }
            return result;
        }

        public void Init()
        {
            CurrentState = State.Working;
            FoundAnyResult = false;
            Message = string.Empty;
            Progress = 0;
            percent = 0;
            IsProgressVisible = false;
            Timer.Reset();
            Total = BigInteger.Zero;

            Speed = 0;
            TotalChecked = 0;
            Remaining = TimeSpan.Zero;
            updateTimer.Stop();
        }

        public bool Finalize(bool success)
        {
            CurrentState = success ? State.FinishedSuccess : State.FinishedFail;
            return success;
        }

        public bool Finalize()
        {
            if (Timer.IsRunning)
            {
                Timer.Stop();
                AddMessageSafe($"Elapsed time: {Timer.Elapsed}");

                if (Total != BigInteger.Zero)
                {
                    BigInteger totalKeys = Progress == 0 || Progress >= 99 ?
                        Total :
                        BigInteger.Multiply(Total, new BigInteger(Progress)) / 100;
                    string kps = GetKPS(totalKeys, Timer.Elapsed.TotalSeconds);
                    AddMessageSafe(kps);
                }
            }

            CurrentState = FoundAnyResult ? State.FinishedSuccess : State.FinishedFail;
            Progress = 100;
            updateTimer.Stop();
            return FoundAnyResult;
        }

        /// <summary>
        /// Thread UNSAFE way of quickly adding a message to report
        /// </summary>
        /// <param name="msg"></param>
        public void AddMessage(string msg)
        {
            Message += string.IsNullOrEmpty(Message) ? msg : $"{Environment.NewLine}{msg}";
        }

        /// <summary>
        /// Thread safe way of adding a message to report
        /// </summary>
        /// <param name="msg"></param>
        public void AddMessageSafe(string msg)
        {
            UIThread.Post(() => Message += string.IsNullOrEmpty(Message) ? msg : $"{Environment.NewLine}{msg}");
        }

        public bool Fail(string msg)
        {
            AddMessage(msg);
            CurrentState = State.FinishedFail;
            return false;
        }

        public bool Pass(string msg)
        {
            AddMessage(msg);
            CurrentState = State.FinishedSuccess;
            return true;
        }


        private static string GetKPS(BigInteger totalKeys, double totalSecond)
        {
            return totalSecond < 1 ? "k/s= ∞" : $"k/s= {totalKeys / new BigInteger(totalSecond):n0}";
        }
        public void SetKeyPerSec(BigInteger totalKeys, double totalSecond) => AddMessage(GetKPS(totalKeys, totalSecond));
        public void SetKeyPerSecSafe(BigInteger totalKeys, double totalSecond) => AddMessageSafe(GetKPS(totalKeys, totalSecond));


        private double percent;
        /// <inheritdoc/>
        public void SetProgressStep(int splitSize)
        {
            AddMessageSafe("Running in parallel.");
            percent = (double)100 / splitSize;
            UIThread.Post(() => IsProgressVisible = true);
            updateTimer.Start();
        }

        private readonly object lockObj = new();
        public void IncrementProgress()
        {
            lock (lockObj)
            {
                Progress += percent;
            }
        }

        private double _speed;
        public double Speed
        {
            get => _speed;
            set => this.RaiseAndSetIfChanged(ref _speed, value);
        }

        private double _totCh;
        public double TotalChecked
        {
            get => _totCh;
            set => this.RaiseAndSetIfChanged(ref _totCh, value);
        }

        private TimeSpan _rem;
        public TimeSpan Remaining
        {
            get => _rem;
            set => this.RaiseAndSetIfChanged(ref _rem, value);
        }


        private readonly System.Timers.Timer updateTimer;

        private void UpdateTimer_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            if (Progress is > 0 and <= 100)
            {
                try
                {
                    TotalChecked = (double)Total * Progress / 100;
                    double time = Timer.Elapsed.TotalSeconds;
                    if (time != 0 && TotalChecked != 0)
                    {
                        Speed = TotalChecked / time;
                        double remKeys = (double)Total - TotalChecked;
                        Debug.Assert(remKeys >= 0);
                        double d = remKeys / Speed;
                        Remaining = TimeSpan.FromSeconds(d);
                    }
                }
                catch (Exception ex)
                {
                    Debug.Fail(ex.Message);
                }
            }
        }
    }
}
