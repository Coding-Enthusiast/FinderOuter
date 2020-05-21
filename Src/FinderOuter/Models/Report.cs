// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Avalonia.Threading;
using ReactiveUI;
using System;
using System.Numerics;

namespace FinderOuter.Models
{
    public enum State
    {
        Ready,
        Working,
        Paused,
        Stopped,
        FinishedSuccess,
        FinishedFail
    }

    public class Report : ReactiveObject, IReport
    {
        private State _state;
        public State CurrentState
        {
            get => _state;
            set => this.RaiseAndSetIfChanged(ref _state, value);
        }

        private string _msg;
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


        public void Init()
        {
            CurrentState = State.Working;
            Message = string.Empty;
            IsProgressVisible = true;
            Progress = 0;
        }

        public bool Finalize(bool success)
        {
            CurrentState = success ? State.FinishedSuccess : State.FinishedFail;
            return success;
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
            Dispatcher.UIThread.InvokeAsync(() => Message += string.IsNullOrEmpty(Message) ? msg : $"{Environment.NewLine}{msg}");
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


        private string GetKPS(BigInteger totalKeys, double totalSecond)
        {
            return totalSecond < 1 ? "k/s= ∞" : $"k/s= {totalKeys / new BigInteger(totalSecond):n0}";
        }
        public void SetKeyPerSec(BigInteger totalKeys, double totalSecond) => AddMessage(GetKPS(totalKeys, totalSecond));
        public void SetKeyPerSecSafe(BigInteger totalKeys, double totalSecond) => AddMessageSafe(GetKPS(totalKeys, totalSecond));

        public void SetProgressSafe(BigInteger total, BigInteger current)
        {
            double val = (double)(current / total * 100);
            Dispatcher.UIThread.InvokeAsync(() => Progress = (double)(current / total * 100));
        }

        public void ChangeProgressVisibilitySafe(bool isVisible) => Dispatcher.UIThread.InvokeAsync(() => IsProgressVisible = isVisible);
    }
}
