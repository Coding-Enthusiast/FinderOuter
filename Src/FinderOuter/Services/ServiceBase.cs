// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Avalonia.Threading;
using FinderOuter.Models;
using System;
using System.Numerics;

namespace FinderOuter.Services
{
    /// <summary>
    /// Base (abstract) class for services. Implements methods requires for creating and updating the report.
    /// </summary>
    public abstract class ServiceBase
    {
        public ServiceBase(Report rep)
        {
            report = rep;
        }


        private readonly Report report;


        protected void InitReport()
        {
            report.CurrentState = State.Working;
            report.Message = string.Empty;
        }

        protected bool FinishReport(bool success)
        {
            report.CurrentState = success ? State.FinishedSuccess : State.FinishedFail;
            return success;
        }

        protected void AddMessage(string msg)
        {
            report.Message += string.IsNullOrEmpty(report.Message) ? msg : $"{Environment.NewLine}{msg}";
        }

        protected bool Fail(string msg)
        {
            AddMessage(msg);
            report.CurrentState = State.FinishedFail;
            return false;
        }

        protected bool Pass(string msg)
        {
            AddMessage(msg);
            report.CurrentState = State.FinishedSuccess;
            return true;
        }

        protected void AddQueue(string msg)
        {
            Dispatcher.UIThread.InvokeAsync(() => 
                report.Message += string.IsNullOrEmpty(report.Message) ? msg : $"{Environment.NewLine}{msg}");
        }

        protected string GetKeyPerSec(BigInteger total, double totalSecond)
        {
            if (totalSecond < 1)
            {
                return "k/s= ∞";
            }
            else
            {
                return $"k/s= {total / new BigInteger(totalSecond):n0}";
            }
        }
    }
}
