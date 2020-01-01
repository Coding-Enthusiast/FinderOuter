// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Models;
using System;
using System.Text;

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
        private readonly StringBuilder queue = new StringBuilder();


        protected void InitReport()
        {
            report.CurrentState = State.Working;
            report.Message = string.Empty;
            queue.Clear();
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
            queue.AppendLine(msg);
        }

        protected bool CopyQueueToMessage(bool hasPassed)
        {
            report.CurrentState = hasPassed ? State.FinishedSuccess : State.FinishedFail;
            AddMessage(queue.ToString());

            return hasPassed;
        }

    }
}
