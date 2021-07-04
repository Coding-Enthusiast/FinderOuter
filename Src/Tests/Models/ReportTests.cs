// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Models;
using Xunit;

namespace Tests.Models
{
    public class ReportTests
    {
        [Fact]
        public void InitTest()
        {
            var report = new Report
            {
                CurrentState = State.FinishedFail,
                FoundAnyResult = true,
                Message = "Foo",
                Progress = 50,
                IsProgressVisible = true
            };
            report.Timer.Start();

            report.Init();

            Assert.Equal(State.Working, report.CurrentState);
            Assert.False(report.FoundAnyResult);
            Assert.Equal(string.Empty, report.Message);
            Assert.Equal(0, report.Progress);
            Assert.False(report.IsProgressVisible);
            Assert.False(report.Timer.IsRunning);
            Assert.Equal(0, report.Timer.ElapsedMilliseconds);
        }


        [Theory]
        [InlineData(false, State.FinishedFail, false)]
        [InlineData(true, State.FinishedSuccess, false)]
        [InlineData(false, State.FinishedFail, true)]
        public void Finalize_FailRunTest(bool found, State expState, bool timer)
        {
            var report = new Report(new MockDispatcher())
            {
                CurrentState = State.Ready,
                FoundAnyResult = found,
                Message = "Foo",
                Progress = 50,
            };

            if (timer)
            {
                report.Timer.Start();
            }

            report.Finalize();

            Assert.Equal(expState, report.CurrentState);
            Assert.Equal(100, report.Progress);
            Assert.False(report.Timer.IsRunning);
            if (timer)
            {
                Assert.Contains("Foo", report.Message);
                Assert.Contains("Elapsed time:", report.Message);
            }
            else
            {
                Assert.Equal("Foo", report.Message);
            }
        }

        [Theory]
        [InlineData(20, 55)]
        [InlineData(73, 51.36986301369863)]
        [InlineData(170, 50.588235294117645)]
        public void ProgressTest(int step, double expected)
        {
            var report = new Report(new MockDispatcher())
            {
                Progress = 50,
            };

            report.SetProgressStep(step);
            Assert.Equal(50, report.Progress);

            report.IncrementProgress();
            Assert.Equal(expected, report.Progress);
        }
    }
}
