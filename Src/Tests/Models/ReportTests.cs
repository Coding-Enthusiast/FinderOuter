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
            Report report = new()
            {
                CurrentState = State.FinishedFail,
                FoundAnyResult = true,
                Message = "Foo",
                Progress = 50,
                IsProgressVisible = true
            };
            report.Timer.Start();
            report.SetTotal(1, 1);
            Assert.Equal(1, report.Total);

            report.Init();

            Assert.Equal(State.Working, report.CurrentState);
            Assert.False(report.FoundAnyResult);
            Assert.Equal(string.Empty, report.Message);
            Assert.Equal(0, report.Progress);
            Assert.False(report.IsProgressVisible);
            Assert.False(report.Timer.IsRunning);
            Assert.Equal(0, report.Timer.ElapsedMilliseconds);
            Assert.Equal(0, report.Total);
        }


        [Theory]
        [InlineData(false, State.FinishedFail, false, false)]
        [InlineData(false, State.FinishedFail, false, true)]
        [InlineData(true, State.FinishedSuccess, false, false)]
        [InlineData(true, State.FinishedSuccess, false, true)]
        [InlineData(false, State.FinishedFail, true, false)]
        [InlineData(false, State.FinishedFail, true, true)]
        public void Finalize_FailRunTest(bool found, State expState, bool timer, bool total)
        {
            Report report = new(new MockDispatcher())
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
            if (total)
            {
                report.SetTotal(10, 3);
            }

            report.Finalize();

            Assert.Equal(expState, report.CurrentState);
            Assert.Equal(100, report.Progress);
            Assert.False(report.Timer.IsRunning);
            if (timer)
            {
                Assert.Contains("Foo", report.Message);
                Assert.Contains("Elapsed time:", report.Message);
                if (total)
                {
                    Assert.Contains("k/s", report.Message);
                }
            }
            else if (total)
            {
                Assert.Contains("Total", report.Message);
                Assert.DoesNotContain("k/s", report.Message);
            }
            else
            {
                Assert.Equal("Foo", report.Message);
            }
        }

        [Fact]
        public void SetTotalTest()
        {
            Report report = new(new MockDispatcher());
            report.SetTotal(10, 3);
            Assert.Equal(1000, report.Total);
            Assert.Equal("Total number of permutations to check: 1,000", report.Message);
        }

        [Theory]
        [InlineData(20, 55)]
        [InlineData(73, 51.36986301369863)]
        [InlineData(170, 50.588235294117645)]
        public void ProgressTest(int step, double expected)
        {
            Report report = new(new MockDispatcher())
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
