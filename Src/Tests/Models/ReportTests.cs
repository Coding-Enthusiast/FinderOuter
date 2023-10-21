// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Avalonia.Threading;
using FinderOuter.Models;
using System;

namespace Tests.Models
{
    public class ReportTests
    {
        private static readonly IDispatcher MockDispatcher = new MockDispatcher();


        [Fact]
        public void ConstructorTest()
        {
            Report report = new();

            Assert.Equal(State.Ready, report.CurrentState);
            Assert.False(report.FoundAnyResult);
            Assert.False(report.IsProgressVisible);
            Assert.Equal(string.Empty, report.Message);
            Assert.Equal(0, report.Progress);
            Assert.NotNull(report.Timer);
            Assert.False(report.Timer.IsRunning);
            Assert.Equal(0, report.Timer.ElapsedMilliseconds);
            Assert.Equal(0, report.Total);
            Assert.NotNull(report.UIThread);
        }

        [Fact]
        public void PropertyChangedTest()
        {
            Report rep = new();

            Assert.PropertyChanged(rep, nameof(rep.CurrentState), () => rep.CurrentState = State.FinishedSuccess);
            Assert.PropertyChanged(rep, nameof(rep.IsProgressVisible), () => rep.IsProgressVisible = true);
            Assert.PropertyChanged(rep, nameof(rep.Message), () => rep.Message = "foo");
            Assert.PropertyChanged(rep, nameof(rep.Progress), () => rep.Progress = 0.9);
        }

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
            report.SetTotal(1);
            Assert.Equal(1, report.Total);

            report.Init();

            Assert.Equal(State.Working, report.CurrentState);
            Assert.False(report.FoundAnyResult);
            Assert.False(report.IsProgressVisible);
            Assert.Equal(string.Empty, report.Message);
            Assert.Equal(0, report.Progress);
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
        public void FinalizeTest(bool found, State expState, bool useTimer, bool setTotal)
        {
            Report report = new(MockDispatcher)
            {
                CurrentState = State.Ready,
                FoundAnyResult = found,
                Message = "Foo",
                Progress = 50,
            };

            if (useTimer)
            {
                report.Timer.Start();
            }
            if (setTotal)
            {
                report.SetTotal(10, 3);
            }

            bool actual = report.Finalize();
            Assert.Equal(found, actual);

            Assert.Equal(expState, report.CurrentState);
            Assert.Equal(100, report.Progress);
            Assert.False(report.Timer.IsRunning);
            if (useTimer)
            {
                Assert.Contains("Foo", report.Message);
                Assert.Contains("Elapsed time:", report.Message);
                if (setTotal)
                {
                    Assert.Contains("k/s", report.Message);
                }
            }
            else if (setTotal)
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
        public void Finalize_WithBoolTest()
        {
            Report report = new(MockDispatcher);

            Assert.True(report.Finalize(true));
            Assert.Equal(State.FinishedSuccess, report.CurrentState);

            Assert.False(report.Finalize(false));
            Assert.Equal(State.FinishedFail, report.CurrentState);
        }

        [Fact]
        public void SetTotalTest()
        {
            Report report = new(MockDispatcher);

            report.SetTotal(10, 3);
            Assert.Equal(1000, report.Total);
            Assert.Equal("Total number of permutations to check: 1,000", report.Message);

            report.SetTotal(10_000);
            Assert.Equal(10_000, report.Total);
            Assert.Contains("Total number of permutations to check: 10,000", report.Message);
        }

        [Theory]
        [InlineData(20, 55)]
        [InlineData(73, 51.36986301369863)]
        [InlineData(170, 50.588235294117645)]
        public void ProgressTest(int step, double expected)
        {
            Report report = new(MockDispatcher)
            {
                Progress = 50,
            };

            report.SetProgressStep(step);
            Assert.Equal(50, report.Progress);

            report.IncrementProgress();
            Assert.Equal(expected, report.Progress);
        }

        [Fact]
        public void AddMessageTest()
        {
            Report report = new(MockDispatcher);

            report.AddMessage("foo");
            Assert.Equal("foo", report.Message);
            report.AddMessage("bar");
            Assert.Equal($"foo{Environment.NewLine}bar", report.Message);
        }

        [Fact]
        public void AddMessageSafeTest()
        {
            Report report = new(MockDispatcher);

            report.AddMessageSafe("foo");
            Assert.Equal("foo", report.Message);
            report.AddMessageSafe("bar");
            Assert.Equal($"foo{Environment.NewLine}bar", report.Message);
        }

        [Fact]
        public void FailTest()
        {
            Report report = new(MockDispatcher);

            Assert.False(report.Fail("foo"));
            Assert.Equal(State.FinishedFail, report.CurrentState);
            Assert.Equal("foo", report.Message);
        }

        [Fact]
        public void PassTest()
        {
            Report report = new(MockDispatcher);

            Assert.True(report.Pass("foo"));
            Assert.Equal(State.FinishedSuccess, report.CurrentState);
            Assert.Equal("foo", report.Message);
        }

        [Theory]
        [InlineData(10000, -1, "k/s= ∞")]
        [InlineData(10000, 0, "k/s= ∞")]
        [InlineData(10000, 1000, "k/s= 10")]
        [InlineData(10000, 10, "k/s= 1,000")]
        public void SetKeyPerSecTest(int total, int time, string exp)
        {
            Report report = new(MockDispatcher);
            report.SetKeyPerSecSafe(total, time);
            Assert.Equal(exp, report.Message);
        }

        [Fact]
        public void ProgressBarTest()
        {
            Report report = new(MockDispatcher);
            Assert.False(report.IsProgressVisible);
            Assert.Equal(0, report.Progress);

            report.SetProgressStep(400);
            Assert.Contains("Running in parallel.", report.Message);
            Assert.True(report.IsProgressVisible);
            Helper.ComparePrivateField(report, "percent", 0.25d);
            Assert.Equal(0, report.Progress);

            report.IncrementProgress();
            Assert.Equal(0.25d, report.Progress);
        }
    }
}
