// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Models;
using FinderOuter.Services;
using FinderOuter.ViewModels;
using System;
using System.Collections.ObjectModel;

namespace Tests.ViewModels
{
    public class OptionVmBaseTests
    {
        private class MockOptVm : OptionVmBase
        {
            public MockOptVm()
            {
            }

            public MockOptVm(IReport rep, IWindowManager wm) : base(rep, wm)
            {
            }

            public override string OptionName => "Name!";
            public override string Description => "Description!";
            public override void Find()
            {
                throw new NotImplementedException();
            }

            internal void SetAllItems()
            {
                allItems = new ObservableCollection<string>[2]
                {
                    new(MockItems1), new(MockItems2)
                };
            }

            internal void AssertIsChanged(bool expected) => Assert.Equal(expected, isChanged);
            internal void SetCurrentItems(string[] items) => CurrentItems = new(items);
            internal void SetSelectedStep() => SelectedStep = MockStep;
            internal void SetIndex(int value) => Index = value;
            internal void SearchSpaceReset() => ResetSearchSpace();
            internal void AssertEmptyAllItems() => Assert.Empty(allItems);
            internal void SetExampleTest(ExampleData data) => SetExamples(data);
            internal void AssertTotalExampleCount(int expected) => Assert.Equal(expected, totalExampleCount);
            internal void AssertTotalExampleIndex(int expected) => Assert.Equal(expected, exampleIndex);

            internal void GetNextExampleTest(object[] expected)
            {
                object[] actual = GetNextExample();
                Assert.Equal(expected, actual);
            }
        }


        private static readonly string[] MockItems1 = new string[] { "Foo1", "Foo2", "Foo3", "Foo4" };
        private static readonly string[] MockItems2 = new string[] { "Bar1", "Bar2", "Bar3" };
        private const int MockIndex = 2;
        private const string MockStep = "MockStep";


        [Fact]
        public void CtorTest()
        {
            MockOptVm vm = new();

            Assert.NotEmpty(vm.MissingChars);
            Assert.Equal(vm.SelectedMissingChar, vm.MissingChars[0]);
            Assert.NotNull(vm.Result);
            Assert.NotNull(vm.WinMan);
            Assert.NotNull(vm.NextCommand);
            Assert.NotNull(vm.PreviousCommand);
            Assert.NotNull(vm.RemoveSelectedCommand);
            Assert.NotNull(vm.ClearAllCommand);
            Assert.Equal(string.Empty, vm.ExampleButtonName);
            Assert.False(vm.IsProcessed);
            Assert.False(vm.HasExample);
        }

        [Fact]
        public void Ctor_NullProperty_Test()
        {
            MockOptVm vm = new(null, null);
            Assert.NotNull(vm.Result);
            Assert.NotNull(vm.WinMan);
        }

        [Fact]
        public void IsChangedTest()
        {
            MockOptVm vm = new();
            vm.AssertIsChanged(false);
            vm.Input = "foo";
            vm.AssertIsChanged(true);
        }

        [Fact]
        public void PropertyChangedTest()
        {
            MockOptVm vm = new();
            vm.SetAllItems();

            Assert.PropertyChanged(vm, nameof(vm.SelectedMissingChar), () => vm.SelectedMissingChar = 'c');
            Assert.PropertyChanged(vm, nameof(vm.Input), () => vm.Input = "foo");
            Assert.PropertyChanged(vm, nameof(vm.CompareInput), () => vm.CompareInput = "foo");
            Assert.PropertyChanged(vm, nameof(vm.SelectedCompareInputType),
                                    () => vm.SelectedCompareInputType = new(CompareInputType.Pubkey));
            Assert.PropertyChanged(vm, nameof(vm.CurrentItems), () => vm.SetCurrentItems(MockItems1));
            Assert.PropertyChanged(vm, nameof(vm.SelectedItem), () => vm.SelectedItem = "foo");
            Assert.PropertyChanged(vm, nameof(vm.SelectedStep), () => vm.SetSelectedStep());
            Assert.PropertyChanged(vm, nameof(vm.Max), () => vm.Max = 1);
            Assert.PropertyChanged(vm, nameof(vm.Index), () => vm.SetIndex(MockIndex));
            Assert.PropertyChanged(vm, nameof(vm.IsProcessed), () => vm.IsProcessed = true);
            Assert.PropertyChanged(vm, nameof(vm.ToAdd), () => vm.ToAdd = "foo");
            Assert.PropertyChanged(vm, nameof(vm.ExampleButtonName), () => vm.ExampleButtonName = "foo");
        }

        [Fact]
        public void PropertySetTest()
        {
            MockOptVm vm = new();
            vm.SetAllItems();

            vm.CompareInput = "comp";
            Assert.Equal("comp", vm.CompareInput);

            vm.SetCurrentItems(MockItems1);
            Assert.Equal(MockItems1, vm.CurrentItems);

            vm.ExampleButtonName = "exbtn";
            Assert.Equal("exbtn", vm.ExampleButtonName);

            vm.SetIndex(MockIndex);
            Assert.Equal(MockIndex, vm.Index);

            vm.Input = "input";
            Assert.Equal("input", vm.Input);

            vm.IsProcessed = true;
            Assert.True(vm.IsProcessed);

            vm.Max = 100;
            Assert.Equal(100, vm.Max);

            vm.SelectedCompareInputType = new(CompareInputType.PrivateKey);
            Assert.Equal(CompareInputType.PrivateKey, vm.SelectedCompareInputType.Value);

            vm.SelectedItem = "selitem";
            Assert.Equal("selitem", vm.SelectedItem);

            vm.SelectedMissingChar = 'x';
            Assert.Equal('x', vm.SelectedMissingChar);

            vm.SetSelectedStep();
            Assert.Equal(MockStep, vm.SelectedStep);

            vm.ToAdd = " aD d "; // Don't remove space or change casing
            Assert.Equal(" aD d ", vm.ToAdd);
        }


        [Fact]
        public void OpenKBTest()
        {
            KnowledgeBaseViewModel expVm = new(KB.Bip32Path);
            MockWindowManager winMan = new(expVm);
            MockOptVm vm = new(null, winMan);
            vm.OpenKB(KB.Bip32Path);
        }


        [Fact]
        public void IndexTest()
        {
            MockOptVm vm = new();
            vm.SetAllItems();
            vm.Max = 2;

            Assert.Equal(0, vm.Index);

            // Invalid values (negative and bigger than all-items count
            vm.SetIndex(-1);
            Assert.Equal(0, vm.Index);
            vm.SetIndex(3);
            Assert.Equal(0, vm.Index);

            vm.SetIndex(1);
            Assert.Equal(1, vm.Index);
            Assert.Equal(MockItems1, vm.CurrentItems);
            Assert.Equal("1/2", vm.SelectedStep);

            vm.SetIndex(2);
            Assert.Equal(2, vm.Index);
            Assert.Equal(MockItems2, vm.CurrentItems);
            Assert.Equal("2/2", vm.SelectedStep);

            vm.SetIndex(0);
            Assert.Equal(0, vm.Index);
            Assert.Null(vm.CurrentItems);
            Assert.Equal(string.Empty, vm.SelectedStep);
        }

        [Fact]
        public void ResetSearchSpaceTest()
        {
            MockOptVm vm = new();
            vm.SetAllItems();
            vm.Max = 2;
            vm.SetIndex(1);
            vm.IsProcessed = true;

            vm.SearchSpaceReset();

            Assert.Equal(0, vm.Index);
            Assert.Equal(0, vm.Max);
            vm.AssertEmptyAllItems();
            Assert.False(vm.IsProcessed);
        }

        [Fact]
        public void NextTest()
        {
            MockOptVm vm = new();
            vm.SetAllItems();
            Assert.Equal(0, vm.Index);

            vm.Next();
            Assert.Equal(1, vm.Index);

            vm.Next();
            Assert.Equal(2, vm.Index);

            // Overflow
            vm.Next();
            Assert.Equal(0, vm.Index);
        }

        [Fact]
        public void PreviousTest()
        {
            MockOptVm vm = new();
            vm.SetAllItems();
            Assert.Equal(0, vm.Index);
            vm.SetIndex(2);
            Assert.Equal(2, vm.Index);

            vm.Previous();
            Assert.Equal(1, vm.Index);

            vm.Previous();
            Assert.Equal(0, vm.Index);

            // Overflow
            vm.Previous();
            Assert.Equal(0, vm.Index);
        }

        [Fact]
        public void ExamplesTest()
        {
            ExampleData<char, int> data = new()
            {
                { 'a', 1 },
                { 'b', 2 },
                { 'c', 3 },
            };
            MockOptVm vm = new();
            Assert.False(vm.HasExample);

            vm.SetExampleTest(data);
            Assert.True(vm.HasExample);
            vm.AssertTotalExampleCount(3);
            vm.AssertTotalExampleIndex(0);
            Assert.Equal("3 Examples", vm.ExampleButtonName);

            vm.GetNextExampleTest(new object[] { 'a', 1 });
            vm.AssertTotalExampleIndex(1);
            Assert.Equal("Example 1/3", vm.ExampleButtonName);

            vm.GetNextExampleTest(new object[] { 'b', 2 });
            vm.AssertTotalExampleIndex(2);
            Assert.Equal("Example 2/3", vm.ExampleButtonName);

            vm.GetNextExampleTest(new object[] { 'c', 3 });
            vm.AssertTotalExampleIndex(3);
            Assert.Equal("Example 3/3", vm.ExampleButtonName);

            vm.GetNextExampleTest(new object[] { 'a', 1 });
            vm.AssertTotalExampleIndex(1);
            Assert.Equal("Example 1/3", vm.ExampleButtonName);
        }
    }
}
