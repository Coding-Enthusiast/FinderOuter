// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Autarkysoft.Bitcoin.ImprovementProposals;
using FinderOuter.Models;
using FinderOuter.ViewModels;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Reflection;

namespace Tests.ViewModels
{
    public class MissingMnemonicViewModelTests
    {
        [Fact]
        public void ConstructorTest()
        {
            Settings settings = new();
            MissingMnemonicViewModel vm = new(settings);

            Assert.Same(settings, vm.Result.Settings);
            Assert.NotNull(vm.MnService);
            Assert.NotEmpty(vm.WordListsList);
            Assert.Equal(BIP0039.WordLists.English, vm.SelectedWordListType);
            Assert.Equal(MnemonicTypes.BIP39, vm.SelectedMnemonicType);
            Assert.Equal(ElectrumMnemonic.MnemonicType.Undefined, vm.SelectedElectrumMnType);
            Assert.False(vm.IsElectrumTypesVisible);
            Assert.NotEmpty(vm.MnemonicTypesList);
            Assert.NotEmpty(vm.ElectrumMnemonicTypesList);
            Assert.NotEmpty(vm.CompareInputTypeList);
            Assert.NotNull(vm.SelectedCompareInputType);
            Assert.NotNull(vm.FindCommand);
            Assert.NotNull(vm.ExampleCommand);
            Assert.True(vm.HasExample);
            Assert.NotNull(vm.StartCommand);
            Assert.NotNull(vm.AddAllCommand);
            Assert.NotNull(vm.AddExactCommand);
            Assert.NotNull(vm.AddSimilarCommand);
            Assert.NotNull(vm.AddStartCommand);
            Assert.NotNull(vm.AddEndCommand);
            Assert.NotNull(vm.AddContainCommand);
        }

        [Fact]
        public void PropertyChangedTest()
        {
            MissingMnemonicViewModel vm = new(new Settings());

            Assert.PropertyChanged(vm, nameof(vm.WordList), () => vm.WordList = Array.Empty<string>());
            Assert.PropertyChanged(vm, nameof(vm.SelectedWordListType), () => vm.SelectedWordListType = BIP0039.WordLists.French);
            Assert.PropertyChanged(vm, nameof(vm.SelectedMnemonicType), () => vm.SelectedMnemonicType = MnemonicTypes.Electrum);
            Assert.PropertyChanged(vm, nameof(vm.SelectedElectrumMnType), () => vm.SelectedElectrumMnType = ElectrumMnemonic.MnemonicType.Standard);
            Assert.PropertyChanged(vm, nameof(vm.KeyPath), () => vm.SelectedElectrumMnType = ElectrumMnemonic.MnemonicType.SegWit);
            Assert.PropertyChanged(vm, nameof(vm.PassPhrase), () => vm.PassPhrase = "foo");
            Assert.PropertyChanged(vm, nameof(vm.KeyPath), () => vm.KeyPath = "foo");
        }

        [Fact]
        public void IsElectrumTypesVisibleTest()
        {
            MissingMnemonicViewModel vm = new(new Settings());
            Assert.Equal(MnemonicTypes.BIP39, vm.SelectedMnemonicType);
            Assert.PropertyChanged(vm, nameof(vm.IsElectrumTypesVisible), () => vm.SelectedMnemonicType = MnemonicTypes.Electrum);
            Assert.True(vm.IsElectrumTypesVisible);
            Assert.PropertyChanged(vm, nameof(vm.IsElectrumTypesVisible), () => vm.SelectedMnemonicType = MnemonicTypes.BIP39);
            Assert.False(vm.IsElectrumTypesVisible);
        }


        private static void CheckAllItems(MissingMnemonicViewModel vm, int expCount)
        {
            FieldInfo fi = typeof(MissingMnemonicViewModel).GetField("allItems", BindingFlags.NonPublic | BindingFlags.Instance);
            if (fi is null)
            {
                Assert.Fail("The private field was not found.");
            }

            object fieldVal = fi.GetValue(vm);
            if (fieldVal is null)
            {
                Assert.Fail("The private field value was null.");
            }
            else if (fieldVal is ObservableCollection<string>[] actual)
            {
                Assert.NotNull(actual);
                Assert.Equal(expCount, actual.Length);
                foreach (var item in actual)
                {
                    Assert.NotNull(item);
                }
            }
            else
            {
                Assert.Fail($"Field value is not the same type as expected.{Environment.NewLine}" +
                            $"Actual type: {fieldVal.GetType()}{Environment.NewLine}" +
                            $"Expected type: ObservableCollection<string>[]");
            }
        }

        internal class VM : MissingMnemonicViewModel
        {
            internal static VM Build()
            {
                VM vm = new()
                {
                    Input = "ozone drill grab fiber curtain grace pudding thank cruise elder * *"
                };
                vm.Start();
                vm.SetCurrentItems();
                return vm;
            }

            internal void SetCurrentItems(IEnumerable<string> arr = null)
            {
                arr ??= Array.Empty<string>();
                CurrentItems = new(arr);
            }

            internal void CheckAllItems(int expCount)
            {
                Assert.NotNull(allItems);
                Assert.Equal(expCount, allItems.Length);
                foreach (var item in allItems)
                {
                    Assert.NotNull(item);
                }
            }
        }

        public static IEnumerable<object[]> GetStartCases()
        {
            yield return new object[] { string.Empty, "Mnemonic can not be null or empty.", false, 0, 0 };
            yield return new object[]
            {
                "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
                string.Empty,
                true, 0, 0
            };
            yield return new object[]
            {
                "ozone drill grab fiber curtain grace pudding thank cruise elder eight *",
                string.Empty,
                true, 1, 1
            };
            yield return new object[]
            {
                "ozone drill grab fiber curtain grace pudding thank cruise * * *",
                string.Empty,
                true, 1, 3
            };
        }
        [Theory]
        [MemberData(nameof(GetStartCases))]
        public void StartTest(string input, string expMsg, bool expSuccess, int expIndex, int expMax)
        {
            VM vm = new()
            {
                Input = input
            };
            vm.Start();

            Assert.Equal(expMsg, vm.Result.Message);
            Assert.Equal(expSuccess, vm.IsProcessed);
            Assert.Equal(expIndex, vm.Index);
            Assert.Equal(expMax, vm.Max);
            if (expMax > 0)
            {
                vm.CheckAllItems(expMax);
            }
        }


        [Fact]
        public void AddAllTest()
        {
            VM vm = VM.Build();

            vm.AddAll();
            Assert.Equal(2048, vm.CurrentItems.Count);
            Assert.Equal("abandon", vm.CurrentItems[0]);

            // Make sure it doesn't add duplicates
            vm.CurrentItems.Clear();
            vm.CurrentItems.Add("abandon");
            Assert.Single(vm.CurrentItems);
            vm.AddAll();
            Assert.Equal(2048, vm.CurrentItems.Count);
            Assert.Equal("abandon", vm.CurrentItems[0]);
            Assert.Equal(1, vm.CurrentItems.Count(x => x == "abandon"));
        }

        [Fact]
        public void AddSimilarTest()
        {
            VM vm = VM.Build();

            vm.ToAdd = null;
            vm.AddSimilar();
            Assert.Equal("Word to add can not be null or empty.", vm.Result.Message);
            vm.Result.Message = string.Empty; // Make future tests easier
            Assert.Empty(vm.CurrentItems);

            vm.ToAdd = string.Empty;
            vm.AddSimilar();
            Assert.Equal("Word to add can not be null or empty.", vm.Result.Message);
            vm.Result.Message = string.Empty;
            Assert.Empty(vm.CurrentItems);

            vm.ToAdd = "act";
            vm.AddSimilar();
            Assert.Equal(3, vm.CurrentItems.Count);
            Assert.Equal("act", vm.CurrentItems[0]);
            Assert.Equal("art", vm.CurrentItems[1]);
            Assert.Equal("pact", vm.CurrentItems[2]);
            Assert.Equal(string.Empty, vm.ToAdd);

            vm.ToAdd = "act";
            vm.AddSimilar();
            Assert.Equal(3, vm.CurrentItems.Count);
            Assert.Equal("act", vm.CurrentItems[0]);
            Assert.Equal("art", vm.CurrentItems[1]);
            Assert.Equal("pact", vm.CurrentItems[2]);
            Assert.Equal(string.Empty, vm.ToAdd);

            vm.ToAdd = " bAr  ";
            vm.AddSimilar();
            Assert.Equal(7, vm.CurrentItems.Count);
            Assert.Equal("act", vm.CurrentItems[0]);
            Assert.Equal("art", vm.CurrentItems[1]);
            Assert.Equal("pact", vm.CurrentItems[2]);
            Assert.Equal("bag", vm.CurrentItems[3]);
            Assert.Equal("bar", vm.CurrentItems[4]);
            Assert.Equal("car", vm.CurrentItems[5]);
            Assert.Equal("jar", vm.CurrentItems[6]);
            Assert.Equal(string.Empty, vm.ToAdd);
        }

        [Fact]
        public void AddExactTest()
        {
            VM vm = VM.Build();

            vm.ToAdd = null;
            vm.AddExact();
            Assert.Equal("The entered word () is not found in selected word-list.", vm.Result.Message);
            vm.Result.Message = string.Empty; // Make future tests easier
            Assert.Empty(vm.CurrentItems);

            vm.ToAdd = string.Empty;
            vm.AddExact();
            Assert.Equal("The entered word () is not found in selected word-list.", vm.Result.Message);
            vm.Result.Message = string.Empty; // Make future tests easier
            Assert.Empty(vm.CurrentItems);

            vm.ToAdd = "foo";
            vm.AddExact();
            Assert.Equal("The entered word (foo) is not found in selected word-list.", vm.Result.Message);
            vm.Result.Message = string.Empty; // Make future tests easier
            Assert.Empty(vm.CurrentItems);
            Assert.Equal("foo", vm.ToAdd);

            vm.ToAdd = "gold";
            vm.AddExact();
            Assert.Single(vm.CurrentItems);
            Assert.Equal("gold", vm.CurrentItems[0]);

            // Trim and lower
            vm.ToAdd = "  ALmOsT    ";
            vm.AddExact();
            Assert.Equal(2, vm.CurrentItems.Count);
            Assert.Equal("gold", vm.CurrentItems[0]);
            Assert.Equal("almost", vm.CurrentItems[1]);
            Assert.Equal(string.Empty, vm.ToAdd);

            // no duplicate
            vm.ToAdd = "almost";
            vm.AddExact();
            Assert.Equal(2, vm.CurrentItems.Count);
            Assert.Equal("gold", vm.CurrentItems[0]);
            Assert.Equal("almost", vm.CurrentItems[1]);
            Assert.Equal(string.Empty, vm.ToAdd);
        }

        [Fact]
        public void AddStartTest()
        {
            VM vm = VM.Build();

            vm.ToAdd = null;
            vm.AddStart();
            Assert.Equal("Word to add can not be null or empty.", vm.Result.Message);
            vm.Result.Message = string.Empty; // Make future tests easier
            Assert.Empty(vm.CurrentItems);

            vm.ToAdd = string.Empty;
            vm.AddStart();
            Assert.Equal("Word to add can not be null or empty.", vm.Result.Message);
            vm.Result.Message = string.Empty; // Make future tests easier
            Assert.Empty(vm.CurrentItems);

            vm.ToAdd = "   ";
            vm.AddStart();
            Assert.Equal("Word to add can not be null or empty.", vm.Result.Message);
            vm.Result.Message = string.Empty; // Make future tests easier
            Assert.Empty(vm.CurrentItems);

            vm.ToAdd = "xyz";
            vm.AddStart();
            Assert.Empty(vm.CurrentItems);

            vm.ToAdd = "cro";
            vm.AddStart();
            Assert.Equal(4, vm.CurrentItems.Count);
            Assert.Equal("crop", vm.CurrentItems[0]);
            Assert.Equal("cross", vm.CurrentItems[1]);
            Assert.Equal("crouch", vm.CurrentItems[2]);
            Assert.Equal("crowd", vm.CurrentItems[3]);
            Assert.Equal(string.Empty, vm.ToAdd);

            vm.ToAdd = "  the   ";
            vm.AddStart();
            Assert.Equal(9, vm.CurrentItems.Count);
            Assert.Equal("crop", vm.CurrentItems[0]);
            Assert.Equal("cross", vm.CurrentItems[1]);
            Assert.Equal("crouch", vm.CurrentItems[2]);
            Assert.Equal("crowd", vm.CurrentItems[3]);
            Assert.Equal("theme", vm.CurrentItems[4]);
            Assert.Equal("then", vm.CurrentItems[5]);
            Assert.Equal("theory", vm.CurrentItems[6]);
            Assert.Equal("there", vm.CurrentItems[7]);
            Assert.Equal("they", vm.CurrentItems[8]);
            Assert.Equal(string.Empty, vm.ToAdd);
        }

        [Fact]
        public void AddEndTest()
        {
            VM vm = VM.Build();

            vm.ToAdd = null;
            vm.AddEnd();
            Assert.Equal("Word to add can not be null or empty.", vm.Result.Message);
            vm.Result.Message = string.Empty; // Make future tests easier
            Assert.Empty(vm.CurrentItems);

            vm.ToAdd = string.Empty;
            vm.AddEnd();
            Assert.Equal("Word to add can not be null or empty.", vm.Result.Message);
            vm.Result.Message = string.Empty; // Make future tests easier
            Assert.Empty(vm.CurrentItems);

            vm.ToAdd = "   ";
            vm.AddEnd();
            Assert.Equal("Word to add can not be null or empty.", vm.Result.Message);
            vm.Result.Message = string.Empty; // Make future tests easier
            Assert.Empty(vm.CurrentItems);

            vm.ToAdd = "xyz";
            vm.AddEnd();
            Assert.Empty(vm.CurrentItems);

            vm.ToAdd = "out";
            vm.AddEnd();
            Assert.Equal(2, vm.CurrentItems.Count);
            Assert.Equal("about", vm.CurrentItems[0]);
            Assert.Equal("scout", vm.CurrentItems[1]);
            Assert.Equal(string.Empty, vm.ToAdd);

            vm.ToAdd = "  oud    ";
            vm.AddEnd();
            Assert.Equal(5, vm.CurrentItems.Count);
            Assert.Equal("about", vm.CurrentItems[0]);
            Assert.Equal("scout", vm.CurrentItems[1]);
            Assert.Equal("cloud", vm.CurrentItems[2]);
            Assert.Equal("loud", vm.CurrentItems[3]);
            Assert.Equal("proud", vm.CurrentItems[4]);
            Assert.Equal(string.Empty, vm.ToAdd);
        }

        [Fact]
        public void AddContainTest()
        {
            VM vm = VM.Build();

            vm.ToAdd = null;
            vm.AddContain();
            Assert.Equal("Word to add can not be null or empty.", vm.Result.Message);
            vm.Result.Message = string.Empty; // Make future tests easier
            Assert.Empty(vm.CurrentItems);

            vm.ToAdd = string.Empty;
            vm.AddContain();
            Assert.Equal("Word to add can not be null or empty.", vm.Result.Message);
            vm.Result.Message = string.Empty; // Make future tests easier
            Assert.Empty(vm.CurrentItems);

            vm.ToAdd = "   ";
            vm.AddContain();
            Assert.Equal("Word to add can not be null or empty.", vm.Result.Message);
            vm.Result.Message = string.Empty; // Make future tests easier
            Assert.Empty(vm.CurrentItems);

            vm.ToAdd = "xyz";
            vm.AddContain();
            Assert.Empty(vm.CurrentItems);

            vm.ToAdd = "arbage";
            vm.AddContain();
            Assert.Single(vm.CurrentItems);
            Assert.Equal("garbage", vm.CurrentItems[0]);
            Assert.Equal(string.Empty, vm.ToAdd);

            vm.ToAdd = "  out    ";
            vm.AddContain();
            Assert.Equal(10, vm.CurrentItems.Count);
            Assert.Equal("garbage", vm.CurrentItems[0]);
            Assert.Equal("about", vm.CurrentItems[1]);
            Assert.Equal(string.Empty, vm.ToAdd);
        }
    }
}
