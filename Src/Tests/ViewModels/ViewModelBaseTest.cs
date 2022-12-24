// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.ViewModels;
using Xunit;

namespace Tests.ViewModels
{
    public class ViewModelBaseTest : ViewModelBase
    {
        [Fact]
        public void RaiseCloseEventTest()
        {
            bool raised = false;
            CLoseEvent += (sender, e) =>
            {
                raised = true;
            };

            RaiseCloseEvent();
            Assert.True(raised);
        }
    }
}
