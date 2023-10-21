// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using FinderOuter.Models;
using FinderOuter.Services;
using FinderOuter.ViewModels;
using System.Threading.Tasks;

namespace Tests
{
    public class MockWindowManager : IWindowManager
    {
        public MockWindowManager(VmWithSizeBase vm)
        {
            expectedVm = vm;
        }
        public MockWindowManager(MessageBoxType mbt, string msg, MessageBoxResult res)
        {
            expectedMsgBoxType = mbt;
            expectedMsg = msg;
            msgBoxResultToReturn = res;
        }


        private readonly VmWithSizeBase expectedVm;
        private readonly MessageBoxType expectedMsgBoxType;
        private readonly string expectedMsg;
        private readonly MessageBoxResult msgBoxResultToReturn;


        public void ShowDialog(VmWithSizeBase vm)
        {
            Assert.NotNull(expectedVm);
            Assert.IsType(expectedVm.GetType(), vm);
        }

        public async Task<MessageBoxResult> ShowMessageBox(MessageBoxType mbType, string message)
        {
            Assert.NotNull(expectedMsg);
            Assert.Equal(expectedMsgBoxType, mbType);
            Assert.Equal(expectedMsg, message);

            return msgBoxResultToReturn;
        }
    }
}
