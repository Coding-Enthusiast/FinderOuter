// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Avalonia.Threading;
using System;

namespace Tests
{
    public class MockDispatcher : IDispatcher
    {
        public bool CheckAccess()
        {
            throw new NotImplementedException();
        }

        public void Post(Action action, DispatcherPriority priority)
        {
            action.Invoke();
        }

        public void VerifyAccess()
        {
            throw new NotImplementedException();
        }
    }
}
