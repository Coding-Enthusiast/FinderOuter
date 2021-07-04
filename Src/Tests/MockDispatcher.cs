// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using Avalonia.Threading;
using System;
using System.Threading.Tasks;

namespace Tests
{
    public class MockDispatcher : IDispatcher
    {
        public bool CheckAccess()
        {
            throw new NotImplementedException();
        }

        public Task InvokeAsync(Action action, DispatcherPriority priority = DispatcherPriority.Normal)
        {
            throw new NotImplementedException();
        }

        public Task<TResult> InvokeAsync<TResult>(Func<TResult> function, DispatcherPriority priority = DispatcherPriority.Normal)
        {
            function.Invoke();
            return null;
        }

        public Task InvokeAsync(Func<Task> function, DispatcherPriority priority = DispatcherPriority.Normal)
        {
            throw new NotImplementedException();
        }

        public Task<TResult> InvokeAsync<TResult>(Func<Task<TResult>> function, DispatcherPriority priority = DispatcherPriority.Normal)
        {
            throw new NotImplementedException();
        }

        public void Post(Action action, DispatcherPriority priority = DispatcherPriority.Normal)
        {
            throw new NotImplementedException();
        }

        public void VerifyAccess()
        {
            throw new NotImplementedException();
        }
    }
}
