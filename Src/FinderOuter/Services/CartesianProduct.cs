// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System;
using System.Collections.Generic;
using System.Linq;

namespace FinderOuter.Services
{
    [Obsolete("This class is very slow to use")]
    public class CartesianProduct
    {
        public static IEnumerable<IEnumerable<T>> Create<T>(IEnumerable<IEnumerable<T>> inputs)
        {
            return inputs.Aggregate(
               EnumerableFrom(Enumerable.Empty<T>()),
               (soFar, input) =>
                   from prevProductItem in soFar
                   from item in input
                   select prevProductItem.Append(item));
        }
        private static IEnumerable<T> EnumerableFrom<T>(T item)
        {
            return new T[] { item };
        }
    }
}
