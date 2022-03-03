// The FinderOuter
// Copyright (c) 2020 Coding Enthusiast
// Distributed under the MIT software license, see the accompanying
// file LICENCE or http://www.opensource.org/licenses/mit-license.php.

using System.Collections;
using System.Collections.Generic;
using System.Linq;

namespace FinderOuter.Models
{
    public class ExampleData : IEnumerable<object[]>
    {
        readonly List<object[]> data = new();

        public int Total => data.Count;

        protected void AddRow(params object[] values)
        {
            data.Add(values);
        }

        protected void AddRows(IEnumerable<object[]> rows)
        {
            foreach (object[] row in rows)
            {
                AddRow(row);
            }
        }

        public IEnumerator<object[]> GetEnumerator() => data.GetEnumerator();
        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }



    public class ExampleData<T> : ExampleData
    {
        public ExampleData(IEnumerable<T> values)
        {
            AddRange(values.ToArray());
        }

        public ExampleData(params T[] values)
        {
            AddRange(values);
        }

        public void Add(T p)
        {
            AddRow(p);
        }

        public void AddRange(params T[] values)
        {
            AddRows(values.Select(x => new object[] { x }));
        }
    }



    public class ExampleData<T1, T2> : ExampleData
    {
        public ExampleData(IEnumerable<(T1, T2)> values)
        {
            AddRange(values.ToArray());
        }

        public ExampleData(params (T1, T2)[] values)
        {
            AddRange(values);
        }

        public void Add(T1 p1, T2 p2)
        {
            AddRow(p1, p2);
        }

        public void AddRange(params (T1 p1, T2 p2)[] values)
        {
            AddRows(values.Select(x => new object[] { x.p1, x.p2 }));
        }
    }



    public class ExampleData<T1, T2, T3> : ExampleData
    {
        public ExampleData(IEnumerable<(T1, T2, T3)> values)
        {
            AddRange(values.ToArray());
        }

        public ExampleData(params (T1, T2, T3)[] values)
        {
            AddRange(values);
        }

        public void Add(T1 p1, T2 p2, T3 p3)
        {
            AddRow(p1, p2, p3);
        }

        public void AddRange(params (T1 p1, T2 p2, T3 p3)[] values)
        {
            AddRows(values.Select(x => new object[] { x.p1, x.p2, x.p3 }));
        }
    }



    public class ExampleData<T1, T2, T3, T4> : ExampleData
    {
        public ExampleData(IEnumerable<(T1, T2, T3, T4)> values)
        {
            AddRange(values.ToArray());
        }

        public ExampleData(params (T1, T2, T3, T4)[] values)
        {
            AddRange(values);
        }

        public void Add(T1 p1, T2 p2, T3 p3, T4 p4)
        {
            AddRow(p1, p2, p3, p4);
        }

        public void AddRange(params (T1 p1, T2 p2, T3 p3, T4 p4)[] values)
        {
            AddRows(values.Select(x => new object[] { x.p1, x.p2, x.p3, x.p4 }));
        }
    }



    public class ExampleData<T1, T2, T3, T4, T5> : ExampleData
    {
        public ExampleData(IEnumerable<(T1, T2, T3, T4, T5)> values)
        {
            AddRange(values.ToArray());
        }

        public ExampleData(params (T1, T2, T3, T4, T5)[] values)
        {
            AddRange(values);
        }

        public void Add(T1 p1, T2 p2, T3 p3, T4 p4, T5 p5)
        {
            AddRow(p1, p2, p3, p4, p5);
        }

        public void AddRange(params (T1 p1, T2 p2, T3 p3, T4 p4, T5 p5)[] values)
        {
            AddRows(values.Select(x => new object[] { x.p1, x.p2, x.p3, x.p4, x.p5 }));
        }
    }



    public class ExampleData<T1, T2, T3, T4, T5, T6> : ExampleData
    {
        public ExampleData(IEnumerable<(T1, T2, T3, T4, T5, T6)> values)
        {
            AddRange(values.ToArray());
        }

        public ExampleData(params (T1, T2, T3, T4, T5, T6)[] values)
        {
            AddRange(values);
        }

        public void Add(T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6)
        {
            AddRow(p1, p2, p3, p4, p5, p6);
        }

        public void AddRange(params (T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6)[] values)
        {
            AddRows(values.Select(x => new object[] { x.p1, x.p2, x.p3, x.p4, x.p5, x.p6 }));
        }
    }



    public class ExampleData<T1, T2, T3, T4, T5, T6, T7> : ExampleData
    {
        public ExampleData(IEnumerable<(T1, T2, T3, T4, T5, T6, T7)> values)
        {
            AddRange(values.ToArray());
        }

        public ExampleData(params (T1, T2, T3, T4, T5, T6, T7)[] values)
        {
            AddRange(values);
        }

        public void Add(T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6, T7 p7)
        {
            AddRow(p1, p2, p3, p4, p5, p6, p7);
        }

        public void AddRange(params (T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6, T7 p7)[] values)
        {
            AddRows(values.Select(x => new object[] { x.p1, x.p2, x.p3, x.p4, x.p5, x.p6, x.p7 }));
        }
    }



    public class ExampleData<T1, T2, T3, T4, T5, T6, T7, T8> : ExampleData
    {
        public ExampleData(IEnumerable<(T1, T2, T3, T4, T5, T6, T7, T8)> values)
        {
            AddRange(values.ToArray());
        }

        public ExampleData(params (T1, T2, T3, T4, T5, T6, T7, T8)[] values)
        {
            AddRange(values);
        }

        public void Add(T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6, T7 p7, T8 p8)
        {
            AddRow(p1, p2, p3, p4, p5, p6, p7, p8);
        }

        public void AddRange(params (T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6, T7 p7, T8 p8)[] values)
        {
            AddRows(values.Select(x => new object[] { x.p1, x.p2, x.p3, x.p4, x.p5, x.p6, x.p7, x.p8 }));
        }
    }



    public class ExampleData<T1, T2, T3, T4, T5, T6, T7, T8, T9> : ExampleData
    {
        public ExampleData(IEnumerable<(T1, T2, T3, T4, T5, T6, T7, T8, T9)> values)
        {
            AddRange(values.ToArray());
        }

        public ExampleData(params (T1, T2, T3, T4, T5, T6, T7, T8, T9)[] values)
        {
            AddRange(values);
        }

        public void Add(T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6, T7 p7, T8 p8, T9 p9)
        {
            AddRow(p1, p2, p3, p4, p5, p6, p7, p8, p9);
        }

        public void AddRange(params (T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6, T7 p7, T8 p8, T9 p9)[] values)
        {
            AddRows(values.Select(x => new object[] { x.p1, x.p2, x.p3, x.p4, x.p5, x.p6, x.p7, x.p8, x.p9 }));
        }
    }



    public class ExampleData<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10> : ExampleData
    {
        public ExampleData(IEnumerable<(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10)> values)
        {
            AddRange(values.ToArray());
        }

        public ExampleData(params (T1, T2, T3, T4, T5, T6, T7, T8, T9, T10)[] values)
        {
            AddRange(values);
        }

        public void Add(T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6, T7 p7, T8 p8, T9 p9, T10 p10)
        {
            AddRow(p1, p2, p3, p4, p5, p6, p7, p8, p9, p10);
        }

        public void AddRange(params (T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6, T7 p7, T8 p8, T9 p9, T10 p10)[] values)
        {
            AddRows(values.Select(x => new object[] { x.p1, x.p2, x.p3, x.p4, x.p5, x.p6, x.p7, x.p8, x.p9, x.p10 }));
        }
    }



    public class ExampleData<T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11> : ExampleData
    {
        public ExampleData(IEnumerable<(T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11)> values)
        {
            AddRange(values.ToArray());
        }

        public ExampleData(params (T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11)[] values)
        {
            AddRange(values);
        }

        public void Add(T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6, T7 p7, T8 p8, T9 p9, T10 p10, T11 p11)
        {
            AddRow(p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11);
        }

        public void AddRange(params (T1 p1, T2 p2, T3 p3, T4 p4, T5 p5, T6 p6, T7 p7, T8 p8, T9 p9, T10 p10, T11 p11)[] values)
        {
            AddRows(values.Select(x => new object[] { x.p1, x.p2, x.p3, x.p4, x.p5, x.p6, x.p7, x.p8, x.p9, x.p10, x.p11 }));
        }
    }
}
