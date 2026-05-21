// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    internal class CanonicalXmlNodeList : XmlNodeList, IList
    {
        private readonly ArrayList _nodeArray;

        internal CanonicalXmlNodeList()
        {
            this._nodeArray = new ArrayList();
        }

        public override XmlNode Item(Int32 index)
        {
            return (XmlNode)this._nodeArray[index];
        }

        public override IEnumerator GetEnumerator()
        {
            return this._nodeArray.GetEnumerator();
        }

        public override Int32 Count
        {
            get { return this._nodeArray.Count; }
        }

        // IList methods
        public Int32 Add(Object value)
        {
            if (!(value is XmlNode))
            {
                throw new ArgumentException(SR.Cryptography_Xml_IncorrectObjectType, "node");
            }

            return this._nodeArray.Add(value);
        }

        public void Clear()
        {
            this._nodeArray.Clear();
        }

        public Boolean Contains(Object value)
        {
            return this._nodeArray.Contains(value);
        }

        public Int32 IndexOf(Object value)
        {
            return this._nodeArray.IndexOf(value);
        }

        public void Insert(Int32 index, Object value)
        {
            if (!(value is XmlNode))
            {
                throw new ArgumentException(SR.Cryptography_Xml_IncorrectObjectType, nameof(value));
            }

            this._nodeArray.Insert(index, value);
        }

        public void Remove(Object value)
        {
            this._nodeArray.Remove(value);
        }

        public void RemoveAt(Int32 index)
        {
            this._nodeArray.RemoveAt(index);
        }

        public Boolean IsFixedSize
        {
            get { return this._nodeArray.IsFixedSize; }
        }

        public Boolean IsReadOnly
        {
            get { return this._nodeArray.IsReadOnly; }
        }

        Object IList.this[Int32 index]
        {
            get { return this._nodeArray[index]; }
            set
            {
                if (!(value is XmlNode))
                {
                    throw new ArgumentException(SR.Cryptography_Xml_IncorrectObjectType, nameof(value));
                }

                this._nodeArray[index] = value;
            }
        }

        public void CopyTo(Array array, Int32 index)
        {
            this._nodeArray.CopyTo(array, index);
        }

        public Object SyncRoot
        {
            get { return this._nodeArray.SyncRoot; }
        }

        public Boolean IsSynchronized
        {
            get { return this._nodeArray.IsSynchronized; }
        }
    }
}
