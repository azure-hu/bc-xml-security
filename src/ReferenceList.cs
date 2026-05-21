// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections;

namespace Org.BouncyCastle.Crypto.Xml
{
    public sealed class ReferenceList : IList
    {
        private readonly ArrayList _references;

        public ReferenceList()
        {
            this._references = new ArrayList();
        }

        public IEnumerator GetEnumerator()
        {
            return this._references.GetEnumerator();
        }

        public Int32 Count
        {
            get { return this._references.Count; }
        }

        public Int32 Add(Object value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            if (!(value is DataReference) && !(value is KeyReference))
            {
                throw new ArgumentException(SR.Cryptography_Xml_IncorrectObjectType, nameof(value));
            }

            return this._references.Add(value);
        }

        public void Clear()
        {
            this._references.Clear();
        }

        public Boolean Contains(Object value)
        {
            return this._references.Contains(value);
        }

        public Int32 IndexOf(Object value)
        {
            return this._references.IndexOf(value);
        }

        public void Insert(Int32 index, Object value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            if (!(value is DataReference) && !(value is KeyReference))
            {
                throw new ArgumentException(SR.Cryptography_Xml_IncorrectObjectType, nameof(value));
            }

            this._references.Insert(index, value);
        }

        public void Remove(Object value)
        {
            this._references.Remove(value);
        }

        public void RemoveAt(Int32 index)
        {
            this._references.RemoveAt(index);
        }

        public EncryptedReference Item(Int32 index)
        {
            return (EncryptedReference)this._references[index];
        }

        [System.Runtime.CompilerServices.IndexerName("ItemOf")]
        public EncryptedReference this[Int32 index]
        {
            get
            {
                return this.Item(index);
            }
            set
            {
                ((IList)this)[index] = value;
            }
        }

        /// <internalonly/>
        Object IList.this[Int32 index]
        {
            get { return this._references[index]; }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(value));
                }

                if (!(value is DataReference) && !(value is KeyReference))
                {
                    throw new ArgumentException(SR.Cryptography_Xml_IncorrectObjectType, nameof(value));
                }

                this._references[index] = value;
            }
        }

        public void CopyTo(Array array, Int32 index)
        {
            this._references.CopyTo(array, index);
        }

        Boolean IList.IsFixedSize
        {
            get { return this._references.IsFixedSize; }
        }

        Boolean IList.IsReadOnly
        {
            get { return this._references.IsReadOnly; }
        }

        public Object SyncRoot
        {
            get { return this._references.SyncRoot; }
        }

        public Boolean IsSynchronized
        {
            get { return this._references.IsSynchronized; }
        }
    }
}
