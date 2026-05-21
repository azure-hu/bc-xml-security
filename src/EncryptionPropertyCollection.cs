// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections;

namespace Org.BouncyCastle.Crypto.Xml
{
    public sealed class EncryptionPropertyCollection : IList
    {
        private readonly ArrayList _props;

        public EncryptionPropertyCollection()
        {
            this._props = new ArrayList();
        }

        public IEnumerator GetEnumerator()
        {
            return this._props.GetEnumerator();
        }

        public Int32 Count
        {
            get { return this._props.Count; }
        }

        /// <internalonly/>
        Int32 IList.Add(Object value)
        {
            if (!(value is EncryptionProperty))
            {
                throw new ArgumentException(SR.Cryptography_Xml_IncorrectObjectType, nameof(value));
            }

            return this._props.Add(value);
        }

        public Int32 Add(EncryptionProperty value)
        {
            return this._props.Add(value);
        }

        public void Clear()
        {
            this._props.Clear();
        }

        /// <internalonly/>
        Boolean IList.Contains(Object value)
        {
            if (!(value is EncryptionProperty))
            {
                throw new ArgumentException(SR.Cryptography_Xml_IncorrectObjectType, nameof(value));
            }

            return this._props.Contains(value);
        }

        public Boolean Contains(EncryptionProperty value)
        {
            return this._props.Contains(value);
        }

        /// <internalonly/>
        Int32 IList.IndexOf(Object value)
        {
            if (!(value is EncryptionProperty))
            {
                throw new ArgumentException(SR.Cryptography_Xml_IncorrectObjectType, nameof(value));
            }

            return this._props.IndexOf(value);
        }

        public Int32 IndexOf(EncryptionProperty value)
        {
            return this._props.IndexOf(value);
        }

        /// <internalonly/>
        void IList.Insert(Int32 index, Object value)
        {
            if (!(value is EncryptionProperty))
            {
                throw new ArgumentException(SR.Cryptography_Xml_IncorrectObjectType, nameof(value));
            }

            this._props.Insert(index, value);
        }

        public void Insert(Int32 index, EncryptionProperty value)
        {
            this._props.Insert(index, value);
        }

        /// <internalonly/>
        void IList.Remove(Object value)
        {
            if (!(value is EncryptionProperty))
            {
                throw new ArgumentException(SR.Cryptography_Xml_IncorrectObjectType, nameof(value));
            }

            this._props.Remove(value);
        }

        public void Remove(EncryptionProperty value)
        {
            this._props.Remove(value);
        }

        public void RemoveAt(Int32 index)
        {
            this._props.RemoveAt(index);
        }

        public Boolean IsFixedSize
        {
            get { return this._props.IsFixedSize; }
        }

        public Boolean IsReadOnly
        {
            get { return this._props.IsReadOnly; }
        }

        public EncryptionProperty Item(Int32 index)
        {
            return (EncryptionProperty)this._props[index];
        }

        [System.Runtime.CompilerServices.IndexerName("ItemOf")]
        public EncryptionProperty this[Int32 index]
        {
            get
            {
                return (EncryptionProperty)((IList)this)[index];
            }
            set
            {
                ((IList)this)[index] = value;
            }
        }

        /// <internalonly/>
        Object IList.this[Int32 index]
        {
            get { return this._props[index]; }
            set
            {
                if (!(value is EncryptionProperty))
                {
                    throw new ArgumentException(SR.Cryptography_Xml_IncorrectObjectType, nameof(value));
                }

                this._props[index] = value;
            }
        }

        public void CopyTo(Array array, Int32 index)
        {
            this._props.CopyTo(array, index);
        }

        public void CopyTo(EncryptionProperty[] array, Int32 index)
        {
            this._props.CopyTo(array, index);
        }

        public Object SyncRoot
        {
            get { return this._props.SyncRoot; }
        }

        public Boolean IsSynchronized
        {
            get { return this._props.IsSynchronized; }
        }
    }
}
