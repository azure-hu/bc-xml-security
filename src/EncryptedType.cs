// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    public abstract class EncryptedType
    {
        private String _id;
        private String _type;
        private String _mimeType;
        private String _encoding;
        private EncryptionMethod _encryptionMethod;
        private CipherData _cipherData;
        private EncryptionPropertyCollection _props;
        private KeyInfo _keyInfo;
        internal XmlElement _cachedXml = null;

        internal Boolean CacheValid
        {
            get
            {
                return (this._cachedXml != null);
            }
        }

        public virtual String Id
        {
            get { return this._id; }
            set
            {
                this._id = value;
                this._cachedXml = null;
            }
        }

        public virtual String Type
        {
            get { return this._type; }
            set
            {
                this._type = value;
                this._cachedXml = null;
            }
        }

        public virtual String MimeType
        {
            get { return this._mimeType; }
            set
            {
                this._mimeType = value;
                this._cachedXml = null;
            }
        }

        public virtual String Encoding
        {
            get { return this._encoding; }
            set
            {
                this._encoding = value;
                this._cachedXml = null;
            }
        }

        public KeyInfo KeyInfo
        {
            get
            {
                if (this._keyInfo == null)
                {
                    this._keyInfo = new KeyInfo();
                }

                return this._keyInfo;
            }
            set { this._keyInfo = value; }
        }

        public virtual EncryptionMethod EncryptionMethod
        {
            get { return this._encryptionMethod; }
            set
            {
                this._encryptionMethod = value;
                this._cachedXml = null;
            }
        }

        public virtual EncryptionPropertyCollection EncryptionProperties
        {
            get
            {
                if (this._props == null)
                {
                    this._props = new EncryptionPropertyCollection();
                }

                return this._props;
            }
        }

        public void AddProperty(EncryptionProperty ep)
        {
            this.EncryptionProperties.Add(ep);
        }

        public virtual CipherData CipherData
        {
            get
            {
                if (this._cipherData == null)
                {
                    this._cipherData = new CipherData();
                }

                return this._cipherData;
            }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(value));
                }

                this._cipherData = value;
                this._cachedXml = null;
            }
        }

        public abstract void LoadXml(XmlElement value);
        public abstract XmlElement GetXml();
    }
}
