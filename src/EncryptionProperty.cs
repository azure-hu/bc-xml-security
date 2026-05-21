// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    public sealed class EncryptionProperty
    {
        private String _target;
        private String _id;
        private XmlElement _elemProp;
        private XmlElement _cachedXml = null;

        // We are being lax here as per the spec
        public EncryptionProperty() { }

        public EncryptionProperty(XmlElement elementProperty)
        {
            if (elementProperty == null)
            {
                throw new ArgumentNullException(nameof(elementProperty));
            }

            if (elementProperty.LocalName != "EncryptionProperty" || elementProperty.NamespaceURI != EncryptedXml.XmlEncNamespaceUrl)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidEncryptionProperty);
            }

            this._elemProp = elementProperty;
            this._cachedXml = null;
        }

        public String Id
        {
            get { return this._id; }
        }

        public String Target
        {
            get { return this._target; }
        }

        public XmlElement PropertyElement
        {
            get { return this._elemProp; }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(value));
                }

                if (value.LocalName != "EncryptionProperty" || value.NamespaceURI != EncryptedXml.XmlEncNamespaceUrl)
                {
                    throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidEncryptionProperty);
                }

                this._elemProp = value;
                this._cachedXml = null;
            }
        }

        private Boolean CacheValid
        {
            get
            {
                return (this._cachedXml != null);
            }
        }

        public XmlElement GetXml()
        {
            if (this.CacheValid)
            {
                return this._cachedXml;
            }

            XmlDocument document = new XmlDocument();
            document.PreserveWhitespace = true;
            return this.GetXml(document);
        }

        internal XmlElement GetXml(XmlDocument document)
        {
            return document.ImportNode(this._elemProp, true) as XmlElement;
        }

        public void LoadXml(XmlElement value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            if (value.LocalName != "EncryptionProperty" || value.NamespaceURI != EncryptedXml.XmlEncNamespaceUrl)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidEncryptionProperty);
            }

            // cache the Xml
            this._cachedXml = value;
            this._id = Utils.GetAttribute(value, "Id", EncryptedXml.XmlEncNamespaceUrl);
            this._target = Utils.GetAttribute(value, "Target", EncryptedXml.XmlEncNamespaceUrl);
            this._elemProp = value;
        }
    }
}
