// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    public sealed class CipherData
    {
        private XmlElement _cachedXml = null;
        private CipherReference _cipherReference = null;
        private Byte[] _cipherValue = null;

        public CipherData() { }

        public CipherData(Byte[] cipherValue)
        {
            this.CipherValue = cipherValue;
        }

        public CipherData(CipherReference cipherReference)
        {
            this.CipherReference = cipherReference;
        }

        private Boolean CacheValid
        {
            get
            {
                return (this._cachedXml != null);
            }
        }

        public CipherReference CipherReference
        {
            get { return this._cipherReference; }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(value));
                }

                if (this.CipherValue != null)
                {
                    throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_CipherValueElementRequired);
                }

                this._cipherReference = value;
                this._cachedXml = null;
            }
        }

        public Byte[] CipherValue
        {
            get { return this._cipherValue; }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(value));
                }

                if (this.CipherReference != null)
                {
                    throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_CipherValueElementRequired);
                }

                this._cipherValue = (Byte[])value.Clone();
                this._cachedXml = null;
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
            // Create the CipherData element
            XmlElement cipherDataElement = (XmlElement)document.CreateElement(EncryptedXml.DefaultXmlEncNamespacePrefix, "CipherData", EncryptedXml.XmlEncNamespaceUrl);
            if (this.CipherValue != null)
            {
                XmlElement cipherValueElement = document.CreateElement(EncryptedXml.DefaultXmlEncNamespacePrefix, "CipherValue", EncryptedXml.XmlEncNamespaceUrl);
                cipherValueElement.AppendChild(document.CreateTextNode(Convert.ToBase64String(this.CipherValue)));
                cipherDataElement.AppendChild(cipherValueElement);
            }
            else
            {
                // No CipherValue specified, see if there is a CipherReference
                if (this.CipherReference == null)
                {
                    throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_CipherValueElementRequired);
                }

                cipherDataElement.AppendChild(this.CipherReference.GetXml(document));
            }
            return cipherDataElement;
        }

        public void LoadXml(XmlElement value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            XmlNamespaceManager nsm = new XmlNamespaceManager(value.OwnerDocument.NameTable);
            nsm.AddNamespace(EncryptedXml.DefaultXmlEncNamespacePrefix, EncryptedXml.XmlEncNamespaceUrl);

            XmlNode cipherValueNode = value.SelectSingleNode(EncryptedXml.DefaultXmlEncNamespacePrefix + ":CipherValue", nsm);
            XmlNode cipherReferenceNode = value.SelectSingleNode(EncryptedXml.DefaultXmlEncNamespacePrefix + ":CipherReference", nsm);
            if (cipherValueNode != null)
            {
                if (cipherReferenceNode != null)
                {
                    throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_CipherValueElementRequired);
                }

                this._cipherValue = Convert.FromBase64String(Utils.DiscardWhiteSpaces(cipherValueNode.InnerText));
            }
            else if (cipherReferenceNode != null)
            {
                this._cipherReference = new CipherReference();
                this._cipherReference.LoadXml((XmlElement)cipherReferenceNode);
            }
            else
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_CipherValueElementRequired);
            }

            // Save away the cached value
            this._cachedXml = value;
        }
    }
}
