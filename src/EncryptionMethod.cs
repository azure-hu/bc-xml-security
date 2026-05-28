// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    public class EncryptionMethod
    {
        private XmlElement _cachedXml = null;
        private Int32 _keySize = 0;
        private String _algorithm;

        public EncryptionMethod()
        {
            this._cachedXml = null;
        }

        public EncryptionMethod(String algorithm)
        {
            this._algorithm = algorithm;
            this._cachedXml = null;
        }

        private Boolean CacheValid
        {
            get
            {
                return (this._cachedXml != null);
            }
        }

        public Int32 KeySize
        {
            get { return this._keySize; }
            set
            {
                if (value <= 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(value), SR.Cryptography_Xml_InvalidKeySize);
                }

                this._keySize = value;
                this._cachedXml = null;
            }
        }

        public String KeyAlgorithm
        {
            get { return this._algorithm; }
            set
            {
                this._algorithm = value;
                this._cachedXml = null;
            }
        }

        public XmlElement GetXml()
        {
            if (this.CacheValid)
            {
                return (this._cachedXml);
            }

            XmlDocument document = new XmlDocument();
            document.PreserveWhitespace = true;
            return this.GetXml(document);
        }

        internal XmlElement GetXml(XmlDocument document)
        {
            // Create the EncryptionMethod element
            XmlElement encryptionMethodElement = (XmlElement)document.CreateElement(EncryptedXml.DefaultXmlEncNamespacePrefix, "EncryptionMethod", EncryptedXml.XmlEncNamespaceUrl);
            if (!String.IsNullOrEmpty(this._algorithm))
            {
                encryptionMethodElement.SetAttribute("Algorithm", this._algorithm);
            }

            if (this._keySize > 0)
            {
                // Construct a KeySize element
                XmlElement keySizeElement = document.CreateElement(EncryptedXml.DefaultXmlEncNamespacePrefix, "KeySize", EncryptedXml.XmlEncNamespaceUrl);
                keySizeElement.AppendChild(document.CreateTextNode(this._keySize.ToString(null, null)));
                encryptionMethodElement.AppendChild(keySizeElement);
            }
            return encryptionMethodElement;
        }

        public void LoadXml(XmlElement value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            XmlNamespaceManager nsm = new XmlNamespaceManager(value.OwnerDocument.NameTable);
            nsm.AddNamespace(EncryptedXml.DefaultXmlEncNamespacePrefix, EncryptedXml.XmlEncNamespaceUrl);

            XmlElement encryptionMethodElement = value;
            this._algorithm = Utils.GetAttribute(encryptionMethodElement, "Algorithm", EncryptedXml.XmlEncNamespaceUrl);

            XmlNode keySizeNode = value.SelectSingleNode(EncryptedXml.DefaultXmlEncNamespacePrefix + ":KeySize", nsm);
            if (keySizeNode != null)
            {
                this.KeySize = Convert.ToInt32(Utils.DiscardWhiteSpaces(keySizeNode.InnerText), null);
            }

            // Save away the cached value
            this._cachedXml = value;
        }
    }
}
