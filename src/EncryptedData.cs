// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    public sealed class EncryptedData : EncryptedType
    {
        public override void LoadXml(XmlElement value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            XmlNamespaceManager nsm = new XmlNamespaceManager(value.OwnerDocument.NameTable);
            nsm.AddNamespace(EncryptedXml.XmlEncNamespacePrefix, EncryptedXml.XmlEncNamespaceUrl);
            nsm.AddNamespace(SignedXml.XmlDsigNamespacePrefix, SignedXml.XmlDsigNamespaceUrl);

            this.Id = Utils.GetAttribute(value, "Id", EncryptedXml.XmlEncNamespaceUrl);
            this.Type = Utils.GetAttribute(value, "Type", EncryptedXml.XmlEncNamespaceUrl);
            this.MimeType = Utils.GetAttribute(value, "MimeType", EncryptedXml.XmlEncNamespaceUrl);
            this.Encoding = Utils.GetAttribute(value, "Encoding", EncryptedXml.XmlEncNamespaceUrl);

            XmlNode encryptionMethodNode = value.SelectSingleNode(EncryptedXml.XmlEncNamespacePrefix + ":EncryptionMethod", nsm);

            // EncryptionMethod
            this.EncryptionMethod = new EncryptionMethod();
            if (encryptionMethodNode != null)
            {
                this.EncryptionMethod.LoadXml(encryptionMethodNode as XmlElement);
            }

            // Key Info
            this.KeyInfo = new KeyInfo();
            XmlNode keyInfoNode = value.SelectSingleNode(SignedXml.XmlDsigNamespacePrefix + ":KeyInfo", nsm);
            if (keyInfoNode != null)
            {
                this.KeyInfo.LoadXml(keyInfoNode as XmlElement);
            }

            // CipherData
            XmlNode cipherDataNode = value.SelectSingleNode(EncryptedXml.XmlEncNamespacePrefix + ":CipherData", nsm);
            if (cipherDataNode == null)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_MissingCipherData);
            }

            this.CipherData = new CipherData();
            this.CipherData.LoadXml(cipherDataNode as XmlElement);

            // EncryptionProperties
            XmlNode encryptionPropertiesNode = value.SelectSingleNode(EncryptedXml.XmlEncNamespacePrefix + ":EncryptionProperties", nsm);
            if (encryptionPropertiesNode != null)
            {
                // Select the EncryptionProperty elements inside the EncryptionProperties element
                XmlNodeList encryptionPropertyNodes = encryptionPropertiesNode.SelectNodes(EncryptedXml.XmlEncNamespacePrefix + ":EncryptionProperty", nsm);
                if (encryptionPropertyNodes != null)
                {
                    foreach (XmlNode node in encryptionPropertyNodes)
                    {
                        EncryptionProperty ep = new EncryptionProperty();
                        ep.LoadXml(node as XmlElement);
                        this.EncryptionProperties.Add(ep);
                    }
                }
            }

            // Save away the cached value
            this._cachedXml = value;
        }

        public override XmlElement GetXml()
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
            // Create the EncryptedData element
            XmlElement encryptedDataElement = (XmlElement)document.CreateElement(EncryptedXml.XmlEncNamespacePrefix, "EncryptedData", EncryptedXml.XmlEncNamespaceUrl);

            // Deal with attributes
            if (!String.IsNullOrEmpty(this.Id))
            {
                encryptedDataElement.SetAttribute("Id", this.Id);
            }

            if (!String.IsNullOrEmpty(this.Type))
            {
                encryptedDataElement.SetAttribute("Type", this.Type);
            }

            if (!String.IsNullOrEmpty(this.MimeType))
            {
                encryptedDataElement.SetAttribute("MimeType", this.MimeType);
            }

            if (!String.IsNullOrEmpty(this.Encoding))
            {
                encryptedDataElement.SetAttribute("Encoding", this.Encoding);
            }

            // EncryptionMethod
            if (this.EncryptionMethod != null)
            {
                encryptedDataElement.AppendChild(this.EncryptionMethod.GetXml(document));
            }

            // KeyInfo
            if (this.KeyInfo.Count > 0)
            {
                encryptedDataElement.AppendChild(this.KeyInfo.GetXml(document));
            }

            // CipherData is required.
            if (this.CipherData == null)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_MissingCipherData);
            }

            encryptedDataElement.AppendChild(this.CipherData.GetXml(document));

            // EncryptionProperties
            if (this.EncryptionProperties.Count > 0)
            {
                XmlElement encryptionPropertiesElement = document.CreateElement(EncryptedXml.XmlEncNamespacePrefix, "EncryptionProperties", EncryptedXml.XmlEncNamespaceUrl);
                for (Int32 index = 0; index < this.EncryptionProperties.Count; index++)
                {
                    EncryptionProperty ep = this.EncryptionProperties.Item(index);
                    encryptionPropertiesElement.AppendChild(ep.GetXml(document));
                }
                encryptedDataElement.AppendChild(encryptionPropertiesElement);
            }
            return encryptedDataElement;
        }
    }
}
