// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    public sealed class EncryptedKey : EncryptedType
    {
        private String _recipient;
        private String _carriedKeyName;
        private ReferenceList _referenceList;

        public EncryptedKey() { }

        public String Recipient
        {
            get
            {
                // an unspecified value for an XmlAttribute is string.Empty
                if (this._recipient == null)
                {
                    this._recipient = String.Empty;
                }

                return this._recipient;
            }
            set
            {
                this._recipient = value;
                this._cachedXml = null;
            }
        }

        public String CarriedKeyName
        {
            get { return this._carriedKeyName; }
            set
            {
                this._carriedKeyName = value;
                this._cachedXml = null;
            }
        }

        public ReferenceList ReferenceList
        {
            get
            {
                if (this._referenceList == null)
                {
                    this._referenceList = new ReferenceList();
                }

                return this._referenceList;
            }
        }

        public void AddReference(DataReference dataReference)
        {
            this.ReferenceList.Add(dataReference);
        }

        public void AddReference(KeyReference keyReference)
        {
            this.ReferenceList.Add(keyReference);
        }

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
            this.Recipient = Utils.GetAttribute(value, "Recipient", EncryptedXml.XmlEncNamespaceUrl);

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

            // CarriedKeyName
            XmlNode carriedKeyNameNode = value.SelectSingleNode(EncryptedXml.XmlEncNamespacePrefix + ":CarriedKeyName", nsm);
            if (carriedKeyNameNode != null)
            {
                this.CarriedKeyName = carriedKeyNameNode.InnerText;
            }

            // ReferenceList
            XmlNode referenceListNode = value.SelectSingleNode(EncryptedXml.XmlEncNamespacePrefix + ":ReferenceList", nsm);
            if (referenceListNode != null)
            {
                // Select the DataReference elements inside the ReferenceList element
                XmlNodeList dataReferenceNodes = referenceListNode.SelectNodes(EncryptedXml.XmlEncNamespacePrefix + ":DataReference", nsm);
                if (dataReferenceNodes != null)
                {
                    foreach (XmlNode node in dataReferenceNodes)
                    {
                        DataReference dr = new DataReference();
                        dr.LoadXml(node as XmlElement);
                        this.ReferenceList.Add(dr);
                    }
                }
                // Select the KeyReference elements inside the ReferenceList element
                XmlNodeList keyReferenceNodes = referenceListNode.SelectNodes(EncryptedXml.XmlEncNamespacePrefix + ":KeyReference", nsm);
                if (keyReferenceNodes != null)
                {
                    foreach (XmlNode node in keyReferenceNodes)
                    {
                        KeyReference kr = new KeyReference();
                        kr.LoadXml(node as XmlElement);
                        this.ReferenceList.Add(kr);
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
                return this._cachedXml;
            }

            XmlDocument document = new XmlDocument();
            document.PreserveWhitespace = true;
            return this.GetXml(document);
        }

        internal XmlElement GetXml(XmlDocument document)
        {
            // Create the EncryptedKey element
            XmlElement encryptedKeyElement = (XmlElement)document.CreateElement(EncryptedXml.XmlEncNamespacePrefix, "EncryptedKey", EncryptedXml.XmlEncNamespaceUrl);

            // Deal with attributes
            if (!String.IsNullOrEmpty(this.Id))
            {
                encryptedKeyElement.SetAttribute("Id", this.Id);
            }

            if (!String.IsNullOrEmpty(this.Type))
            {
                encryptedKeyElement.SetAttribute("Type", this.Type);
            }

            if (!String.IsNullOrEmpty(this.MimeType))
            {
                encryptedKeyElement.SetAttribute("MimeType", this.MimeType);
            }

            if (!String.IsNullOrEmpty(this.Encoding))
            {
                encryptedKeyElement.SetAttribute("Encoding", this.Encoding);
            }

            if (!String.IsNullOrEmpty(this.Recipient))
            {
                encryptedKeyElement.SetAttribute("Recipient", this.Recipient);
            }

            // EncryptionMethod
            if (this.EncryptionMethod != null)
            {
                encryptedKeyElement.AppendChild(this.EncryptionMethod.GetXml(document));
            }

            // KeyInfo
            if (this.KeyInfo.Count > 0)
            {
                encryptedKeyElement.AppendChild(this.KeyInfo.GetXml(document));
            }

            // CipherData
            if (this.CipherData == null)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_MissingCipherData);
            }

            encryptedKeyElement.AppendChild(this.CipherData.GetXml(document));

            // EncryptionProperties
            if (this.EncryptionProperties.Count > 0)
            {
                XmlElement encryptionPropertiesElement = document.CreateElement(EncryptedXml.XmlEncNamespacePrefix, "EncryptionProperties", EncryptedXml.XmlEncNamespaceUrl);
                for (Int32 index = 0; index < this.EncryptionProperties.Count; index++)
                {
                    EncryptionProperty ep = this.EncryptionProperties.Item(index);
                    encryptionPropertiesElement.AppendChild(ep.GetXml(document));
                }
                encryptedKeyElement.AppendChild(encryptionPropertiesElement);
            }

            // ReferenceList
            if (this.ReferenceList.Count > 0)
            {
                XmlElement referenceListElement = document.CreateElement(EncryptedXml.XmlEncNamespacePrefix, "ReferenceList", EncryptedXml.XmlEncNamespaceUrl);
                for (Int32 index = 0; index < this.ReferenceList.Count; index++)
                {
                    referenceListElement.AppendChild(this.ReferenceList[index].GetXml(document));
                }
                encryptedKeyElement.AppendChild(referenceListElement);
            }

            // CarriedKeyName
            if (this.CarriedKeyName != null)
            {
                XmlElement carriedKeyNameElement = (XmlElement)document.CreateElement(EncryptedXml.XmlEncNamespacePrefix, "CarriedKeyName", EncryptedXml.XmlEncNamespaceUrl);
                XmlText carriedKeyNameText = document.CreateTextNode(this.CarriedKeyName);
                carriedKeyNameElement.AppendChild(carriedKeyNameText);
                encryptedKeyElement.AppendChild(carriedKeyNameElement);
            }

            return encryptedKeyElement;
        }
    }
}
