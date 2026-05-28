// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    public class KeyInfoAgreementMethod : KeyInfoClause
    {
        private XmlElement _cachedXml = null;
        private String _algorithm = null;
        private KeyInfo _originatorKeyInfo = null;
        private KeyInfo _recipientKeyInfo = null;
        private Byte[] _kaNonce = null;
        private readonly ArrayList _agreementMethodClauses;

        //
        // public constructors
        //

        public KeyInfoAgreementMethod()
        {
            this._agreementMethodClauses = new ArrayList();
        }

        public KeyInfoAgreementMethod(String algorithm) : this()
        {
            this.Algorithm = algorithm;
        }

        public KeyInfoAgreementMethod(String algorithm, KeyInfo originatorKeyInfo, KeyInfo recipientKeyInfo) : this(algorithm)
        {
            this.OriginatorKeyInfo = originatorKeyInfo;
            this.RecipientKeyInfo = recipientKeyInfo;
        }

        public KeyInfoAgreementMethod(String algorithm, KeyInfo originatorKeyInfo, KeyInfo recipientKeyInfo, Byte[] kaNonce) : this(algorithm, originatorKeyInfo, recipientKeyInfo)
        {
            this.KaNonce = this.KaNonce;
        }

        public KeyInfoAgreementMethod(String algorithm, Byte[] kaNonce) : this(algorithm, null, null) { }

        //
        // public properties
        //

        public String Algorithm
        {
            get
            {
                return this._algorithm;
            }

            set
            {
                this._algorithm = value;
            }
        }

        public KeyInfo OriginatorKeyInfo
        {
            get
            {
                return this._originatorKeyInfo;
            }

            set
            {
                this._originatorKeyInfo = value;
            }
        }

        public KeyInfo RecipientKeyInfo
        {
            get
            {
                return this._recipientKeyInfo;
            }

            set
            {
                this._recipientKeyInfo = value;
            }
        }

        public Byte[] KaNonce
        {
            get
            {
                return this._kaNonce;
            }

            set
            {
                this._kaNonce = value;
            }
        }

        private Boolean CacheValid
        {
            get
            {
                return (this._cachedXml != null);
            }
        }

        public override XmlElement GetXml()
        {
            if (this.CacheValid)
            {
                return this._cachedXml;
            }

            XmlDocument xmlDocument = new XmlDocument
            {
                PreserveWhitespace = true
            };
            return this.GetXml(xmlDocument);
        }

        internal override XmlElement GetXml(XmlDocument xmlDocument)
        {
            // Create the actual element
            XmlElement agreementMethodElement = xmlDocument.CreateElement(EncryptedXml.DefaultXmlEncNamespacePrefix, "AgreementMethod", EncryptedXml.XmlEncNamespaceUrl);

            if (!String.IsNullOrEmpty(this.Algorithm))
            {
                agreementMethodElement.SetAttribute("Algorithm", this.Algorithm);
            }

            // Add all the clauses that go underneath it
            for (Int32 i = 0; i < this._agreementMethodClauses.Count; ++i)
            {
                XmlElement xmlElement = ((KeyInfoAgreementMethodClause)this._agreementMethodClauses[i]).GetXml(xmlDocument);
                if (xmlElement != null)
                {
                    agreementMethodElement.AppendChild(xmlElement);
                }
            }

            if (this.OriginatorKeyInfo != null)
            {
                XmlElement originatorKeyInfo = this.OriginatorKeyInfo.GetXml(xmlDocument);
                XmlElement originatorKeyInfoElement = xmlDocument.CreateElement(EncryptedXml.DefaultXmlEncNamespacePrefix, "OriginatorKeyInfo", EncryptedXml.XmlEncNamespaceUrl);
                foreach (XmlElement childElement in originatorKeyInfo.ChildNodes)
                {
                    originatorKeyInfoElement.AppendChild(childElement);
                }
                agreementMethodElement.AppendChild(originatorKeyInfoElement);
            }

            if (this.RecipientKeyInfo != null)
            {
                XmlElement recipientKeyInfo = this.RecipientKeyInfo.GetXml(xmlDocument);
                XmlElement recipientKeyInfolement = xmlDocument.CreateElement(EncryptedXml.DefaultXmlEncNamespacePrefix, "RecipientKeyInfo", EncryptedXml.XmlEncNamespaceUrl);
                foreach (XmlElement childElement in recipientKeyInfo.ChildNodes)
                {
                    recipientKeyInfolement.AppendChild(childElement);
                }
                agreementMethodElement.AppendChild(recipientKeyInfolement);
            }

            if (this.KaNonce != null)
            {
                XmlElement kaNonceElement = xmlDocument.CreateElement(SignedXml.DefaultXmlDsigNamespacePrefix, "KA-Nonce", SignedXml.XmlDsigNamespaceUrl);
                kaNonceElement.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(this.KaNonce)));
                agreementMethodElement.AppendChild(kaNonceElement);
            }

            return agreementMethodElement;
        }

        public override void LoadXml(XmlElement value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            this.Algorithm = Utils.GetAttribute(value, "Algorithm", SignedXml.XmlDsigNamespaceUrl);

            XmlElement agreementMethodElement = value.CloneNode(true) as XmlElement;

            XmlNamespaceManager nsm = new XmlNamespaceManager(agreementMethodElement.OwnerDocument.NameTable);
            nsm.AddNamespace(SignedXml.DefaultXmlDsigNamespacePrefix, SignedXml.XmlDsigNamespaceUrl);
            nsm.AddNamespace(EncryptedXml.DefaultXmlEncNamespacePrefix, EncryptedXml.XmlEncNamespaceUrl);

            XmlNode originatorKeyInfoNode = agreementMethodElement.SelectSingleNode(EncryptedXml.DefaultXmlEncNamespacePrefix + ":OriginatorKeyInfo", nsm);
            if (originatorKeyInfoNode != null)
            {
                KeyInfo originatorKeyInfo = new KeyInfo();
                originatorKeyInfo.LoadXml(originatorKeyInfoNode as XmlElement);
                this.OriginatorKeyInfo = originatorKeyInfo;
                agreementMethodElement.RemoveChild(originatorKeyInfoNode);
            }

            XmlNode recipientKeyInfoNode = agreementMethodElement.SelectSingleNode(EncryptedXml.DefaultXmlEncNamespacePrefix + ":RecipientKeyInfo", nsm);
            if (recipientKeyInfoNode != null)
            {
                KeyInfo recipientKeyInfo = new KeyInfo();
                recipientKeyInfo.LoadXml(recipientKeyInfoNode as XmlElement);
                this.RecipientKeyInfo = recipientKeyInfo;
                agreementMethodElement.RemoveChild(recipientKeyInfoNode);
            }

            XmlNode kaNonceNode = agreementMethodElement.SelectSingleNode(SignedXml.DefaultXmlDsigNamespacePrefix + ":KA-Nonce", nsm);
            if (kaNonceNode != null)
            {
                this.KaNonce = Convert.FromBase64String(Utils.DiscardWhiteSpaces(kaNonceNode.InnerText));
                agreementMethodElement.RemoveChild(kaNonceNode);
            }

            XmlNode child = agreementMethodElement.FirstChild;
            while (child != null)
            {
                XmlElement elem = child as XmlElement;
                if (elem != null)
                {
                    String kicString = elem.NamespaceURI + " " + elem.LocalName;

                    KeyInfoAgreementMethodClause keyInfoAgreementMethodClause = CryptoHelpers.CreateFromName<KeyInfoAgreementMethodClause>(kicString);
                    // if we don't know what kind of KeyDerivationMethodClause we're looking at, use a generic KeyInfoNode:
                    if (keyInfoAgreementMethodClause == null)
                    {
                        keyInfoAgreementMethodClause = new KeyInfoAgreementMethodNode();
                    }

                    // Ask the create clause to fill itself with the corresponding XML
                    keyInfoAgreementMethodClause.LoadXml(elem);
                    // Add it to our list of KeyInfoClauses
                    this.AddClause(keyInfoAgreementMethodClause);
                }
                child = child.NextSibling;
            }

            // Save away the cached value
            this._cachedXml = value;
        }

        public void AddClause(KeyInfoAgreementMethodClause clause)
        {
            this._agreementMethodClauses.Add(clause);
        }

        public IEnumerator GetEnumerator()
        {
            return this._agreementMethodClauses.GetEnumerator();
        }

        public IEnumerator GetEnumerator(Type requestedObjectType)
        {
            ArrayList requestedList = new ArrayList();

            Object tempObj;
            IEnumerator tempEnum = this._agreementMethodClauses.GetEnumerator();

            while (tempEnum.MoveNext())
            {
                tempObj = tempEnum.Current;
                if (requestedObjectType.Equals(tempObj.GetType()))
                {
                    requestedList.Add(tempObj);
                }
            }

            return requestedList.GetEnumerator();
        }
    }
}
