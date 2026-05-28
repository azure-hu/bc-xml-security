// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    public class Signature
    {
        private String _id;
        private SignedInfo _signedInfo;
        private Byte[] _signatureValue;
        private String _signatureValueId;
        private KeyInfo _keyInfo;
        private IList _embeddedObjects;
        private readonly CanonicalXmlNodeList _referencedItems;
        private SignedXml _signedXml = null;

        internal SignedXml SignedXml
        {
            get { return this._signedXml; }
            set { this._signedXml = value; }
        }

        //
        // public constructors
        //

        public Signature()
        {
            this._embeddedObjects = new ArrayList();
            this._referencedItems = new CanonicalXmlNodeList();
        }

        //
        // public properties
        //

        public String Id
        {
            get { return this._id; }
            set { this._id = value; }
        }

        public SignedInfo SignedInfo
        {
            get { return this._signedInfo; }
            set
            {
                this._signedInfo = value;
                if (this.SignedXml != null && this._signedInfo != null)
                {
                    this._signedInfo.SignedXml = this.SignedXml;
                }
            }
        }

        public Byte[] SignatureValue
        {
            get { return this._signatureValue; }
            set { this._signatureValue = value; }
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

        public IList ObjectList
        {
            get { return this._embeddedObjects; }
            set { this._embeddedObjects = value; }
        }

        internal CanonicalXmlNodeList ReferencedItems
        {
            get { return this._referencedItems; }
        }

        //
        // public methods
        //

        public XmlElement GetXml()
        {
            XmlDocument document = new XmlDocument();
            document.PreserveWhitespace = true;
            return this.GetXml(document);
        }

        internal XmlElement GetXml(XmlDocument document)
        {
            // Create the Signature
            XmlElement signatureElement = (XmlElement)document.CreateElement(SignedXml.DefaultXmlDsigNamespacePrefix, "Signature", SignedXml.XmlDsigNamespaceUrl);
            if (!String.IsNullOrEmpty(this._id))
            {
                signatureElement.SetAttribute("Id", this._id);
            }

            // Add the SignedInfo
            if (this._signedInfo == null)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_SignedInfoRequired);
            }

            signatureElement.AppendChild(this._signedInfo.GetXml(document));

            // Add the SignatureValue
            if (this._signatureValue == null)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_SignatureValueRequired);
            }

            XmlElement signatureValueElement = document.CreateElement(SignedXml.DefaultXmlDsigNamespacePrefix, "SignatureValue", SignedXml.XmlDsigNamespaceUrl);
            signatureValueElement.AppendChild(document.CreateTextNode(Convert.ToBase64String(this._signatureValue)));
            if (!String.IsNullOrEmpty(this._signatureValueId))
            {
                signatureValueElement.SetAttribute("Id", this._signatureValueId);
            }

            signatureElement.AppendChild(signatureValueElement);

            // Add the KeyInfo
            if (this.KeyInfo.Count > 0)
            {
                signatureElement.AppendChild(this.KeyInfo.GetXml(document));
            }

            // Add the Objects
            foreach (Object obj in this._embeddedObjects)
            {
                DataObject dataObj = obj as DataObject;
                if (dataObj != null)
                {
                    signatureElement.AppendChild(dataObj.GetXml(document));
                }
            }

            return signatureElement;
        }

        public void LoadXml(XmlElement value)
        {
            // Make sure we don't get passed null
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            // Signature
            XmlElement signatureElement = value;
            if (!signatureElement.LocalName.Equals("Signature"))
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidElement, "Signature");
            }

            // Id attribute -- optional
            this._id = Utils.GetAttribute(signatureElement, "Id", SignedXml.XmlDsigNamespaceUrl);
            if (!Utils.VerifyAttributes(signatureElement, "Id"))
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidElement, "Signature");
            }

            XmlNamespaceManager nsm = new XmlNamespaceManager(value.OwnerDocument.NameTable);
            nsm.AddNamespace(SignedXml.DefaultXmlDsigNamespacePrefix, SignedXml.XmlDsigNamespaceUrl);
            Int32 expectedChildNodes = 0;

            // SignedInfo
            XmlNodeList signedInfoNodes = signatureElement.SelectNodes(SignedXml.DefaultXmlDsigNamespacePrefix + ":SignedInfo", nsm);
            if (signedInfoNodes == null || signedInfoNodes.Count == 0 || signedInfoNodes.Count > 1)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidElement, "SignedInfo");
            }

            XmlElement signedInfoElement = signedInfoNodes[0] as XmlElement;
            expectedChildNodes += signedInfoNodes.Count;

            this.SignedInfo = new SignedInfo();
            this.SignedInfo.LoadXml(signedInfoElement);

            // SignatureValue
            XmlNodeList signatureValueNodes = signatureElement.SelectNodes(SignedXml.DefaultXmlDsigNamespacePrefix + ":SignatureValue", nsm);
            if (signatureValueNodes == null || signatureValueNodes.Count == 0 || signatureValueNodes.Count > 1)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidElement, "SignatureValue");
            }

            XmlElement signatureValueElement = signatureValueNodes[0] as XmlElement;
            expectedChildNodes += signatureValueNodes.Count;
            this._signatureValue = Convert.FromBase64String(Utils.DiscardWhiteSpaces(signatureValueElement.InnerText));
            this._signatureValueId = Utils.GetAttribute(signatureValueElement, "Id", SignedXml.XmlDsigNamespaceUrl);
            if (!Utils.VerifyAttributes(signatureValueElement, "Id"))
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidElement, "SignatureValue");
            }

            // KeyInfo - optional single element
            XmlNodeList keyInfoNodes = signatureElement.SelectNodes(SignedXml.DefaultXmlDsigNamespacePrefix + ":KeyInfo", nsm);
            this._keyInfo = new KeyInfo();
            if (keyInfoNodes != null)
            {
                if (keyInfoNodes.Count > 1)
                {
                    throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidElement, "KeyInfo");
                }
                foreach (XmlNode node in keyInfoNodes)
                {
                    XmlElement keyInfoElement = node as XmlElement;
                    if (keyInfoElement != null)
                    {
                        this._keyInfo.LoadXml(keyInfoElement);
                    }
                }
                expectedChildNodes += keyInfoNodes.Count;
            }

            // Object - zero or more elements allowed
            XmlNodeList objectNodes = signatureElement.SelectNodes(SignedXml.DefaultXmlDsigNamespacePrefix + ":Object", nsm);
            this._embeddedObjects.Clear();
            if (objectNodes != null)
            {
                foreach (XmlNode node in objectNodes)
                {
                    XmlElement objectElement = node as XmlElement;
                    if (objectElement != null)
                    {
                        DataObject dataObj = new DataObject();
                        dataObj.LoadXml(objectElement);
                        this._embeddedObjects.Add(dataObj);
                    }
                }
                expectedChildNodes += objectNodes.Count;
            }

            // Select all elements that have Id attributes
            XmlNodeList nodeList = signatureElement.SelectNodes("//*[@Id]", nsm);
            if (nodeList != null)
            {
                foreach (XmlNode node in nodeList)
                {
                    this._referencedItems.Add(node);
                }
            }
            // Verify that there aren't any extra nodes that aren't allowed
            if (signatureElement.SelectNodes("*").Count != expectedChildNodes)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidElement, "Signature");
            }
        }

        public void AddObject(DataObject dataObject)
        {
            this._embeddedObjects.Add(dataObject);
        }
    }
}
