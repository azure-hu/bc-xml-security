// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    public sealed class CipherReference : EncryptedReference
    {
        private Byte[] _cipherValue;

        public CipherReference() : base()
        {
            this.ReferenceType = "CipherReference";
        }

        public CipherReference(String uri) : base(uri)
        {
            this.ReferenceType = "CipherReference";
        }

        public CipherReference(String uri, TransformChain transformChain) : base(uri, transformChain)
        {
            this.ReferenceType = "CipherReference";
        }

        // This method is used to cache results from resolved cipher references.
        internal Byte[] CipherValue
        {
            get
            {
                if (!this.CacheValid)
                {
                    return null;
                }

                return this._cipherValue;
            }
            set
            {
                this._cipherValue = value;
            }
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

        internal new XmlElement GetXml(XmlDocument document)
        {
            if (this.ReferenceType == null)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_ReferenceTypeRequired);
            }

            // Create the Reference
            XmlElement referenceElement = document.CreateElement(EncryptedXml.DefaultXmlEncNamespacePrefix, this.ReferenceType, EncryptedXml.XmlEncNamespaceUrl);
            if (!String.IsNullOrEmpty(this.Uri))
            {
                referenceElement.SetAttribute("URI", this.Uri);
            }

            // Add the transforms to the CipherReference
            if (this.TransformChain.Count > 0)
            {
                referenceElement.AppendChild(this.TransformChain.GetXml(document, EncryptedXml.XmlEncNamespaceUrl));
            }

            return referenceElement;
        }

        public override void LoadXml(XmlElement value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            this.ReferenceType = value.LocalName;
            String uri = Utils.GetAttribute(value, "URI", EncryptedXml.XmlEncNamespaceUrl);
            this.Uri = uri ?? throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_UriRequired);

            // Transforms
            XmlNamespaceManager nsm = new XmlNamespaceManager(value.OwnerDocument.NameTable);
            nsm.AddNamespace(EncryptedXml.DefaultXmlEncNamespacePrefix, EncryptedXml.XmlEncNamespaceUrl);
            XmlNode transformsNode = value.SelectSingleNode(EncryptedXml.DefaultXmlEncNamespacePrefix + ":Transforms", nsm);
            if (transformsNode != null)
            {
                this.TransformChain.LoadXml(transformsNode as XmlElement);
            }

            // cache the Xml
            this._cachedXml = value;
        }
    }
}
