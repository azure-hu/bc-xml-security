// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    public abstract class EncryptedReference
    {
        private String _uri;
        private String _referenceType;
        private TransformChain _transformChain;
        internal XmlElement _cachedXml = null;

        protected EncryptedReference() : this(String.Empty, new TransformChain())
        {
        }

        protected EncryptedReference(String uri) : this(uri, new TransformChain())
        {
        }

        protected EncryptedReference(String uri, TransformChain transformChain)
        {
            this.TransformChain = transformChain;
            this.Uri = uri;
            this._cachedXml = null;
        }

        public String Uri
        {
            get { return this._uri; }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(SR.Cryptography_Xml_UriRequired);
                }

                this._uri = value;
                this._cachedXml = null;
            }
        }

        public TransformChain TransformChain
        {
            get
            {
                if (this._transformChain == null)
                {
                    this._transformChain = new TransformChain();
                }

                return this._transformChain;
            }
            set
            {
                this._transformChain = value;
                this._cachedXml = null;
            }
        }

        public void AddTransform(Transform transform)
        {
            this.TransformChain.Add(transform);
        }

        protected String ReferenceType
        {
            get { return this._referenceType; }
            set
            {
                this._referenceType = value;
                this._cachedXml = null;
            }
        }

        protected internal Boolean CacheValid
        {
            get
            {
                return (this._cachedXml != null);
            }
        }

        public virtual XmlElement GetXml()
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
            if (this.ReferenceType == null)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_ReferenceTypeRequired);
            }

            // Create the Reference
            XmlElement referenceElement = document.CreateElement(EncryptedXml.XmlEncNamespacePrefix, this.ReferenceType, EncryptedXml.XmlEncNamespaceUrl);
            if (!String.IsNullOrEmpty(this._uri))
            {
                referenceElement.SetAttribute("URI", this._uri);
            }

            // Add the transforms to the CipherReference
            if (this.TransformChain.Count > 0)
            {
                referenceElement.AppendChild(this.TransformChain.GetXml(document, SignedXml.XmlDsigNamespaceUrl));
            }

            return referenceElement;
        }

        public virtual void LoadXml(XmlElement value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            this.ReferenceType = value.LocalName;

            String uri = Utils.GetAttribute(value, "URI", EncryptedXml.XmlEncNamespaceUrl);
            if (uri == null)
            {
                throw new ArgumentNullException(SR.Cryptography_Xml_UriRequired);
            }

            this.Uri = uri;

            // Transforms
            XmlNamespaceManager nsm = new XmlNamespaceManager(value.OwnerDocument.NameTable);
            nsm.AddNamespace(SignedXml.XmlDsigNamespacePrefix, SignedXml.XmlDsigNamespaceUrl);
            XmlNode transformsNode = value.SelectSingleNode(SignedXml.XmlDsigNamespacePrefix + ":Transforms", nsm);
            if (transformsNode != null)
            {
                this.TransformChain.LoadXml(transformsNode as XmlElement);
            }

            // cache the Xml
            this._cachedXml = value;
        }
    }
}
