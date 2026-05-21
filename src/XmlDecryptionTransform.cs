// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections;
using System.IO;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    // XML Decryption Transform is used to specify the order of XML Digital Signature
    // and XML Encryption when performed on the same document.

    public class XmlDecryptionTransform : Transform
    {
        private readonly Type[] _inputTypes = { typeof(Stream), typeof(XmlDocument) };
        private readonly Type[] _outputTypes = { typeof(XmlDocument) };
        private XmlNodeList _encryptedDataList = null;
        private ArrayList _arrayListUri = null; // this ArrayList object represents the Uri's to be excluded
        private EncryptedXml _exml = null; // defines the XML encryption processing rules
        private XmlDocument _containingDocument = null;
        private XmlNamespaceManager _nsm = null;
        private const String XmlDecryptionTransformNamespaceUrl = "http://www.w3.org/2002/07/decrypt#";
        private const String XmlDecryptionTransformNamespacePrefix = "xdec";

        public XmlDecryptionTransform()
        {
            this.Algorithm = SignedXml.XmlDecryptionTransformUrl;
        }

        private ArrayList ExceptUris
        {
            get
            {
                if (this._arrayListUri == null)
                {
                    this._arrayListUri = new ArrayList();
                }

                return this._arrayListUri;
            }
        }

        protected virtual Boolean IsTargetElement(XmlElement inputElement, String idValue)
        {
            if (inputElement == null)
            {
                return false;
            }

            if (inputElement.GetAttribute("Id") == idValue || inputElement.GetAttribute("id") == idValue ||
                inputElement.GetAttribute("ID") == idValue)
            {
                return true;
            }

            return false;
        }

        public EncryptedXml EncryptedXml
        {
            get
            {
                if (this._exml != null)
                {
                    return this._exml;
                }

                Reference reference = this.Reference;
                SignedXml signedXml = (reference == null ? this.SignedXml : reference.SignedXml);
                if (signedXml == null || signedXml.EncryptedXml == null)
                {
                    this._exml = new EncryptedXml(this._containingDocument); // default processing rules
                }
                else
                {
                    this._exml = signedXml.EncryptedXml;
                }

                return this._exml;
            }
            set { this._exml = value; }
        }

        public override Type[] InputTypes
        {
            get { return this._inputTypes; }
        }

        public override Type[] OutputTypes
        {
            get { return this._outputTypes; }
        }

        public void AddExceptUri(String uri)
        {
            if (uri == null)
            {
                throw new ArgumentNullException(nameof(uri));
            }

            this.ExceptUris.Add(uri);
        }

        public override void LoadInnerXml(XmlNodeList nodeList)
        {
            if (nodeList == null)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_UnknownTransform);
            }

            this.ExceptUris.Clear();
            foreach (XmlNode node in nodeList)
            {
                XmlElement elem = node as XmlElement;
                if (elem != null)
                {
                    if (elem.LocalName == "Except" && elem.NamespaceURI == XmlDecryptionTransformNamespaceUrl)
                    {
                        // the Uri is required
                        String uri = Utils.GetAttribute(elem, "URI", XmlDecryptionTransformNamespaceUrl);
                        if (uri == null || uri.Length == 0 || uri[0] != '#')
                        {
                            throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_UriRequired);
                        }

                        if (!Utils.VerifyAttributes(elem, "URI"))
                        {
                            throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_UnknownTransform);
                        }
                        String idref = Utils.ExtractIdFromLocalUri(uri);
                        this.ExceptUris.Add(idref);
                    }
                    else
                    {
                        throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_UnknownTransform);
                    }
                }
            }
        }

        protected override XmlNodeList GetInnerXml()
        {
            if (this.ExceptUris.Count == 0)
            {
                return null;
            }

            XmlDocument document = new XmlDocument();
            XmlElement element = document.CreateElement(SignedXml.XmlDsigNamespacePrefix, "Transform", SignedXml.XmlDsigNamespaceUrl);
            if (!String.IsNullOrEmpty(this.Algorithm))
            {
                element.SetAttribute("Algorithm", this.Algorithm);
            }

            foreach (String uri in this.ExceptUris)
            {
                XmlElement exceptUriElement = document.CreateElement(XmlDecryptionTransformNamespacePrefix, "Except", XmlDecryptionTransformNamespaceUrl);
                exceptUriElement.SetAttribute("URI", uri);
                element.AppendChild(exceptUriElement);
            }
            return element.ChildNodes;
        }

        public override void LoadInput(Object obj)
        {
            if (obj is Stream)
            {
                this.LoadStreamInput((Stream)obj);
            }
            else if (obj is XmlDocument)
            {
                this.LoadXmlDocumentInput((XmlDocument)obj);
            }
        }

        private void LoadStreamInput(Stream stream)
        {
            XmlDocument document = new XmlDocument();
            document.PreserveWhitespace = true;
            XmlResolver resolver = (this.ResolverSet ? this._xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), this.BaseURI));
            XmlReader xmlReader = Utils.PreProcessStreamInput(stream, resolver, this.BaseURI);
            document.Load(xmlReader);
            this._containingDocument = document;
            this._nsm = new XmlNamespaceManager(this._containingDocument.NameTable);
            this._nsm.AddNamespace(EncryptedXml.XmlEncNamespacePrefix, EncryptedXml.XmlEncNamespaceUrl);
            // select all EncryptedData elements
            this._encryptedDataList = document.SelectNodes("//" + EncryptedXml.XmlEncNamespacePrefix + ":EncryptedData", this._nsm);
        }

        private void LoadXmlDocumentInput(XmlDocument document)
        {
            if (document == null)
            {
                throw new ArgumentNullException(nameof(document));
            }

            this._containingDocument = document;
            this._nsm = new XmlNamespaceManager(document.NameTable);
            this._nsm.AddNamespace(EncryptedXml.XmlEncNamespacePrefix, EncryptedXml.XmlEncNamespaceUrl);
            // select all EncryptedData elements
            this._encryptedDataList = document.SelectNodes("//" + EncryptedXml.XmlEncNamespacePrefix + ":EncryptedData", this._nsm);
        }

        // Replace the encrytped XML element with the decrypted data for signature verification
        private void ReplaceEncryptedData(XmlElement encryptedDataElement, Byte[] decrypted)
        {
            XmlNode parent = encryptedDataElement.ParentNode;
            if (parent.NodeType == XmlNodeType.Document)
            {
                // We're replacing the root element.  In order to correctly reflect the semantics of the
                // decryption transform, we need to replace the entire document with the decrypted data.
                // However, EncryptedXml.ReplaceData will preserve other top-level elements such as the XML
                // entity declaration and top level comments.  So, in this case we must do the replacement
                // ourselves.
                parent.InnerXml = this.EncryptedXml.Encoding.GetString(decrypted);
            }
            else
            {
                // We're replacing a node in the middle of the document - EncryptedXml knows how to handle
                // this case in conformance with the transform's requirements, so we'll just defer to it.
                this.EncryptedXml.ReplaceData(encryptedDataElement, decrypted);
            }
        }

        private Boolean ProcessEncryptedDataItem(XmlElement encryptedDataElement)
        {
            // first see whether we want to ignore this one
            if (this.ExceptUris.Count > 0)
            {
                for (Int32 index = 0; index < this.ExceptUris.Count; index++)
                {
                    if (this.IsTargetElement(encryptedDataElement, (String)this.ExceptUris[index]))
                    {
                        return false;
                    }
                }
            }
            EncryptedData ed = new EncryptedData();
            ed.LoadXml(encryptedDataElement);
            ICipherParameters symAlg = this.EncryptedXml.GetDecryptionKey(ed, null);
            if (symAlg == null)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_MissingDecryptionKey);
            }

            Byte[] decrypted = this.EncryptedXml.DecryptData(ed, symAlg);

            this.ReplaceEncryptedData(encryptedDataElement, decrypted);
            return true;
        }

        private void ProcessElementRecursively(XmlNodeList encryptedDatas)
        {
            if (encryptedDatas == null || encryptedDatas.Count == 0)
            {
                return;
            }

            Queue encryptedDatasQueue = new Queue();
            foreach (XmlNode value in encryptedDatas)
            {
                encryptedDatasQueue.Enqueue(value);
            }
            XmlNode node = encryptedDatasQueue.Dequeue() as XmlNode;
            while (node != null)
            {
                XmlElement encryptedDataElement = node as XmlElement;
                if (encryptedDataElement != null && encryptedDataElement.LocalName == "EncryptedData" &&
                    encryptedDataElement.NamespaceURI == EncryptedXml.XmlEncNamespaceUrl)
                {
                    XmlNode sibling = encryptedDataElement.NextSibling;
                    XmlNode parent = encryptedDataElement.ParentNode;
                    if (this.ProcessEncryptedDataItem(encryptedDataElement))
                    {
                        // find the new decrypted element.
                        XmlNode child = parent.FirstChild;
                        while (child != null && child.NextSibling != sibling)
                        {
                            child = child.NextSibling;
                        }

                        if (child != null)
                        {
                            XmlNodeList nodes = child.SelectNodes("//" + EncryptedXml.XmlEncNamespacePrefix + ":EncryptedData", this._nsm);
                            if (nodes.Count > 0)
                            {
                                foreach (XmlNode value in nodes)
                                {
                                    encryptedDatasQueue.Enqueue(value);
                                }
                            }
                        }
                    }
                }
                if (encryptedDatasQueue.Count == 0)
                {
                    break;
                }

                node = encryptedDatasQueue.Dequeue() as XmlNode;
            }
        }

        public override Object GetOutput()
        {
            // decrypt the encrypted sections
            if (this._encryptedDataList != null)
            {
                this.ProcessElementRecursively(this._encryptedDataList);
            }
            // propagate namespaces
            Utils.AddNamespaces(this._containingDocument.DocumentElement, this.PropagatedNamespaces);
            return this._containingDocument;
        }

        public override Object GetOutput(Type type)
        {
            if (type == typeof(XmlDocument))
            {
                return (XmlDocument)this.GetOutput();
            }
            else
            {
                throw new ArgumentException(SR.Cryptography_Xml_TransformIncorrectInputType, nameof(type));
            }
        }
    }
}
