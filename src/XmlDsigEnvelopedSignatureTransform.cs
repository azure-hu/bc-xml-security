// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.IO;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    public class XmlDsigEnvelopedSignatureTransform : Transform
    {
        private readonly Type[] _inputTypes = { typeof(Stream), typeof(XmlNodeList), typeof(XmlDocument) };
        private readonly Type[] _outputTypes = { typeof(XmlNodeList), typeof(XmlDocument) };
        private XmlNodeList _inputNodeList;
        private readonly Boolean _includeComments = false;
        private XmlNamespaceManager _nsm = null;
        private XmlDocument _containingDocument = null;
        private Int32 _signaturePosition = 0;

        internal Int32 SignaturePosition
        {
            set { this._signaturePosition = value; }
        }

        public XmlDsigEnvelopedSignatureTransform()
        {
            this.Algorithm = SignedXml.XmlDsigEnvelopedSignatureTransformUrl;
        }

        /// <internalonly/>
        public XmlDsigEnvelopedSignatureTransform(Boolean includeComments)
        {
            this._includeComments = includeComments;
            this.Algorithm = SignedXml.XmlDsigEnvelopedSignatureTransformUrl;
        }

        public override Type[] InputTypes
        {
            get { return this._inputTypes; }
        }

        public override Type[] OutputTypes
        {
            get { return this._outputTypes; }
        }

        // An enveloped signature has no inner XML elements
        public override void LoadInnerXml(XmlNodeList nodeList)
        {
            if (nodeList != null && nodeList.Count > 0)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_UnknownTransform);
            }
        }

        // An enveloped signature has no inner XML elements
        protected override XmlNodeList GetInnerXml()
        {
            return null;
        }

        public override void LoadInput(Object obj)
        {
            if (obj is Stream)
            {
                this.LoadStreamInput((Stream)obj);
                return;
            }
            if (obj is XmlNodeList)
            {
                this.LoadXmlNodeListInput((XmlNodeList)obj);
                return;
            }
            if (obj is XmlDocument)
            {
                this.LoadXmlDocumentInput((XmlDocument)obj);
                return;
            }
        }

        private void LoadStreamInput(Stream stream)
        {
            XmlDocument doc = new XmlDocument();
            doc.PreserveWhitespace = true;
            XmlResolver resolver = (this.ResolverSet ? this._xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), this.BaseURI));
            XmlReader xmlReader = Utils.PreProcessStreamInput(stream, resolver, this.BaseURI);
            doc.Load(xmlReader);
            this._containingDocument = doc;
            if (this._containingDocument == null)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_EnvelopedSignatureRequiresContext);
            }

            this._nsm = new XmlNamespaceManager(this._containingDocument.NameTable);
            this._nsm.AddNamespace(SignedXml.XmlDsigNamespacePrefix, SignedXml.XmlDsigNamespaceUrl);
        }

        private void LoadXmlNodeListInput(XmlNodeList nodeList)
        {
            // Empty node list is not acceptable
            if (nodeList == null)
            {
                throw new ArgumentNullException(nameof(nodeList));
            }

            this._containingDocument = Utils.GetOwnerDocument(nodeList);
            if (this._containingDocument == null)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_EnvelopedSignatureRequiresContext);
            }

            this._nsm = new XmlNamespaceManager(this._containingDocument.NameTable);
            this._nsm.AddNamespace(SignedXml.XmlDsigNamespacePrefix, SignedXml.XmlDsigNamespaceUrl);
            this._inputNodeList = nodeList;
        }

        private void LoadXmlDocumentInput(XmlDocument doc)
        {
            if (doc == null)
            {
                throw new ArgumentNullException(nameof(doc));
            }

            this._containingDocument = doc;
            this._nsm = new XmlNamespaceManager(this._containingDocument.NameTable);
            this._nsm.AddNamespace(SignedXml.XmlDsigNamespacePrefix, SignedXml.XmlDsigNamespaceUrl);
        }

        public override Object GetOutput()
        {
            if (this._containingDocument == null)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_EnvelopedSignatureRequiresContext);
            }

            // If we have received an XmlNodeList as input
            if (this._inputNodeList != null)
            {
                // If the position has not been set, then we don't want to remove any signature tags
                if (this._signaturePosition == 0)
                {
                    return this._inputNodeList;
                }

                XmlNodeList signatureList = this._containingDocument.SelectNodes("//" + SignedXml.XmlDsigNamespacePrefix + ":Signature", this._nsm);
                if (signatureList == null)
                {
                    return this._inputNodeList;
                }

                CanonicalXmlNodeList resultNodeList = new CanonicalXmlNodeList();
                foreach (XmlNode node in this._inputNodeList)
                {
                    if (node == null)
                    {
                        continue;
                    }
                    // keep namespaces
                    if (Utils.IsXmlNamespaceNode(node) || Utils.IsNamespaceNode(node))
                    {
                        resultNodeList.Add(node);
                    }
                    else
                    {
                        // SelectSingleNode throws an exception for xmldecl PI for example, so we will just ignore those exceptions
                        try
                        {
                            // Find the nearest signature ancestor tag
                            XmlNode result = node.SelectSingleNode("ancestor-or-self::" + SignedXml.XmlDsigNamespacePrefix + ":Signature[1]", this._nsm);
                            Int32 position = 0;
                            foreach (XmlNode node1 in signatureList)
                            {
                                position++;
                                if (node1 == result)
                                {
                                    break;
                                }
                            }
                            if (result == null || position != this._signaturePosition)
                            {
                                resultNodeList.Add(node);
                            }
                        }
                        catch { }
                    }
                }
                return resultNodeList;
            }
            // Else we have received either a stream or a document as input
            else
            {
                XmlNodeList signatureList = this._containingDocument.SelectNodes("//" + SignedXml.XmlDsigNamespacePrefix + ":Signature", this._nsm);
                if (signatureList == null)
                {
                    return this._containingDocument;
                }

                if (signatureList.Count < this._signaturePosition || this._signaturePosition <= 0)
                {
                    return this._containingDocument;
                }

                // Remove the signature node with all its children nodes
                signatureList[this._signaturePosition - 1].ParentNode.RemoveChild(signatureList[this._signaturePosition - 1]);
                return this._containingDocument;
            }
        }

        public override Object GetOutput(Type type)
        {
            if (type == typeof(XmlNodeList) || type.IsSubclassOf(typeof(XmlNodeList)))
            {
                if (this._inputNodeList == null)
                {
                    this._inputNodeList = Utils.AllDescendantNodes(this._containingDocument, true);
                }
                return (XmlNodeList)this.GetOutput();
            }
            else if (type == typeof(XmlDocument) || type.IsSubclassOf(typeof(XmlDocument)))
            {
                if (this._inputNodeList != null)
                {
                    throw new ArgumentException(SR.Cryptography_Xml_TransformIncorrectInputType, nameof(type));
                }

                return (XmlDocument)this.GetOutput();
            }
            else
            {
                throw new ArgumentException(SR.Cryptography_Xml_TransformIncorrectInputType, nameof(type));
            }
        }
    }
}
