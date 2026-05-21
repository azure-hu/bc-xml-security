// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Text;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    // all input types eventually lead to the creation of an XmlDocument document
    // of this type. it maintains the node subset state and performs output rendering during canonicalization
    internal class CanonicalXmlDocument : XmlDocument, ICanonicalizableNode
    {
        private readonly Boolean _defaultNodeSetInclusionState;
        private readonly Boolean _includeComments;
        private Boolean _isInNodeSet;

        public CanonicalXmlDocument(Boolean defaultNodeSetInclusionState, Boolean includeComments) : base()
        {
            this.PreserveWhitespace = true;
            this._includeComments = includeComments;
            this._isInNodeSet = this._defaultNodeSetInclusionState = defaultNodeSetInclusionState;
        }

        public Boolean IsInNodeSet
        {
            get { return this._isInNodeSet; }
            set { this._isInNodeSet = value; }
        }

        public void Write(StringBuilder strBuilder, DocPosition docPos, AncestralNamespaceContextManager anc)
        {
            docPos = DocPosition.BeforeRootElement;
            foreach (XmlNode childNode in this.ChildNodes)
            {
                if (childNode.NodeType == XmlNodeType.Element)
                {
                    CanonicalizationDispatcher.Write(childNode, strBuilder, DocPosition.InRootElement, anc);
                    docPos = DocPosition.AfterRootElement;
                }
                else
                {
                    CanonicalizationDispatcher.Write(childNode, strBuilder, docPos, anc);
                }
            }
        }

        public void WriteHash(IHash signer, DocPosition docPos, AncestralNamespaceContextManager anc)
        {
            docPos = DocPosition.BeforeRootElement;
            foreach (XmlNode childNode in this.ChildNodes)
            {
                if (childNode.NodeType == XmlNodeType.Element)
                {
                    CanonicalizationDispatcher.WriteHash(childNode, signer, DocPosition.InRootElement, anc);
                    docPos = DocPosition.AfterRootElement;
                }
                else
                {
                    CanonicalizationDispatcher.WriteHash(childNode, signer, docPos, anc);
                }
            }
        }

        public override XmlElement CreateElement(String prefix, String localName, String namespaceURI)
        {
            return new CanonicalXmlElement(prefix, localName, namespaceURI, this, this._defaultNodeSetInclusionState);
        }

        public override XmlAttribute CreateAttribute(String prefix, String localName, String namespaceURI)
        {
            return new CanonicalXmlAttribute(prefix, localName, namespaceURI, this, this._defaultNodeSetInclusionState);
        }

        protected override XmlAttribute CreateDefaultAttribute(String prefix, String localName, String namespaceURI)
        {
            return new CanonicalXmlAttribute(prefix, localName, namespaceURI, this, this._defaultNodeSetInclusionState);
        }

        public override XmlText CreateTextNode(String text)
        {
            return new CanonicalXmlText(text, this, this._defaultNodeSetInclusionState);
        }

        public override XmlWhitespace CreateWhitespace(String prefix)
        {
            return new CanonicalXmlWhitespace(prefix, this, this._defaultNodeSetInclusionState);
        }

        public override XmlSignificantWhitespace CreateSignificantWhitespace(String text)
        {
            return new CanonicalXmlSignificantWhitespace(text, this, this._defaultNodeSetInclusionState);
        }

        public override XmlProcessingInstruction CreateProcessingInstruction(String target, String data)
        {
            return new CanonicalXmlProcessingInstruction(target, data, this, this._defaultNodeSetInclusionState);
        }

        public override XmlComment CreateComment(String data)
        {
            return new CanonicalXmlComment(data, this, this._defaultNodeSetInclusionState, this._includeComments);
        }

        public override XmlEntityReference CreateEntityReference(String name)
        {
            return new CanonicalXmlEntityReference(name, this, this._defaultNodeSetInclusionState);
        }

        public override XmlCDataSection CreateCDataSection(String data)
        {
            return new CanonicalXmlCDataSection(data, this, this._defaultNodeSetInclusionState);
        }
    }
}
