// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Text;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    // the class that provides node subset state and canonicalization function to XmlAttribute
    internal class CanonicalXmlAttribute : XmlAttribute, ICanonicalizableNode
    {
        private Boolean _isInNodeSet;

        public CanonicalXmlAttribute(String prefix, String localName, String namespaceURI, XmlDocument doc, Boolean defaultNodeSetInclusionState)
            : base(prefix, localName, namespaceURI, doc)
        {
            this.IsInNodeSet = defaultNodeSetInclusionState;
        }

        public Boolean IsInNodeSet
        {
            get { return this._isInNodeSet; }
            set { this._isInNodeSet = value; }
        }

        public void Write(StringBuilder strBuilder, DocPosition docPos, AncestralNamespaceContextManager anc)
        {
            strBuilder.Append(" " + this.Name + "=\"");
            strBuilder.Append(Utils.EscapeAttributeValue(this.Value));
            strBuilder.Append("\"");
        }

        public void WriteHash(IHash hash, DocPosition docPos, AncestralNamespaceContextManager anc)
        {
            UTF8Encoding utf8 = new UTF8Encoding(false);
            Byte[] rgbData = utf8.GetBytes(" " + this.Name + "=\"");
            hash.BlockUpdate(rgbData, 0, rgbData.Length);
            rgbData = utf8.GetBytes(Utils.EscapeAttributeValue(this.Value));
            hash.BlockUpdate(rgbData, 0, rgbData.Length);
            rgbData = utf8.GetBytes("\"");
            hash.BlockUpdate(rgbData, 0, rgbData.Length);
        }
    }
}
