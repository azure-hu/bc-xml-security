// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Text;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    // the class that provides node subset state and canonicalization function to XmlWhitespace
    internal class CanonicalXmlWhitespace : XmlWhitespace, ICanonicalizableNode
    {
        private System.Boolean _isInNodeSet;

        public CanonicalXmlWhitespace(System.String strData, XmlDocument doc, System.Boolean defaultNodeSetInclusionState)
            : base(strData, doc)
        {
            this._isInNodeSet = defaultNodeSetInclusionState;
        }

        public System.Boolean IsInNodeSet
        {
            get { return this._isInNodeSet; }
            set { this._isInNodeSet = value; }
        }

        public void Write(StringBuilder strBuilder, DocPosition docPos, AncestralNamespaceContextManager anc)
        {
            if (this.IsInNodeSet && docPos == DocPosition.InRootElement)
            {
                strBuilder.Append(Utils.EscapeWhitespaceData(this.Value));
            }
        }

        public void WriteHash(IHash hash, DocPosition docPos, AncestralNamespaceContextManager anc)
        {
            if (this.IsInNodeSet && docPos == DocPosition.InRootElement)
            {
                UTF8Encoding utf8 = new UTF8Encoding(false);
                System.Byte[] rgbData = utf8.GetBytes(Utils.EscapeWhitespaceData(this.Value));
                hash.BlockUpdate(rgbData, 0, rgbData.Length);
            }
        }
    }
}
