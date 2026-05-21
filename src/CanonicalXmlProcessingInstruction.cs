// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Text;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    // the class that provides node subset state and canonicalization function to XmlProcessingInstruction
    internal class CanonicalXmlProcessingInstruction : XmlProcessingInstruction, ICanonicalizableNode
    {
        private Boolean _isInNodeSet;

        public CanonicalXmlProcessingInstruction(String target, String data, XmlDocument doc, Boolean defaultNodeSetInclusionState)
            : base(target, data, doc)
        {
            this._isInNodeSet = defaultNodeSetInclusionState;
        }

        public Boolean IsInNodeSet
        {
            get { return this._isInNodeSet; }
            set { this._isInNodeSet = value; }
        }

        public void Write(StringBuilder strBuilder, DocPosition docPos, AncestralNamespaceContextManager anc)
        {
            if (!this.IsInNodeSet)
            {
                return;
            }

            if (docPos == DocPosition.AfterRootElement)
            {
                strBuilder.Append((Char)10);
            }

            strBuilder.Append("<?");
            strBuilder.Append(this.Name);
            if ((this.Value != null) && (this.Value.Length > 0))
            {
                strBuilder.Append(" " + this.Value);
            }

            strBuilder.Append("?>");
            if (docPos == DocPosition.BeforeRootElement)
            {
                strBuilder.Append((Char)10);
            }
        }

        public void WriteHash(IHash hash, DocPosition docPos, AncestralNamespaceContextManager anc)
        {
            if (!this.IsInNodeSet)
            {
                return;
            }

            UTF8Encoding utf8 = new UTF8Encoding(false);
            Byte[] rgbData;
            if (docPos == DocPosition.AfterRootElement)
            {
                rgbData = utf8.GetBytes("(char) 10");
                hash.BlockUpdate(rgbData, 0, rgbData.Length);
            }
            rgbData = utf8.GetBytes("<?");
            hash.BlockUpdate(rgbData, 0, rgbData.Length);
            rgbData = utf8.GetBytes((this.Name));
            hash.BlockUpdate(rgbData, 0, rgbData.Length);
            if ((this.Value != null) && (this.Value.Length > 0))
            {
                rgbData = utf8.GetBytes(" " + this.Value);
                hash.BlockUpdate(rgbData, 0, rgbData.Length);
            }
            rgbData = utf8.GetBytes("?>");
            hash.BlockUpdate(rgbData, 0, rgbData.Length);
            if (docPos == DocPosition.BeforeRootElement)
            {
                rgbData = utf8.GetBytes("(char) 10");
                hash.BlockUpdate(rgbData, 0, rgbData.Length);
            }
        }
    }
}
