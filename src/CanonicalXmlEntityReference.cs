// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Text;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    // the class that provides node subset state and canonicalization function to XmlEntityReference
    internal class CanonicalXmlEntityReference : XmlEntityReference, ICanonicalizableNode
    {
        private Boolean _isInNodeSet;

        public CanonicalXmlEntityReference(String name, XmlDocument doc, Boolean defaultNodeSetInclusionState)
            : base(name, doc)
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
            if (this.IsInNodeSet)
            {
                CanonicalizationDispatcher.WriteGenericNode(this, strBuilder, docPos, anc);
            }
        }

        public void WriteHash(IHash hash, DocPosition docPos, AncestralNamespaceContextManager anc)
        {
            if (this.IsInNodeSet)
            {
                CanonicalizationDispatcher.WriteHashGenericNode(this, hash, docPos, anc);
            }
        }
    }
}
