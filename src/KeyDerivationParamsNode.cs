// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    // This is for generic, unknown nodes
    public class KeyDerivationParamsNode : KeyDerivationParamsClause
    {
        private XmlElement _node;

        //
        // public constructors
        //

        public KeyDerivationParamsNode() { }

        public KeyDerivationParamsNode(XmlElement node)
        {
            this._node = node;
        }

        //
        // public properties
        //

        public override String Algorithm { get { return String.Empty; } }

        public XmlElement Value
        {
            get { return this._node; }
            set { this._node = value; }
        }

        //
        // public methods
        //

        public override XmlElement GetXml()
        {
            XmlDocument xmlDocument = new XmlDocument();
            xmlDocument.PreserveWhitespace = true;
            return this.GetXml(xmlDocument);
        }

        internal override XmlElement GetXml(XmlDocument xmlDocument)
        {
            return xmlDocument.ImportNode(this._node, true) as XmlElement;
        }

        public override void LoadXml(XmlElement value)
        {
            this._node = value;
        }
    }
}
