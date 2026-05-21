// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    public class KeyInfoName : KeyInfoClause
    {
        private String _keyName;

        //
        // public constructors
        //

        public KeyInfoName() : this(null) { }

        public KeyInfoName(String keyName)
        {
            this.Value = keyName;
        }

        //
        // public properties
        //

        public String Value
        {
            get { return this._keyName; }
            set { this._keyName = value; }
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
            XmlElement nameElement = xmlDocument.CreateElement(SignedXml.XmlDsigNamespacePrefix, "KeyName", SignedXml.XmlDsigNamespaceUrl);
            nameElement.AppendChild(xmlDocument.CreateTextNode(this._keyName));
            return nameElement;
        }

        public override void LoadXml(XmlElement value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            XmlElement nameElement = value;
            this._keyName = nameElement.InnerText.Trim();
        }
    }
}
