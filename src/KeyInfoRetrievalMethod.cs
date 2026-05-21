// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    public class KeyInfoRetrievalMethod : KeyInfoClause
    {
        private String _uri;
        private String _type;

        //
        // public constructors
        //

        public KeyInfoRetrievalMethod() { }

        public KeyInfoRetrievalMethod(String strUri)
        {
            this._uri = strUri;
        }

        public KeyInfoRetrievalMethod(String strUri, String typeName)
        {
            this._uri = strUri;
            this._type = typeName;
        }

        //
        // public properties
        //

        public String Uri
        {
            get { return this._uri; }
            set { this._uri = value; }
        }

        public String Type
        {
            get { return this._type; }
            set { this._type = value; }
        }

        public override XmlElement GetXml()
        {
            XmlDocument xmlDocument = new XmlDocument();
            xmlDocument.PreserveWhitespace = true;
            return this.GetXml(xmlDocument);
        }

        internal override XmlElement GetXml(XmlDocument xmlDocument)
        {
            // Create the actual element
            XmlElement retrievalMethodElement = xmlDocument.CreateElement(SignedXml.XmlDsigNamespacePrefix, "RetrievalMethod", SignedXml.XmlDsigNamespaceUrl);

            if (!String.IsNullOrEmpty(this._uri))
            {
                retrievalMethodElement.SetAttribute("URI", this._uri);
            }

            if (!String.IsNullOrEmpty(this._type))
            {
                retrievalMethodElement.SetAttribute("Type", this._type);
            }

            return retrievalMethodElement;
        }

        public override void LoadXml(XmlElement value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            this._uri = Utils.GetAttribute(value, "URI", SignedXml.XmlDsigNamespaceUrl);
            this._type = Utils.GetAttribute(value, "Type", SignedXml.XmlDsigNamespaceUrl);
        }
    }
}
