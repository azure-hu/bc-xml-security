// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    public class DataObject
    {
        private String _id;
        private String _mimeType;
        private String _encoding;
        private CanonicalXmlNodeList _elData;
        private String _innerText;
        private XmlElement _cachedXml;

        //
        // public constructors
        //

        public DataObject()
        {
            this._cachedXml = null;
            this._elData = new CanonicalXmlNodeList();
        }

        public DataObject(String id, String mimeType, String encoding, XmlElement data)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            this._id = id;
            this._mimeType = mimeType;
            this._encoding = encoding;
            this._elData = new CanonicalXmlNodeList();
            this._elData.Add(data);
            this._cachedXml = null;
        }

        //
        // public properties
        //

        public String Id
        {
            get { return this._id; }
            set
            {
                this._id = value;
                this._cachedXml = null;
            }
        }

        public String MimeType
        {
            get { return this._mimeType; }
            set
            {
                this._mimeType = value;
                this._cachedXml = null;
            }
        }

        public String Encoding
        {
            get { return this._encoding; }
            set
            {
                this._encoding = value;
                this._cachedXml = null;
            }
        }

        public XmlNodeList Data
        {
            get { return this._elData; }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(value));
                }

                // Reset the node list
                this._innerText = null;
                this._elData = new CanonicalXmlNodeList();
                foreach (XmlNode node in value)
                {
                    this._elData.Add(node);
                }
                this._cachedXml = null;
            }
        }

        public String InnerText
        {
            get { return this._innerText; }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(value));
                }

                // Reset the node list
                this._elData = null;
                this._innerText = value;
                this._cachedXml = null;
            }
        }

        private Boolean CacheValid
        {
            get
            {
                return (this._cachedXml != null);
            }
        }

        //
        // public methods
        //

        public XmlElement GetXml()
        {
            if (this.CacheValid)
            {
                return (this._cachedXml);
            }

            XmlDocument document = new XmlDocument();
            document.PreserveWhitespace = true;
            return this.GetXml(document);
        }

        internal XmlElement GetXml(XmlDocument document)
        {
            XmlElement objectElement = document.CreateElement(SignedXml.XmlDsigNamespacePrefix, "Object", SignedXml.XmlDsigNamespaceUrl);

            if (!String.IsNullOrEmpty(this._id))
            {
                objectElement.SetAttribute("Id", this._id);
            }

            if (!String.IsNullOrEmpty(this._mimeType))
            {
                objectElement.SetAttribute("MimeType", this._mimeType);
            }

            if (!String.IsNullOrEmpty(this._encoding))
            {
                objectElement.SetAttribute("Encoding", this._encoding);
            }

            if (this._elData != null && this._elData.Count > 0)
            {
                foreach (XmlNode node in this._elData)
                {
                    objectElement.AppendChild(document.ImportNode(node, true));
                }
            }
            else if (!String.IsNullOrEmpty(this._innerText))
            {
                objectElement.InnerText = this._innerText;
            }

            return objectElement;
        }

        public void LoadXml(XmlElement value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            this._id = Utils.GetAttribute(value, "Id", SignedXml.XmlDsigNamespaceUrl);
            this._mimeType = Utils.GetAttribute(value, "MimeType", SignedXml.XmlDsigNamespaceUrl);
            this._encoding = Utils.GetAttribute(value, "Encoding", SignedXml.XmlDsigNamespaceUrl);

            foreach (XmlNode node in value.ChildNodes)
            {
                this._elData.Add(node);
            }

            // Save away the cached value
            this._cachedXml = value;
        }
    }
}
