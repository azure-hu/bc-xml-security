// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    public class KeyInfo : IEnumerable
    {
        private String _id = null;
        private readonly ArrayList _keyInfoClauses;

        //
        // public constructors
        //

        public KeyInfo()
        {
            this._keyInfoClauses = new ArrayList();
        }

        //
        // public properties
        //

        public String Id
        {
            get { return this._id; }
            set { this._id = value; }
        }

        public XmlElement GetXml()
        {
            XmlDocument xmlDocument = new XmlDocument();
            xmlDocument.PreserveWhitespace = true;
            return this.GetXml(xmlDocument);
        }

        internal XmlElement GetXml(XmlDocument xmlDocument)
        {
            // Create the KeyInfo element itself
            XmlElement keyInfoElement = xmlDocument.CreateElement(SignedXml.XmlDsigNamespacePrefix, "KeyInfo", SignedXml.XmlDsigNamespaceUrl);
            if (!String.IsNullOrEmpty(this._id))
            {
                keyInfoElement.SetAttribute("Id", this._id);
            }

            // Add all the clauses that go underneath it
            for (Int32 i = 0; i < this._keyInfoClauses.Count; ++i)
            {
                XmlElement xmlElement = ((KeyInfoClause)this._keyInfoClauses[i]).GetXml(xmlDocument);
                if (xmlElement != null)
                {
                    keyInfoElement.AppendChild(xmlElement);
                }
            }
            return keyInfoElement;
        }

        public void LoadXml(XmlElement value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            XmlElement keyInfoElement = value;
            this._id = Utils.GetAttribute(keyInfoElement, "Id", SignedXml.XmlDsigNamespaceUrl);
            if (!Utils.VerifyAttributes(keyInfoElement, "Id"))
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidElement, "KeyInfo");
            }

            XmlNode child = keyInfoElement.FirstChild;
            while (child != null)
            {
                XmlElement elem = child as XmlElement;
                if (elem != null)
                {
                    // Create the right type of KeyInfoClause; we use a combination of the namespace and tag name (local name)
                    String kicString = elem.NamespaceURI + " " + elem.LocalName;
                    // Special-case handling for KeyValue -- we have to go one level deeper
                    if (kicString == "http://www.w3.org/2000/09/xmldsig# KeyValue")
                    {
                        if (!Utils.VerifyAttributes(elem, (String[])null))
                        {
                            throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidElement, "KeyInfo/KeyValue");
                        }
                        XmlNodeList nodeList2 = elem.ChildNodes;
                        foreach (XmlNode node2 in nodeList2)
                        {
                            XmlElement elem2 = node2 as XmlElement;
                            if (elem2 != null)
                            {
                                kicString += "/" + elem2.LocalName;
                                break;
                            }
                        }
                    }

                    KeyInfoClause keyInfoClause = CryptoHelpers.CreateFromName<KeyInfoClause>(kicString);
                    // if we don't know what kind of KeyInfoClause we're looking at, use a generic KeyInfoNode:
                    if (keyInfoClause == null)
                    {
                        keyInfoClause = new KeyInfoNode();
                    }

                    // Ask the create clause to fill itself with the corresponding XML
                    keyInfoClause.LoadXml(elem);
                    // Add it to our list of KeyInfoClauses
                    this.AddClause(keyInfoClause);
                }
                child = child.NextSibling;
            }
        }

        public Int32 Count
        {
            get { return this._keyInfoClauses.Count; }
        }

        //
        // public constructors
        //

        public void AddClause(KeyInfoClause clause)
        {
            this._keyInfoClauses.Add(clause);
        }

        public IEnumerator GetEnumerator()
        {
            return this._keyInfoClauses.GetEnumerator();
        }

        public IEnumerator GetEnumerator(Type requestedObjectType)
        {
            ArrayList requestedList = new ArrayList();

            Object tempObj;
            IEnumerator tempEnum = this._keyInfoClauses.GetEnumerator();

            while (tempEnum.MoveNext())
            {
                tempObj = tempEnum.Current;
                if (requestedObjectType.Equals(tempObj.GetType()))
                {
                    requestedList.Add(tempObj);
                }
            }

            return requestedList.GetEnumerator();
        }
    }
}
