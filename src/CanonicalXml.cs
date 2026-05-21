// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.IO;
using System.Text;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    internal class CanonicalXml
    {
        private readonly CanonicalXmlDocument _c14nDoc;
        private readonly C14NAncestralNamespaceContextManager _ancMgr;

        // private static string defaultXPathWithoutComments = "(//. | //@* | //namespace::*)[not(self::comment())]";
        // private static string defaultXPathWithoutComments = "(//. | //@* | //namespace::*)";
        // private static string defaultXPathWithComments = "(//. | //@* | //namespace::*)";
        // private static string defaultXPathWithComments = "(//. | //@* | //namespace::*)";

        internal CanonicalXml(Stream inputStream, Boolean includeComments, XmlResolver resolver, String strBaseUri)
        {
            if (inputStream == null)
            {
                throw new ArgumentNullException(nameof(inputStream));
            }

            this._c14nDoc = new CanonicalXmlDocument(true, includeComments);
            this._c14nDoc.XmlResolver = resolver;
            this._c14nDoc.Load(Utils.PreProcessStreamInput(inputStream, resolver, strBaseUri));
            this._ancMgr = new C14NAncestralNamespaceContextManager();
        }

        internal CanonicalXml(XmlDocument document, XmlResolver resolver) : this(document, resolver, false) { }
        internal CanonicalXml(XmlDocument document, XmlResolver resolver, Boolean includeComments)
        {
            if (document == null)
            {
                throw new ArgumentNullException(nameof(document));
            }

            this._c14nDoc = new CanonicalXmlDocument(true, includeComments);
            this._c14nDoc.XmlResolver = resolver;
            this._c14nDoc.Load(new XmlNodeReader(document));
            this._ancMgr = new C14NAncestralNamespaceContextManager();
        }

        internal CanonicalXml(XmlNodeList nodeList, XmlResolver resolver, Boolean includeComments)
        {
            if (nodeList == null)
            {
                throw new ArgumentNullException(nameof(nodeList));
            }

            XmlDocument doc = Utils.GetOwnerDocument(nodeList);
            if (doc == null)
            {
                throw new ArgumentException(nameof(nodeList));
            }

            this._c14nDoc = new CanonicalXmlDocument(false, includeComments);
            this._c14nDoc.XmlResolver = resolver;
            this._c14nDoc.Load(new XmlNodeReader(doc));
            this._ancMgr = new C14NAncestralNamespaceContextManager();

            MarkInclusionStateForNodes(nodeList, doc, this._c14nDoc);
        }

        private static void MarkNodeAsIncluded(XmlNode node)
        {
            if (node is ICanonicalizableNode)
            {
                ((ICanonicalizableNode)node).IsInNodeSet = true;
            }
        }

        private static void MarkInclusionStateForNodes(XmlNodeList nodeList, XmlDocument inputRoot, XmlDocument root)
        {
            CanonicalXmlNodeList elementList = new CanonicalXmlNodeList();
            CanonicalXmlNodeList elementListCanonical = new CanonicalXmlNodeList();
            elementList.Add(inputRoot);
            elementListCanonical.Add(root);
            Int32 index = 0;

            do
            {
                XmlNode currentNode = (XmlNode)elementList[index];
                XmlNode currentNodeCanonical = (XmlNode)elementListCanonical[index];
                XmlNodeList childNodes = currentNode.ChildNodes;
                XmlNodeList childNodesCanonical = currentNodeCanonical.ChildNodes;
                for (Int32 i = 0; i < childNodes.Count; i++)
                {
                    elementList.Add(childNodes[i]);
                    elementListCanonical.Add(childNodesCanonical[i]);

                    if (Utils.NodeInList(childNodes[i], nodeList))
                    {
                        MarkNodeAsIncluded(childNodesCanonical[i]);
                    }

                    XmlAttributeCollection attribNodes = childNodes[i].Attributes;
                    if (attribNodes != null)
                    {
                        for (Int32 j = 0; j < attribNodes.Count; j++)
                        {
                            if (Utils.NodeInList(attribNodes[j], nodeList))
                            {
                                MarkNodeAsIncluded(childNodesCanonical[i].Attributes.Item(j));
                            }
                        }
                    }
                }
                index++;
            } while (index < elementList.Count);
        }

        internal Byte[] GetBytes()
        {
            StringBuilder sb = new StringBuilder();
            this._c14nDoc.Write(sb, DocPosition.BeforeRootElement, this._ancMgr);
            UTF8Encoding utf8 = new UTF8Encoding(false);
            return utf8.GetBytes(sb.ToString());
        }

        internal void GetDigestedBytes(IHash signer)
        {
            this._c14nDoc.WriteHash(signer, DocPosition.BeforeRootElement, this._ancMgr);
        }
    }
}
