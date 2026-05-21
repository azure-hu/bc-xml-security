// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.IO;
using System.Text;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    internal class ExcCanonicalXml
    {
        private readonly CanonicalXmlDocument _c14nDoc;
        private readonly ExcAncestralNamespaceContextManager _ancMgr;

        internal ExcCanonicalXml(Stream inputStream, Boolean includeComments, String inclusiveNamespacesPrefixList, XmlResolver resolver, String strBaseUri)
        {
            if (inputStream == null)
            {
                throw new ArgumentNullException(nameof(inputStream));
            }

            this._c14nDoc = new CanonicalXmlDocument(true, includeComments);
            this._c14nDoc.XmlResolver = resolver;
            this._c14nDoc.Load(Utils.PreProcessStreamInput(inputStream, resolver, strBaseUri));
            this._ancMgr = new ExcAncestralNamespaceContextManager(inclusiveNamespacesPrefixList);
        }

        internal ExcCanonicalXml(XmlDocument document, Boolean includeComments, String inclusiveNamespacesPrefixList, XmlResolver resolver)
        {
            if (document == null)
            {
                throw new ArgumentNullException(nameof(document));
            }

            this._c14nDoc = new CanonicalXmlDocument(true, includeComments);
            this._c14nDoc.XmlResolver = resolver;
            this._c14nDoc.Load(new XmlNodeReader(document));
            this._ancMgr = new ExcAncestralNamespaceContextManager(inclusiveNamespacesPrefixList);
        }

        internal ExcCanonicalXml(XmlNodeList nodeList, Boolean includeComments, String inclusiveNamespacesPrefixList, XmlResolver resolver)
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
            this._ancMgr = new ExcAncestralNamespaceContextManager(inclusiveNamespacesPrefixList);

            MarkInclusionStateForNodes(nodeList, doc, this._c14nDoc);
        }

        internal Byte[] GetBytes()
        {
            StringBuilder sb = new StringBuilder();
            this._c14nDoc.Write(sb, DocPosition.BeforeRootElement, this._ancMgr);
            UTF8Encoding utf8 = new UTF8Encoding(false);
            return utf8.GetBytes(sb.ToString());
        }

        internal void GetDigestedBytes(IHash hash)
        {
            this._c14nDoc.WriteHash(hash, DocPosition.BeforeRootElement, this._ancMgr);
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

        private static void MarkNodeAsIncluded(XmlNode node)
        {
            if (node is ICanonicalizableNode)
            {
                ((ICanonicalizableNode)node).IsInNodeSet = true;
            }
        }
    }
}
