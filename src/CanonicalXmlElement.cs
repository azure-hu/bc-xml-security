// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections;
using System.Text;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    // the class that provides node subset state and canonicalization function to XmlElement
    internal class CanonicalXmlElement : XmlElement, ICanonicalizableNode
    {
        private Boolean _isInNodeSet;

        public CanonicalXmlElement(String prefix, String localName, String namespaceURI, XmlDocument doc, Boolean defaultNodeSetInclusionState)
            : base(prefix, localName, namespaceURI, doc)
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
            Hashtable nsLocallyDeclared = new Hashtable();
            SortedList nsListToRender = new SortedList(new NamespaceSortOrder());
            SortedList attrListToRender = new SortedList(new AttributeSortOrder());

            XmlAttributeCollection attrList = this.Attributes;
            if (attrList != null)
            {
                foreach (XmlAttribute attr in attrList)
                {
                    if (((CanonicalXmlAttribute)attr).IsInNodeSet || Utils.IsNamespaceNode(attr) || Utils.IsXmlNamespaceNode(attr))
                    {
                        if (Utils.IsNamespaceNode(attr))
                        {
                            anc.TrackNamespaceNode(attr, nsListToRender, nsLocallyDeclared);
                        }
                        else if (Utils.IsXmlNamespaceNode(attr))
                        {
                            anc.TrackXmlNamespaceNode(attr, nsListToRender, attrListToRender, nsLocallyDeclared);
                        }
                        else if (this.IsInNodeSet)
                        {
                            attrListToRender.Add(attr, null);
                        }
                    }
                }
            }

            if (!Utils.IsCommittedNamespace(this, this.Prefix, this.NamespaceURI))
            {
                String name = ((this.Prefix.Length > 0) ? "xmlns" + ":" + this.Prefix : "xmlns");
                XmlAttribute nsattrib = (XmlAttribute)this.OwnerDocument.CreateAttribute(name);
                nsattrib.Value = this.NamespaceURI;
                anc.TrackNamespaceNode(nsattrib, nsListToRender, nsLocallyDeclared);
            }

            if (this.IsInNodeSet)
            {
                anc.GetNamespacesToRender(this, attrListToRender, nsListToRender, nsLocallyDeclared);

                strBuilder.Append('<').Append(this.Name);
                foreach (Object attr in nsListToRender.GetKeyList())
                {
                    (attr as CanonicalXmlAttribute).Write(strBuilder, docPos, anc);
                }
                foreach (Object attr in attrListToRender.GetKeyList())
                {
                    (attr as CanonicalXmlAttribute).Write(strBuilder, docPos, anc);
                }
                strBuilder.Append('>');
            }

            anc.EnterElementContext();
            anc.LoadUnrenderedNamespaces(nsLocallyDeclared);
            anc.LoadRenderedNamespaces(nsListToRender);

            XmlNodeList childNodes = this.ChildNodes;
            foreach (XmlNode childNode in childNodes)
            {
                CanonicalizationDispatcher.Write(childNode, strBuilder, docPos, anc);
            }

            anc.ExitElementContext();

            if (this.IsInNodeSet)
            {
                strBuilder.Append("</" + this.Name + ">");
            }
        }

        public void WriteHash(IHash hash, DocPosition docPos, AncestralNamespaceContextManager anc)
        {
            Hashtable nsLocallyDeclared = new Hashtable();
            SortedList nsListToRender = new SortedList(new NamespaceSortOrder());
            SortedList attrListToRender = new SortedList(new AttributeSortOrder());
            UTF8Encoding utf8 = new UTF8Encoding(false);
            Byte[] rgbData;

            XmlAttributeCollection attrList = this.Attributes;
            if (attrList != null)
            {
                foreach (XmlAttribute attr in attrList)
                {
                    if (((CanonicalXmlAttribute)attr).IsInNodeSet || Utils.IsNamespaceNode(attr) || Utils.IsXmlNamespaceNode(attr))
                    {
                        if (Utils.IsNamespaceNode(attr))
                        {
                            anc.TrackNamespaceNode(attr, nsListToRender, nsLocallyDeclared);
                        }
                        else if (Utils.IsXmlNamespaceNode(attr))
                        {
                            anc.TrackXmlNamespaceNode(attr, nsListToRender, attrListToRender, nsLocallyDeclared);
                        }
                        else if (this.IsInNodeSet)
                        {
                            attrListToRender.Add(attr, null);
                        }
                    }
                }
            }

            if (!Utils.IsCommittedNamespace(this, this.Prefix, this.NamespaceURI))
            {
                String name = ((this.Prefix.Length > 0) ? "xmlns" + ":" + this.Prefix : "xmlns");
                XmlAttribute nsattrib = (XmlAttribute)this.OwnerDocument.CreateAttribute(name);
                nsattrib.Value = this.NamespaceURI;
                anc.TrackNamespaceNode(nsattrib, nsListToRender, nsLocallyDeclared);
            }

            if (this.IsInNodeSet)
            {
                anc.GetNamespacesToRender(this, attrListToRender, nsListToRender, nsLocallyDeclared);
                rgbData = utf8.GetBytes("<" + this.Name);
                hash.BlockUpdate(rgbData, 0, rgbData.Length);
                foreach (Object attr in nsListToRender.GetKeyList())
                {
                    (attr as CanonicalXmlAttribute).WriteHash(hash, docPos, anc);
                }
                foreach (Object attr in attrListToRender.GetKeyList())
                {
                    (attr as CanonicalXmlAttribute).WriteHash(hash, docPos, anc);
                }
                rgbData = utf8.GetBytes(">");
                hash.BlockUpdate(rgbData, 0, rgbData.Length);
            }

            anc.EnterElementContext();
            anc.LoadUnrenderedNamespaces(nsLocallyDeclared);
            anc.LoadRenderedNamespaces(nsListToRender);

            XmlNodeList childNodes = this.ChildNodes;
            foreach (XmlNode childNode in childNodes)
            {
                CanonicalizationDispatcher.WriteHash(childNode, hash, docPos, anc);
            }

            anc.ExitElementContext();

            if (this.IsInNodeSet)
            {
                rgbData = utf8.GetBytes("</" + this.Name + ">");
                hash.BlockUpdate(rgbData, 0, rgbData.Length);
            }
        }
    }
}
