// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.IO;
using System.Xml;
using System.Xml.XPath;

namespace Org.BouncyCastle.Crypto.Xml
{
    // A class representing DSIG XPath Transforms

    public class XmlDsigXPathTransform : Transform
    {
        private readonly Type[] _inputTypes = { typeof(Stream), typeof(XmlNodeList), typeof(XmlDocument) };
        private readonly Type[] _outputTypes = { typeof(XmlNodeList) };
        private String _xpathexpr;
        private XmlDocument _document;
        private XmlNamespaceManager _nsm;

        public XmlDsigXPathTransform()
        {
            this.Algorithm = SignedXml.XmlDsigXPathTransformUrl;
        }

        public override Type[] InputTypes
        {
            get { return this._inputTypes; }
        }

        public override Type[] OutputTypes
        {
            get { return this._outputTypes; }
        }

        public override void LoadInnerXml(XmlNodeList nodeList)
        {
            // XPath transform is specified by text child of first XPath child
            if (nodeList == null)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_UnknownTransform);
            }

            foreach (XmlNode node in nodeList)
            {
                String prefix = null;
                String namespaceURI = null;
                XmlElement elem = node as XmlElement;
                if (elem != null)
                {
                    if (elem.LocalName == "XPath")
                    {
                        this._xpathexpr = elem.InnerXml.Trim(null);
                        XmlNodeReader nr = new XmlNodeReader(elem);
                        XmlNameTable nt = nr.NameTable;
                        this._nsm = new XmlNamespaceManager(nt);
                        if (!Utils.VerifyAttributes(elem, (String)null))
                        {
                            throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_UnknownTransform);
                        }
                        // Look for a namespace in the attributes
                        foreach (XmlAttribute attrib in elem.Attributes)
                        {
                            if (attrib.Prefix == "xmlns")
                            {
                                prefix = attrib.LocalName;
                                namespaceURI = attrib.Value;
                                if (prefix == null)
                                {
                                    prefix = elem.Prefix;
                                    namespaceURI = elem.NamespaceURI;
                                }
                                this._nsm.AddNamespace(prefix, namespaceURI);
                            }
                        }
                        break;
                    }
                    else
                    {
                        throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_UnknownTransform);
                    }
                }
            }

            if (this._xpathexpr == null)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_UnknownTransform);
            }
        }

        protected override XmlNodeList GetInnerXml()
        {
            XmlDocument document = new XmlDocument();
            XmlElement element = document.CreateElement(SignedXml.DefaultXmlDsigNamespacePrefix, "XPath", SignedXml.XmlDsigNamespaceUrl);

            if (this._nsm != null)
            {
                // Add each of the namespaces as attributes of the element
                foreach (String prefix in this._nsm)
                {
                    switch (prefix)
                    {
                        // Ignore the xml namespaces
                        case "xml":
                        case "xmlns":
                            break;

                        // Other namespaces
                        default:
                            // Ignore the default namespace
                            if (prefix != null && prefix.Length > 0)
                            {
                                element.SetAttribute("xmlns:" + prefix, this._nsm.LookupNamespace(prefix));
                            }

                            break;
                    }
                }
            }
            // Add the XPath as the inner xml of the element
            element.InnerXml = this._xpathexpr;
            document.AppendChild(element);
            return document.ChildNodes;
        }

        public override void LoadInput(Object obj)
        {
            if (obj is Stream)
            {
                this.LoadStreamInput((Stream)obj);
            }
            else if (obj is XmlNodeList)
            {
                this.LoadXmlNodeListInput((XmlNodeList)obj);
            }
            else if (obj is XmlDocument)
            {
                this.LoadXmlDocumentInput((XmlDocument)obj);
            }
        }

        private void LoadStreamInput(Stream stream)
        {
            XmlResolver resolver = (this.ResolverSet ? this._xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), this.BaseURI));
            XmlReader valReader = Utils.PreProcessStreamInput(stream, resolver, this.BaseURI);
            this._document = new XmlDocument();
            this._document.PreserveWhitespace = true;
            this._document.Load(valReader);
        }

        private void LoadXmlNodeListInput(XmlNodeList nodeList)
        {
            // Use C14N to get a document
            XmlResolver resolver = (this.ResolverSet ? this._xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), this.BaseURI));
            CanonicalXml c14n = new CanonicalXml((XmlNodeList)nodeList, resolver, true);
            using (MemoryStream ms = new MemoryStream(c14n.GetBytes()))
            {
                this.LoadStreamInput(ms);
            }
        }

        private void LoadXmlDocumentInput(XmlDocument doc)
        {
            this._document = doc;
        }

        public override Object GetOutput()
        {
            CanonicalXmlNodeList resultNodeList = new CanonicalXmlNodeList();
            if (!String.IsNullOrEmpty(this._xpathexpr))
            {
                XPathNavigator navigator = this._document.CreateNavigator();
                XPathNodeIterator it = navigator.Select("//. | //@*");

                XPathExpression xpathExpr = navigator.Compile("boolean(" + this._xpathexpr + ")");
                xpathExpr.SetContext(this._nsm);

                while (it.MoveNext())
                {
                    XmlNode node = ((IHasXmlNode)it.Current).GetNode();

                    Boolean include = (Boolean)it.Current.Evaluate(xpathExpr);
                    if (include == true)
                    {
                        resultNodeList.Add(node);
                    }
                }

                // keep namespaces
                it = navigator.Select("//namespace::*");
                while (it.MoveNext())
                {
                    XmlNode node = ((IHasXmlNode)it.Current).GetNode();
                    resultNodeList.Add(node);
                }
            }

            return resultNodeList;
        }

        public override Object GetOutput(Type type)
        {
            if (type != typeof(XmlNodeList) && !type.IsSubclassOf(typeof(XmlNodeList)))
            {
                throw new ArgumentException(SR.Cryptography_Xml_TransformIncorrectInputType, nameof(type));
            }

            return (XmlNodeList)this.GetOutput();
        }
    }
}
