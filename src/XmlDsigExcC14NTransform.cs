// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.IO;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    public class XmlDsigExcC14NTransform : Transform
    {
        private readonly Type[] _inputTypes = { typeof(Stream), typeof(XmlDocument), typeof(XmlNodeList) };
        private readonly Type[] _outputTypes = { typeof(Stream) };
        private readonly Boolean _includeComments = false;
        private String _inclusiveNamespacesPrefixList;
        private ExcCanonicalXml _excCanonicalXml;

        public XmlDsigExcC14NTransform() : this(false, null) { }

        public XmlDsigExcC14NTransform(Boolean includeComments) : this(includeComments, null) { }

        public XmlDsigExcC14NTransform(String inclusiveNamespacesPrefixList) : this(false, inclusiveNamespacesPrefixList) { }

        public XmlDsigExcC14NTransform(Boolean includeComments, String inclusiveNamespacesPrefixList)
        {
            this._includeComments = includeComments;
            this._inclusiveNamespacesPrefixList = inclusiveNamespacesPrefixList;
            this.Algorithm = (includeComments ? SignedXml.XmlDsigExcC14NWithCommentsTransformUrl : SignedXml.XmlDsigExcC14NTransformUrl);
        }

        public String InclusiveNamespacesPrefixList
        {
            get { return this._inclusiveNamespacesPrefixList; }
            set { this._inclusiveNamespacesPrefixList = value; }
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
            if (nodeList != null)
            {
                foreach (XmlNode n in nodeList)
                {
                    XmlElement e = n as XmlElement;
                    if (e != null)
                    {
                        if (e.LocalName.Equals("InclusiveNamespaces")
                        && e.NamespaceURI.Equals(SignedXml.XmlDsigExcC14NTransformUrl) &&
                        Utils.HasAttribute(e, "PrefixList", SignedXml.XmlDsigNamespaceUrl))
                        {
                            if (!Utils.VerifyAttributes(e, "PrefixList"))
                            {
                                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_UnknownTransform);
                            }
                            this.InclusiveNamespacesPrefixList = Utils.GetAttribute(e, "PrefixList", SignedXml.XmlDsigNamespaceUrl);
                            return;
                        }
                        else
                        {
                            throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_UnknownTransform);
                        }
                    }
                }
            }
        }

        public override void LoadInput(Object obj)
        {
            XmlResolver resolver = (this.ResolverSet ? this._xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), this.BaseURI));
            if (obj is Stream)
            {
                this._excCanonicalXml = new ExcCanonicalXml((Stream)obj, this._includeComments, this._inclusiveNamespacesPrefixList, resolver, this.BaseURI);
            }
            else if (obj is XmlDocument)
            {
                this._excCanonicalXml = new ExcCanonicalXml((XmlDocument)obj, this._includeComments, this._inclusiveNamespacesPrefixList, resolver);
            }
            else if (obj is XmlNodeList)
            {
                this._excCanonicalXml = new ExcCanonicalXml((XmlNodeList)obj, this._includeComments, this._inclusiveNamespacesPrefixList, resolver);
            }
            else
            {
                throw new ArgumentException(SR.Cryptography_Xml_IncorrectObjectType, nameof(obj));
            }
        }

        protected override XmlNodeList GetInnerXml()
        {
            if (this.InclusiveNamespacesPrefixList == null)
            {
                return null;
            }

            XmlDocument document = new XmlDocument();
            XmlElement element = document.CreateElement(SignedXml.DefaultXmlDsigNamespacePrefix, "Transform", SignedXml.XmlDsigNamespaceUrl);
            if (!String.IsNullOrEmpty(this.Algorithm))
            {
                element.SetAttribute("Algorithm", this.Algorithm);
            }

            XmlElement prefixListElement = document.CreateElement(SignedXml.XmlDsigExcC14NTransformPrefix, "InclusiveNamespaces", SignedXml.XmlDsigExcC14NTransformUrl);
            prefixListElement.SetAttribute("PrefixList", this.InclusiveNamespacesPrefixList);
            element.AppendChild(prefixListElement);
            return element.ChildNodes;
        }

        public override Object GetOutput()
        {
            return new MemoryStream(this._excCanonicalXml.GetBytes());
        }

        public override Object GetOutput(Type type)
        {
            if (type != typeof(Stream) && !type.IsSubclassOf(typeof(Stream)))
            {
                throw new ArgumentException(SR.Cryptography_Xml_TransformIncorrectInputType, nameof(type));
            }

            return new MemoryStream(this._excCanonicalXml.GetBytes());
        }

        public override void GetDigestedOutput(IHash signer)
        {
            this._excCanonicalXml.GetDigestedBytes(signer);
        }
    }
}
