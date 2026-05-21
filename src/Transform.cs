// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

// This file contains the classes necessary to represent the Transform processing model used in
// XMLDSIG. The basic idea is as follows. A Reference object contains within it a TransformChain, which
// is an ordered set of XMLDSIG transforms (represented by <Transform>...</Transform> clauses in the XML).
// A transform in XMLDSIG operates on an input of either an octet stream or a node set and produces
// either an octet stream or a node set. Conversion between the two types is performed by parsing (octet stream->
// node set) or C14N (node set->octet stream). We generalize this slightly to allow a transform to define an array of
// input and output types (because I believe in the future there will be perf gains by being smarter about what goes in & comes out)
// Each XMLDSIG transform is represented by a subclass of the abstract Transform class. We need to use CryptoConfig to
// associate Transform classes with URLs for transform extensibility, but that's a future concern for this code.
// Once the Transform chain is constructed, call TransformToOctetStream to convert some sort of input type to an octet
// stream. (We only bother implementing that much now since every use of transform chains in XmlDsig ultimately yields something to hash).

using System;
using System.Collections;
using System.IO;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    public abstract class Transform
    {
        private String _algorithm;
        private String _baseUri = null;
        internal XmlResolver _xmlResolver = null;
        private Boolean _bResolverSet = false;
        private SignedXml _signedXml = null;
        private Reference _reference = null;
        private Hashtable _propagatedNamespaces = null;
        private XmlElement _context = null;

        internal String BaseURI
        {
            get { return this._baseUri; }
            set { this._baseUri = value; }
        }

        internal SignedXml SignedXml
        {
            get { return this._signedXml; }
            set { this._signedXml = value; }
        }

        internal Reference Reference
        {
            get { return this._reference; }
            set { this._reference = value; }
        }

        //
        // protected constructors
        //

        protected Transform() { }

        //
        // public properties
        //

        public String Algorithm
        {
            get { return this._algorithm; }
            set { this._algorithm = value; }
        }

        public XmlResolver Resolver
        {
            internal get
            {
                return this._xmlResolver;
            }
            // This property only has a public setter. The rationale for this is that we don't have a good value
            // to return when it has not been explicitely set, as we are using XmlSecureResolver by default
            set
            {
                this._xmlResolver = value;
                this._bResolverSet = true;
            }
        }

        internal Boolean ResolverSet
        {
            get { return this._bResolverSet; }
        }

        public abstract Type[] InputTypes
        {
            get;
        }

        public abstract Type[] OutputTypes
        {
            get;
        }

        internal Boolean AcceptsType(Type inputType)
        {
            if (this.InputTypes != null)
            {
                for (Int32 i = 0; i < this.InputTypes.Length; i++)
                {
                    if (inputType == this.InputTypes[i] || inputType.IsSubclassOf(this.InputTypes[i]))
                    {
                        return true;
                    }
                }
            }
            return false;
        }

        //
        // public methods
        //

        public XmlElement GetXml()
        {
            XmlDocument document = new XmlDocument();
            document.PreserveWhitespace = true;
            return this.GetXml(document);
        }

        internal XmlElement GetXml(XmlDocument document)
        {
            return this.GetXml(document, "Transform");
        }

        internal XmlElement GetXml(XmlDocument document, String name)
        {
            XmlElement transformElement = document.CreateElement(SignedXml.XmlDsigNamespacePrefix, name, SignedXml.XmlDsigNamespaceUrl);
            if (!String.IsNullOrEmpty(this.Algorithm))
            {
                transformElement.SetAttribute("Algorithm", this.Algorithm);
            }

            XmlNodeList children = this.GetInnerXml();
            if (children != null)
            {
                foreach (XmlNode node in children)
                {
                    transformElement.AppendChild(document.ImportNode(node, true));
                }
            }
            return transformElement;
        }

        public abstract void LoadInnerXml(XmlNodeList nodeList);

        protected abstract XmlNodeList GetInnerXml();

        public abstract void LoadInput(Object obj);

        public abstract Object GetOutput();

        public abstract Object GetOutput(Type type);

        public virtual void GetDigestedOutput(IHash hash)
        {
            // Default the buffer size to 4K.
            Byte[] buffer = new Byte[4096];
            Int32 bytesRead;
            Stream inputStream = (Stream)this.GetOutput(typeof(Stream));
            hash.Reset();
            while ((bytesRead = inputStream.Read(buffer, 0, buffer.Length)) > 0)
            {
                hash.BlockUpdate(buffer, 0, bytesRead);
            }
        }

        public XmlElement Context
        {
            get
            {
                if (this._context != null)
                {
                    return this._context;
                }

                Reference reference = this.Reference;
                SignedXml signedXml = (reference == null ? this.SignedXml : reference.SignedXml);
                if (signedXml == null)
                {
                    return null;
                }

                return signedXml._context;
            }
            set
            {
                this._context = value;
            }
        }

        public Hashtable PropagatedNamespaces
        {
            get
            {
                if (this._propagatedNamespaces != null)
                {
                    return this._propagatedNamespaces;
                }

                Reference reference = this.Reference;
                SignedXml signedXml = (reference == null ? this.SignedXml : reference.SignedXml);

                // If the reference is not a Uri reference with a DataObject target, return an empty hashtable.
                if (reference != null &&
                    ((reference.ReferenceTargetType != ReferenceTargetType.UriReference) ||
                     (String.IsNullOrEmpty(reference.Uri) || reference.Uri[0] != '#')))
                {
                    this._propagatedNamespaces = new Hashtable(0);
                    return this._propagatedNamespaces;
                }

                CanonicalXmlNodeList namespaces = null;
                if (reference != null)
                {
                    namespaces = reference._namespaces;
                }
                else if (signedXml?._context != null)
                {
                    namespaces = Utils.GetPropagatedAttributes(signedXml._context);
                }

                // if no namespaces have been propagated, return an empty hashtable.
                if (namespaces == null)
                {
                    this._propagatedNamespaces = new Hashtable(0);
                    return this._propagatedNamespaces;
                }

                this._propagatedNamespaces = new Hashtable(namespaces.Count);
                foreach (XmlNode attrib in namespaces)
                {
                    String key = ((attrib.Prefix.Length > 0) ? attrib.Prefix + ":" + attrib.LocalName : attrib.LocalName);
                    if (!this._propagatedNamespaces.Contains(key))
                    {
                        this._propagatedNamespaces.Add(key, attrib.Value);
                    }
                }
                return this._propagatedNamespaces;
            }
        }
    }
}
