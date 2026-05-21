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
    // This class represents an ordered chain of transforms

    public class TransformChain
    {
        private readonly ArrayList _transforms;

        public TransformChain()
        {
            this._transforms = new ArrayList();
        }

        public void Add(Transform transform)
        {
            if (transform != null)
            {
                this._transforms.Add(transform);
            }
        }

        public IEnumerator GetEnumerator()
        {
            return this._transforms.GetEnumerator();
        }

        public Int32 Count
        {
            get { return this._transforms.Count; }
        }

        public Transform this[Int32 index]
        {
            get
            {
                if (index >= this._transforms.Count)
                {
                    throw new ArgumentException(SR.ArgumentOutOfRange_Index, nameof(index));
                }

                return (Transform)this._transforms[index];
            }
        }

        // The goal behind this method is to pump the input stream through the transforms and get back something that
        // can be hashed
        internal Stream TransformToOctetStream(Object inputObject, Type inputType, XmlResolver resolver, String baseUri)
        {
            Object currentInput = inputObject;
            foreach (Transform transform in this._transforms)
            {
                if (currentInput == null || transform.AcceptsType(currentInput.GetType()))
                {
                    //in this case, no translation necessary, pump it through
                    transform.Resolver = resolver;
                    transform.BaseURI = baseUri;
                    transform.LoadInput(currentInput);
                    currentInput = transform.GetOutput();
                }
                else
                {
                    // We need translation
                    // For now, we just know about Stream->{XmlNodeList,XmlDocument} and {XmlNodeList,XmlDocument}->Stream
                    if (currentInput is Stream)
                    {
                        if (transform.AcceptsType(typeof(XmlDocument)))
                        {
                            Stream currentInputStream = currentInput as Stream;
                            XmlDocument doc = new XmlDocument();
                            doc.PreserveWhitespace = true;
                            XmlReader valReader = Utils.PreProcessStreamInput(currentInputStream, resolver, baseUri);
                            doc.Load(valReader);
                            transform.LoadInput(doc);
                            currentInputStream.Close();
                            currentInput = transform.GetOutput();
                            continue;
                        }
                        else
                        {
                            throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_TransformIncorrectInputType);
                        }
                    }
                    if (currentInput is XmlNodeList)
                    {
                        if (transform.AcceptsType(typeof(Stream)))
                        {
                            CanonicalXml c14n = new CanonicalXml((XmlNodeList)currentInput, resolver, false);
                            MemoryStream ms = new MemoryStream(c14n.GetBytes());
                            transform.LoadInput(ms);
                            currentInput = transform.GetOutput();
                            ms.Close();
                            continue;
                        }
                        else
                        {
                            throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_TransformIncorrectInputType);
                        }
                    }
                    if (currentInput is XmlDocument)
                    {
                        if (transform.AcceptsType(typeof(Stream)))
                        {
                            CanonicalXml c14n = new CanonicalXml((XmlDocument)currentInput, resolver);
                            MemoryStream ms = new MemoryStream(c14n.GetBytes());
                            transform.LoadInput(ms);
                            currentInput = transform.GetOutput();
                            ms.Close();
                            continue;
                        }
                        else
                        {
                            throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_TransformIncorrectInputType);
                        }
                    }
                    throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_TransformIncorrectInputType);
                }
            }

            // Final processing, either we already have a stream or have to canonicalize
            if (currentInput is Stream)
            {
                return currentInput as Stream;
            }
            if (currentInput is XmlNodeList)
            {
                CanonicalXml c14n = new CanonicalXml((XmlNodeList)currentInput, resolver, false);
                MemoryStream ms = new MemoryStream(c14n.GetBytes());
                return ms;
            }
            if (currentInput is XmlDocument)
            {
                CanonicalXml c14n = new CanonicalXml((XmlDocument)currentInput, resolver);
                MemoryStream ms = new MemoryStream(c14n.GetBytes());
                return ms;
            }
            throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_TransformIncorrectInputType);
        }

        internal Stream TransformToOctetStream(Stream input, XmlResolver resolver, String baseUri)
        {
            return this.TransformToOctetStream(input, typeof(Stream), resolver, baseUri);
        }

        internal Stream TransformToOctetStream(XmlDocument document, XmlResolver resolver, String baseUri)
        {
            return this.TransformToOctetStream(document, typeof(XmlDocument), resolver, baseUri);
        }

        internal XmlElement GetXml(XmlDocument document, String ns)
        {
            XmlElement transformsElement = document.CreateElement("Transforms", ns);
            foreach (Transform transform in this._transforms)
            {
                if (transform != null)
                {
                    // Construct the individual transform element
                    XmlElement transformElement = transform.GetXml(document);
                    if (transformElement != null)
                    {
                        transformsElement.AppendChild(transformElement);
                    }
                }
            }
            return transformsElement;
        }

        internal void LoadXml(XmlElement value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            XmlNamespaceManager nsm = new XmlNamespaceManager(value.OwnerDocument.NameTable);
            nsm.AddNamespace(SignedXml.XmlDsigNamespacePrefix, SignedXml.XmlDsigNamespaceUrl);

            XmlNodeList transformNodes = value.SelectNodes(SignedXml.XmlDsigNamespacePrefix + ":Transform", nsm);
            if (transformNodes.Count == 0)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidElement, "Transforms");
            }

            this._transforms.Clear();
            for (Int32 i = 0; i < transformNodes.Count; ++i)
            {
                XmlElement transformElement = (XmlElement)transformNodes.Item(i);
                String algorithm = Utils.GetAttribute(transformElement, "Algorithm", SignedXml.XmlDsigNamespaceUrl);
                Transform transform = CryptoHelpers.CreateFromName<Transform>(algorithm);
                if (transform == null)
                {
                    throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_UnknownTransform);
                }
                // let the transform read the children of the transformElement for data
                transform.LoadInnerXml(transformElement.ChildNodes);
                this._transforms.Add(transform);
            }
        }
    }
}
