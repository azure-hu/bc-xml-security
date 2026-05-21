// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Globalization;
using System.IO;
using System.Net;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    public class Reference
    {
        internal static readonly String DefaultDigestMethod = EncryptedXml.XmlEncSHA256Url;

        private String _id;
        private String _uri;
        private String _type;
        private TransformChain _transformChain;
        private String _digestMethod;
        private Byte[] _digestValue;
        private IHash _hashAlgorithm;
        private readonly Object _refTarget;
        private readonly ReferenceTargetType _refTargetType;
        private XmlElement _cachedXml;
        private SignedXml _signedXml = null;
        internal CanonicalXmlNodeList _namespaces = null;
        private Byte[] _hashval = null;

        //
        // public constructors
        //

        public Reference()
        {
            this._transformChain = new TransformChain();
            this._refTarget = null;
            this._refTargetType = ReferenceTargetType.UriReference;
            this._cachedXml = null;
            this._digestMethod = DefaultDigestMethod;
        }

        public Reference(Stream stream)
        {
            this._transformChain = new TransformChain();
            this._refTarget = stream;
            this._refTargetType = ReferenceTargetType.Stream;
            this._cachedXml = null;
            this._digestMethod = DefaultDigestMethod;
        }

        public Reference(String uri)
        {
            this._transformChain = new TransformChain();
            this._refTarget = uri;
            this._uri = uri;
            this._refTargetType = ReferenceTargetType.UriReference;
            this._cachedXml = null;
            this._digestMethod = DefaultDigestMethod;
        }

        internal Reference(XmlElement element)
        {
            this._transformChain = new TransformChain();
            this._refTarget = element;
            this._refTargetType = ReferenceTargetType.XmlElement;
            this._cachedXml = null;
            this._digestMethod = DefaultDigestMethod;
        }

        //
        // public properties
        //

        public String Id
        {
            get { return this._id; }
            set { this._id = value; }
        }

        public String Uri
        {
            get { return this._uri; }
            set
            {
                this._uri = value;
                this._cachedXml = null;
            }
        }

        public String Type
        {
            get { return this._type; }
            set
            {
                this._type = value;
                this._cachedXml = null;
            }
        }

        public String DigestMethod
        {
            get { return this._digestMethod; }
            set
            {
                this._digestMethod = value;
                this._cachedXml = null;
            }
        }

        public Byte[] DigestValue
        {
            get { return this._digestValue; }
            set
            {
                this._digestValue = value;
                this._cachedXml = null;
            }
        }

        public TransformChain TransformChain
        {
            get
            {
                if (this._transformChain == null)
                {
                    this._transformChain = new TransformChain();
                }

                return this._transformChain;
            }
            set
            {
                this._transformChain = value;
                this._cachedXml = null;
            }
        }

        internal Boolean CacheValid
        {
            get
            {
                return (this._cachedXml != null);
            }
        }

        internal SignedXml SignedXml
        {
            get { return this._signedXml; }
            set { this._signedXml = value; }
        }

        internal ReferenceTargetType ReferenceTargetType
        {
            get
            {
                return this._refTargetType;
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
            // Create the Reference
            XmlElement referenceElement = document.CreateElement(SignedXml.XmlDsigNamespacePrefix, "Reference", SignedXml.XmlDsigNamespaceUrl);

            if (!String.IsNullOrEmpty(this._id))
            {
                referenceElement.SetAttribute("Id", this._id);
            }

            if (this._uri != null)
            {
                referenceElement.SetAttribute("URI", this._uri);
            }

            if (!String.IsNullOrEmpty(this._type))
            {
                referenceElement.SetAttribute("Type", this._type);
            }

            // Add the transforms to the Reference
            if (this.TransformChain.Count != 0)
            {
                referenceElement.AppendChild(this.TransformChain.GetXml(document, SignedXml.XmlDsigNamespaceUrl));
            }

            // Add the DigestMethod
            if (String.IsNullOrEmpty(this._digestMethod))
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_DigestMethodRequired);
            }

            XmlElement digestMethodElement = document.CreateElement(SignedXml.XmlDsigNamespacePrefix, "DigestMethod", SignedXml.XmlDsigNamespaceUrl);
            digestMethodElement.SetAttribute("Algorithm", this._digestMethod);
            referenceElement.AppendChild(digestMethodElement);

            if (this.DigestValue == null)
            {
                if (this._hashval == null)
                {
                    throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_DigestValueRequired);
                }

                this.DigestValue = this._hashval;
            }

            XmlElement digestValueElement = document.CreateElement(SignedXml.XmlDsigNamespacePrefix, "DigestValue", SignedXml.XmlDsigNamespaceUrl);
            digestValueElement.AppendChild(document.CreateTextNode(Convert.ToBase64String(this._digestValue)));
            referenceElement.AppendChild(digestValueElement);

            return referenceElement;
        }

        public void LoadXml(XmlElement value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            this._id = Utils.GetAttribute(value, "Id", SignedXml.XmlDsigNamespaceUrl);
            this._uri = Utils.GetAttribute(value, "URI", SignedXml.XmlDsigNamespaceUrl);
            this._type = Utils.GetAttribute(value, "Type", SignedXml.XmlDsigNamespaceUrl);
            if (!Utils.VerifyAttributes(value, new String[] { "Id", "URI", "Type" }))
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidElement, "Reference");
            }

            XmlNamespaceManager nsm = new XmlNamespaceManager(value.OwnerDocument.NameTable);
            nsm.AddNamespace(SignedXml.XmlDsigNamespacePrefix, SignedXml.XmlDsigNamespaceUrl);

            // Transforms
            Boolean hasTransforms = false;
            this.TransformChain = new TransformChain();
            XmlNodeList transformsNodes = value.SelectNodes(SignedXml.XmlDsigNamespacePrefix + ":Transforms", nsm);
            if (transformsNodes != null && transformsNodes.Count != 0)
            {
                if (transformsNodes.Count > 1)
                {
                    throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidElement, "Reference/Transforms");
                }
                hasTransforms = true;
                XmlElement transformsElement = transformsNodes[0] as XmlElement;
                if (!Utils.VerifyAttributes(transformsElement, (String[])null))
                {
                    throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidElement, "Reference/Transforms");
                }
                XmlNodeList transformNodes = transformsElement.SelectNodes(SignedXml.XmlDsigNamespacePrefix + ":Transform", nsm);
                if (transformNodes != null)
                {
                    if (transformNodes.Count != transformsElement.SelectNodes("*").Count)
                    {
                        throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidElement, "Reference/Transforms");
                    }
                    if (transformNodes.Count > Utils.MaxTransformsPerReference)
                    {
                        throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidElement, "Reference/Transforms");
                    }
                    foreach (XmlNode transformNode in transformNodes)
                    {
                        XmlElement transformElement = transformNode as XmlElement;
                        String algorithm = Utils.GetAttribute(transformElement, "Algorithm", SignedXml.XmlDsigNamespaceUrl);
                        if (algorithm == null || !Utils.VerifyAttributes(transformElement, "Algorithm"))
                        {
                            throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_UnknownTransform);
                        }
                        Transform transform = CryptoHelpers.CreateFromName<Transform>(algorithm);
                        if (transform == null)
                        {
                            throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_UnknownTransform);
                        }
                        this.AddTransform(transform);
                        // let the transform read the children of the transformElement for data
                        transform.LoadInnerXml(transformElement.ChildNodes);
                        // Hack! this is done to get around the lack of here() function support in XPath
                        if (transform is XmlDsigEnvelopedSignatureTransform)
                        {
                            // Walk back to the Signature tag. Find the nearest signature ancestor
                            // Signature-->SignedInfo-->Reference-->Transforms-->Transform
                            XmlNode signatureTag = transformElement.SelectSingleNode("ancestor::" + SignedXml.XmlDsigNamespacePrefix + ":Signature[1]", nsm);
                            XmlNodeList signatureList = transformElement.SelectNodes("//" + SignedXml.XmlDsigNamespacePrefix + ":Signature", nsm);
                            if (signatureList != null)
                            {
                                Int32 position = 0;
                                foreach (XmlNode node in signatureList)
                                {
                                    position++;
                                    if (node == signatureTag)
                                    {
                                        ((XmlDsigEnvelopedSignatureTransform)transform).SignaturePosition = position;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // DigestMethod
            XmlNodeList digestMethodNodes = value.SelectNodes(SignedXml.XmlDsigNamespacePrefix + ":DigestMethod", nsm);
            if (digestMethodNodes == null || digestMethodNodes.Count == 0 || digestMethodNodes.Count > 1)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidElement, "Reference/DigestMethod");
            }

            XmlElement digestMethodElement = digestMethodNodes[0] as XmlElement;
            this._digestMethod = Utils.GetAttribute(digestMethodElement, "Algorithm", SignedXml.XmlDsigNamespaceUrl);
            if (this._digestMethod == null || !Utils.VerifyAttributes(digestMethodElement, "Algorithm"))
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidElement, "Reference/DigestMethod");
            }


            // DigestValue
            XmlNodeList digestValueNodes = value.SelectNodes(SignedXml.XmlDsigNamespacePrefix + ":DigestValue", nsm);
            if (digestValueNodes == null || digestValueNodes.Count == 0 || digestValueNodes.Count > 1)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidElement, "Reference/DigestValue");
            }

            XmlElement digestValueElement = digestValueNodes[0] as XmlElement;
            this._digestValue = Convert.FromBase64String(Utils.DiscardWhiteSpaces(digestValueElement.InnerText));
            if (!Utils.VerifyAttributes(digestValueElement, (String[])null))
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidElement, "Reference/DigestValue");
            }
            // Verify that there aren't any extra nodes that aren't allowed
            Int32 expectedChildNodeCount = hasTransforms ? 3 : 2;
            if (value.SelectNodes("*").Count != expectedChildNodeCount)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidElement, "Reference");
            }

            // cache the Xml
            this._cachedXml = value;
        }

        public void AddTransform(Transform transform)
        {
            if (transform == null)
            {
                throw new ArgumentNullException(nameof(transform));
            }

            transform.Reference = this;
            this.TransformChain.Add(transform);
        }

        internal void UpdateHashValue(XmlDocument document, CanonicalXmlNodeList refList)
        {
            this.DigestValue = this.CalculateHashValue(document, refList);
        }

        // What we want to do is pump the input throug the TransformChain and then
        // hash the output of the chain document is the document context for resolving relative references
        internal Byte[] CalculateHashValue(XmlDocument document, CanonicalXmlNodeList refList)
        {
            // refList is a list of elements that might be targets of references
            // Now's the time to create our hashing algorithm
            IDigest digest = CryptoHelpers.CreateFromName<IDigest>(this._digestMethod);
            if (digest == null)
            {
                IMac mac = CryptoHelpers.CreateFromName<IMac>(this._digestMethod);
                if (mac == null)
                {
                    throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_CreateHashAlgorithmFailed);
                }

                // For compatibility to corefx' HMAC implementation
                Byte[] randomKey = Utils.GenerateRandomBlock(mac.GetMacSize());
                mac.Init(new KeyParameter(randomKey));

                this._hashAlgorithm = new MacHashWrapper(mac);
            }
            else
            {
                this._hashAlgorithm = new DigestHashWrapper(digest);
            }

            // Let's go get the target.
            String baseUri = (document == null ? System.Environment.CurrentDirectory + "\\" : document.BaseURI);
            Stream hashInputStream = null;
            WebResponse response = null;
            Stream inputStream = null;
            XmlResolver resolver = null;
            this._hashval = null;

            try
            {
                switch (this._refTargetType)
                {
                    case ReferenceTargetType.Stream:
                        // This is the easiest case. We already have a stream, so just pump it through the TransformChain
                        resolver = (this.SignedXml.ResolverSet ? this.SignedXml._xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), baseUri));
                        hashInputStream = this.TransformChain.TransformToOctetStream((Stream)this._refTarget, resolver, baseUri);
                        break;
                    case ReferenceTargetType.UriReference:
                        // Second-easiest case -- dereference the URI & pump through the TransformChain
                        // handle the special cases where the URI is null (meaning whole doc)
                        // or the URI is just a fragment (meaning a reference to an embedded Object)
                        if (this._uri == null)
                        {
                            // We need to create a DocumentNavigator out of the XmlElement
                            resolver = (this.SignedXml.ResolverSet ? this.SignedXml._xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), baseUri));
                            // In the case of a Uri-less reference, we will simply pass null to the transform chain.
                            // The first transform in the chain is expected to know how to retrieve the data to hash.
                            hashInputStream = this.TransformChain.TransformToOctetStream((Stream)null, resolver, baseUri);
                        }
                        else if (this._uri.Length == 0)
                        {
                            // This is the self-referential case. First, check that we have a document context.
                            // The Enveloped Signature does not discard comments as per spec; those will be omitted during the transform chain process
                            if (document == null)
                            {
                                throw new System.Security.Cryptography.CryptographicException(String.Format(CultureInfo.CurrentCulture, SR.Cryptography_Xml_SelfReferenceRequiresContext, this._uri));
                            }

                            // Normalize the containing document
                            resolver = (this.SignedXml.ResolverSet ? this.SignedXml._xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), baseUri));
                            XmlDocument docWithNoComments = Utils.DiscardComments(Utils.PreProcessDocumentInput(document, resolver, baseUri));
                            hashInputStream = this.TransformChain.TransformToOctetStream(docWithNoComments, resolver, baseUri);
                        }
                        else if (this._uri[0] == '#')
                        {
                            // If we get here, then we are constructing a Reference to an embedded DataObject
                            // referenced by an Id = attribute. Go find the relevant object
                            Boolean discardComments = true;
                            String idref = Utils.GetIdFromLocalUri(this._uri, out discardComments);
                            if (idref == "xpointer(/)")
                            {
                                // This is a self referencial case
                                if (document == null)
                                {
                                    throw new System.Security.Cryptography.CryptographicException(String.Format(CultureInfo.CurrentCulture, SR.Cryptography_Xml_SelfReferenceRequiresContext, this._uri));
                                }

                                // We should not discard comments here!!!
                                resolver = (this.SignedXml.ResolverSet ? this.SignedXml._xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), baseUri));
                                hashInputStream = this.TransformChain.TransformToOctetStream(Utils.PreProcessDocumentInput(document, resolver, baseUri), resolver, baseUri);
                                break;
                            }

                            XmlElement elem = this.SignedXml.GetIdElement(document, idref);
                            if (elem != null)
                            {
                                this._namespaces = Utils.GetPropagatedAttributes(elem.ParentNode as XmlElement);
                            }

                            if (elem == null)
                            {
                                // Go throw the referenced items passed in
                                if (refList != null)
                                {
                                    foreach (XmlNode node in refList)
                                    {
                                        XmlElement tempElem = node as XmlElement;
                                        if ((tempElem != null) && (Utils.HasAttribute(tempElem, "Id", SignedXml.XmlDsigNamespaceUrl))
                                            && (Utils.GetAttribute(tempElem, "Id", SignedXml.XmlDsigNamespaceUrl).Equals(idref)))
                                        {
                                            elem = tempElem;
                                            if (this._signedXml._context != null)
                                            {
                                                this._namespaces = Utils.GetPropagatedAttributes(this._signedXml._context);
                                            }

                                            break;
                                        }
                                    }
                                }
                            }

                            if (elem == null)
                            {
                                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidReference);
                            }

                            XmlDocument normDocument = Utils.PreProcessElementInput(elem, resolver, baseUri);
                            // Add the propagated attributes
                            Utils.AddNamespaces(normDocument.DocumentElement, this._namespaces);

                            resolver = (this.SignedXml.ResolverSet ? this.SignedXml._xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), baseUri));
                            if (discardComments)
                            {
                                // We should discard comments before going into the transform chain
                                XmlDocument docWithNoComments = Utils.DiscardComments(normDocument);
                                hashInputStream = this.TransformChain.TransformToOctetStream(docWithNoComments, resolver, baseUri);
                            }
                            else
                            {
                                // This is an XPointer reference, do not discard comments!!!
                                hashInputStream = this.TransformChain.TransformToOctetStream(normDocument, resolver, baseUri);
                            }
                        }
                        else
                        {
                            throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_UriNotResolved, this._uri);
                        }
                        break;
                    case ReferenceTargetType.XmlElement:
                        // We need to create a DocumentNavigator out of the XmlElement
                        resolver = (this.SignedXml.ResolverSet ? this.SignedXml._xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), baseUri));
                        hashInputStream = this.TransformChain.TransformToOctetStream(Utils.PreProcessElementInput((XmlElement)this._refTarget, resolver, baseUri), resolver, baseUri);
                        break;
                    default:
                        throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_UriNotResolved, this._uri);
                }

                // Compute the new hash value
                hashInputStream = SignedXmlDebugLog.LogReferenceData(this, hashInputStream);
                // Default the buffer size to 4K.
                Byte[] buffer = new Byte[4096];
                Int32 bytesRead;
                this._hashAlgorithm.Reset();
                while ((bytesRead = hashInputStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    this._hashAlgorithm.BlockUpdate(buffer, 0, bytesRead);
                }
                this._hashval = new Byte[this._hashAlgorithm.GetHashSize()];
                this._hashAlgorithm.DoFinal(this._hashval, 0);
            }
            finally
            {
                if (hashInputStream != null)
                {
                    hashInputStream.Close();
                }

                if (response != null)
                {
                    response.Close();
                }

                if (inputStream != null)
                {
                    inputStream.Close();
                }
            }

            return this._hashval;
        }
    }
}
