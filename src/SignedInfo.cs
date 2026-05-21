// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections;
using System.Globalization;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    public class SignedInfo : ICollection
    {
        private String _id;
        private String _canonicalizationMethod;
        private String _signatureMethod;
        private String _signatureLength;
        private readonly ArrayList _references;
        private XmlElement _cachedXml = null;
        private SignedXml _signedXml = null;
        private Transform _canonicalizationMethodTransform = null;

        internal SignedXml SignedXml
        {
            get { return this._signedXml; }
            set { this._signedXml = value; }
        }

        public SignedInfo()
        {
            this._references = new ArrayList();
        }

        public IEnumerator GetEnumerator()
        {
            throw new NotSupportedException();
        }

        public void CopyTo(Array array, Int32 index)
        {
            throw new NotSupportedException();
        }

        public Int32 Count
        {
            get { throw new NotSupportedException(); }
        }

        public Boolean IsReadOnly
        {
            get { throw new NotSupportedException(); }
        }

        public Boolean IsSynchronized
        {
            get { throw new NotSupportedException(); }
        }

        public Object SyncRoot
        {
            get { throw new NotSupportedException(); }
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

        public String CanonicalizationMethod
        {
            get
            {
                // Default the canonicalization method to C14N
                if (this._canonicalizationMethod == null)
                {
                    return SignedXml.XmlDsigC14NTransformUrl;
                }

                return this._canonicalizationMethod;
            }
            set
            {
                this._canonicalizationMethod = value;
                this._cachedXml = null;
            }
        }

        public Transform CanonicalizationMethodObject
        {
            get
            {
                if (this._canonicalizationMethodTransform == null)
                {
                    this._canonicalizationMethodTransform = CryptoHelpers.CreateFromName<Transform>(this.CanonicalizationMethod);
                    if (this._canonicalizationMethodTransform == null)
                    {
                        throw new System.Security.Cryptography.CryptographicException(String.Format(CultureInfo.CurrentCulture, SR.Cryptography_Xml_CreateTransformFailed, this.CanonicalizationMethod));
                    }

                    this._canonicalizationMethodTransform.SignedXml = this.SignedXml;
                    this._canonicalizationMethodTransform.Reference = null;
                }
                return this._canonicalizationMethodTransform;
            }
        }

        public String SignatureMethod
        {
            get { return this._signatureMethod; }
            set
            {
                this._signatureMethod = value;
                this._cachedXml = null;
            }
        }

        public String SignatureLength
        {
            get { return this._signatureLength; }
            set
            {
                this._signatureLength = value;
                this._cachedXml = null;
            }
        }

        public ArrayList References
        {
            get { return this._references; }
        }

        internal Boolean CacheValid
        {
            get
            {
                if (this._cachedXml == null)
                {
                    return false;
                }
                // now check all the references
                foreach (Reference reference in this.References)
                {
                    if (!reference.CacheValid)
                    {
                        return false;
                    }
                }
                return true;
            }
        }

        //
        // public methods
        //

        public XmlElement GetXml()
        {
            if (this.CacheValid)
            {
                return this._cachedXml;
            }

            XmlDocument document = new XmlDocument();
            document.PreserveWhitespace = true;
            return this.GetXml(document);
        }

        internal XmlElement GetXml(XmlDocument document)
        {
            // Create the root element
            XmlElement signedInfoElement = document.CreateElement(SignedXml.XmlDsigNamespacePrefix, "SignedInfo", SignedXml.XmlDsigNamespaceUrl);
            if (!String.IsNullOrEmpty(this._id))
            {
                signedInfoElement.SetAttribute("Id", this._id);
            }

            // Add the canonicalization method, defaults to SignedXml.XmlDsigNamespaceUrl
            XmlElement canonicalizationMethodElement = this.CanonicalizationMethodObject.GetXml(document, "CanonicalizationMethod");
            signedInfoElement.AppendChild(canonicalizationMethodElement);

            // Add the signature method
            if (String.IsNullOrEmpty(this._signatureMethod))
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_SignatureMethodRequired);
            }

            XmlElement signatureMethodElement = document.CreateElement(SignedXml.XmlDsigNamespacePrefix, "SignatureMethod", SignedXml.XmlDsigNamespaceUrl);
            signatureMethodElement.SetAttribute("Algorithm", this._signatureMethod);
            // Add HMACOutputLength tag if we have one
            if (this._signatureLength != null)
            {
                //XmlElement hmacLengthElement = document.CreateElement(null, "HMACOutputLength", SignedXml.XmlDsigNamespaceUrl);
                XmlElement hmacLengthElement = document.CreateElement(SignedXml.XmlDsigNamespacePrefix, "HMACOutputLength", SignedXml.XmlDsigNamespaceUrl);
                XmlText outputLength = document.CreateTextNode(this._signatureLength);
                hmacLengthElement.AppendChild(outputLength);
                signatureMethodElement.AppendChild(hmacLengthElement);
            }

            signedInfoElement.AppendChild(signatureMethodElement);

            // Add the references
            if (this._references.Count == 0)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_ReferenceElementRequired);
            }

            for (Int32 i = 0; i < this._references.Count; ++i)
            {
                Reference reference = (Reference)this._references[i];
                signedInfoElement.AppendChild(reference.GetXml(document));
            }

            return signedInfoElement;
        }

        public void LoadXml(XmlElement value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            // SignedInfo
            XmlElement signedInfoElement = value;
            if (!signedInfoElement.LocalName.Equals("SignedInfo"))
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidElement, "SignedInfo");
            }

            XmlNamespaceManager nsm = new XmlNamespaceManager(value.OwnerDocument.NameTable);
            nsm.AddNamespace(SignedXml.XmlDsigNamespacePrefix, SignedXml.XmlDsigNamespaceUrl);
            Int32 expectedChildNodes = 0;

            // Id attribute -- optional
            this._id = Utils.GetAttribute(signedInfoElement, "Id", SignedXml.XmlDsigNamespaceUrl);
            if (!Utils.VerifyAttributes(signedInfoElement, "Id"))
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidElement, "SignedInfo");
            }

            // CanonicalizationMethod -- must be present
            XmlNodeList canonicalizationMethodNodes = signedInfoElement.SelectNodes(SignedXml.XmlDsigNamespacePrefix + ":CanonicalizationMethod", nsm);
            if (canonicalizationMethodNodes == null || canonicalizationMethodNodes.Count == 0 || canonicalizationMethodNodes.Count > 1)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidElement, "SignedInfo/CanonicalizationMethod");
            }

            XmlElement canonicalizationMethodElement = canonicalizationMethodNodes.Item(0) as XmlElement;
            expectedChildNodes += canonicalizationMethodNodes.Count;
            this._canonicalizationMethod = Utils.GetAttribute(canonicalizationMethodElement, "Algorithm", SignedXml.XmlDsigNamespaceUrl);
            if (this._canonicalizationMethod == null || !Utils.VerifyAttributes(canonicalizationMethodElement, "Algorithm"))
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidElement, "SignedInfo/CanonicalizationMethod");
            }

            this._canonicalizationMethodTransform = null;
            if (canonicalizationMethodElement.ChildNodes.Count > 0)
            {
                this.CanonicalizationMethodObject.LoadInnerXml(canonicalizationMethodElement.ChildNodes);
            }

            // SignatureMethod -- must be present
            XmlNodeList signatureMethodNodes = signedInfoElement.SelectNodes(SignedXml.XmlDsigNamespacePrefix + ":SignatureMethod", nsm);
            if (signatureMethodNodes == null || signatureMethodNodes.Count == 0 || signatureMethodNodes.Count > 1)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidElement, "SignedInfo/SignatureMethod");
            }

            XmlElement signatureMethodElement = signatureMethodNodes.Item(0) as XmlElement;
            expectedChildNodes += signatureMethodNodes.Count;
            this._signatureMethod = Utils.GetAttribute(signatureMethodElement, "Algorithm", SignedXml.XmlDsigNamespaceUrl);
            if (this._signatureMethod == null || !Utils.VerifyAttributes(signatureMethodElement, "Algorithm"))
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidElement, "SignedInfo/SignatureMethod");
            }

            // Now get the output length if we are using a MAC algorithm
            XmlElement signatureLengthElement = signatureMethodElement.SelectSingleNode(SignedXml.XmlDsigNamespacePrefix + ":HMACOutputLength", nsm) as XmlElement;
            if (signatureLengthElement != null)
            {
                this._signatureLength = signatureLengthElement.InnerXml;
            }

            // flush out any reference that was there
            this._references.Clear();

            // Reference - 0 or more
            XmlNodeList referenceNodes = signedInfoElement.SelectNodes(SignedXml.XmlDsigNamespacePrefix + ":Reference", nsm);
            if (referenceNodes != null)
            {
                if (referenceNodes.Count > Utils.MaxReferencesPerSignedInfo)
                {
                    throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidElement, "SignedInfo/Reference");
                }
                foreach (XmlNode node in referenceNodes)
                {
                    XmlElement referenceElement = node as XmlElement;
                    Reference reference = new Reference();
                    this.AddReference(reference);
                    reference.LoadXml(referenceElement);
                }
                expectedChildNodes += referenceNodes.Count;
                // Verify that there aren't any extra nodes that aren't allowed
                if (signedInfoElement.SelectNodes("*").Count != expectedChildNodes)
                {
                    throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidElement, "SignedInfo");
                }
            }

            // Save away the cached value
            this._cachedXml = signedInfoElement;
        }

        public void AddReference(Reference reference)
        {
            if (reference == null)
            {
                throw new ArgumentNullException(nameof(reference));
            }

            reference.SignedXml = this.SignedXml;
            this._references.Add(reference);
        }
    }
}
