// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    public class SignedXml
    {
        protected Signature m_signature;
        private String m_strSigningKeyName;

        private AsymmetricKeyParameter _signingKey;
        private XmlDocument _containingDocument = null;
        private IEnumerator _keyInfoEnum = null;
        private IList<X509Certificate> _x509Collection = null;
        private IEnumerator _x509Enum = null;

        private Boolean[] _refProcessed = null;
        private Int32[] _refLevelCache = null;

        internal XmlResolver _xmlResolver = null;
        internal XmlElement _context = null;
        protected Boolean _bResolverSet = false;

        private Func<SignedXml, Boolean> _signatureFormatValidator = DefaultSignatureFormatValidator;
        private Collection<String> _safeCanonicalizationMethods;

        // Built in canonicalization algorithm URIs
        private static IList<String> s_knownCanonicalizationMethods = null;
        // Built in transform algorithm URIs (excluding canonicalization URIs)
        private static IList<String> s_defaultSafeTransformMethods = null;

        // additional HMAC Url identifiers
        private const String XmlDsigMoreHMACMD5Url       = XmlDsigMoreNamespaceUrl + "hmac-md5";
        public  const String XmlDsigHMACSHA1Url          = XmlDsigNamespaceUrl + "hmac-sha1";
        private const String XmlDsigMoreHMACSHA224Url    = XmlDsigMoreNamespaceUrl + "hmac-sha224";
        private const String XmlDsigMoreHMACSHA256Url    = XmlDsigMoreNamespaceUrl + "hmac-sha256";
        private const String XmlDsigMoreHMACSHA384Url    = XmlDsigMoreNamespaceUrl + "hmac-sha384";
        private const String XmlDsigMoreHMACSHA512Url    = XmlDsigMoreNamespaceUrl + "hmac-sha512";
        private const String XmlDsigMoreHMACRIPEMD160Url = XmlDsigMoreNamespaceUrl + "hmac-ripemd160";

        // defines the XML encryption processing rules
        private EncryptedXml _exml = null;

        //
        // public constant Url identifiers most frequently used within the XML Signature classes
        //

        public const String XmlDsigNamespaceUrl = "http://www.w3.org/2000/09/xmldsig#";
        public const String DefaultXmlDsigNamespacePrefix = "ds";
        public const String XmlDsig11NamespaceUrl =  "http://www.w3.org/2009/xmldsig11#";
        public const String DefaultXmlDsig11NamespacePrefix = "dsig11";
        public const String XmlDsigMinimalCanonicalizationUrl = XmlDsigNamespaceUrl + "minimal";
        public const String XmlDsigCanonicalizationUrl = XmlDsigC14NTransformUrl;
        public const String XmlDsigCanonicalizationWithCommentsUrl = XmlDsigC14NWithCommentsTransformUrl;

        public const String XmlDsigMoreNamespaceUrl = "http://www.w3.org/2001/04/xmldsig-more#";
        public const String XmlDsigMore200705NamespaceUrl = "http://www.w3.org/2007/05/xmldsig-more#";
        public const String XmlDsigMore202104NamespaceUrl = "http://www.w3.org/2021/04/xmldsig-more#";

        public const String XmlDsigSHA1Url       = XmlDsigNamespaceUrl + "sha1";
        public const String XmlDsigSHA256Url     = EncryptedXml.XmlEncSHA256Url;
        public const String XmlDsigSHA384Url     = SignedXml.XmlDsigMoreSHA384Url;
        public const String XmlDsigSHA512Url     = EncryptedXml.XmlEncSHA512Url;

        public const String XmlDsigMoreSHA224Url = XmlDsigMoreNamespaceUrl + "sha224";
        public const String XmlDsigMoreSHA384Url = XmlDsigMoreNamespaceUrl + "sha384";

        public const String XmlDsigMoreSHA3_224Url = XmlDsigMore200705NamespaceUrl + "sha3-224";
        public const String XmlDsigMoreSHA3_256Url = XmlDsigMore200705NamespaceUrl + "sha3-256";
        public const String XmlDsigMoreSHA3_384Url = XmlDsigMore200705NamespaceUrl + "sha3-384";
        public const String XmlDsigMoreSHA3_512Url = XmlDsigMore200705NamespaceUrl + "sha3-512";

        public const String XmlDsigDSAUrl         = XmlDsigNamespaceUrl + "dsa-sha1";
        public const String XmlDsig11DSASHA256Url = XmlDsigMore200705NamespaceUrl + "dsa-sha256";

        public const String XmlDsigMoreRSAMD5Url       = XmlDsigMoreNamespaceUrl + "rsa-md5";
        public const String XmlDsigRSASHA1Url      = XmlDsigNamespaceUrl + "rsa-sha1";
        public const String XmlDsigMoreRSASHA224Url    = XmlDsigMoreNamespaceUrl + "rsa-sha224";
        public const String XmlDsigMoreRSASHA256Url    = XmlDsigMoreNamespaceUrl + "rsa-sha256";
        public const String XmlDsigMoreRSASHA384Url    = XmlDsigMoreNamespaceUrl + "rsa-sha384";
        public const String XmlDsigMoreRSASHA512Url    = XmlDsigMoreNamespaceUrl + "rsa-sha512";
        public const String XmlDsigMoreRSARIPEMD160Url = XmlDsigMoreNamespaceUrl + "rsa-ripemd160";

        public const String XmlDsigMoreECDSASHA1Url      = XmlDsigMoreNamespaceUrl + "ecdsa-sha1";
        public const String XmlDsigMoreECDSASHA224Url    = XmlDsigMoreNamespaceUrl + "ecdsa-sha224";
        public const String XmlDsigMoreECDSASHA256Url    = XmlDsigMoreNamespaceUrl + "ecdsa-sha256";
        public const String XmlDsigMoreECDSASHA384Url    = XmlDsigMoreNamespaceUrl + "ecdsa-sha384";
        public const String XmlDsigMoreECDSASHA512Url    = XmlDsigMoreNamespaceUrl + "ecdsa-sha512";
        public const String XmlDsigMoreECDSASHA3_224Url  = XmlDsigMore202104NamespaceUrl + "ecdsa-sha3-224";
        public const String XmlDsigMoreECDSASHA3_256Url  = XmlDsigMore202104NamespaceUrl + "ecdsa-sha3-256";
        public const String XmlDsigMoreECDSASHA3_384Url  = XmlDsigMore202104NamespaceUrl + "ecdsa-sha3-384";
        public const String XmlDsigMoreECDSASHA3_512Url  = XmlDsigMore202104NamespaceUrl + "ecdsa-sha3-512";
        public const String XmlDsigMoreECDSARIPEMD160Url = XmlDsigMore200705NamespaceUrl + "ecdsa-ripemd160";

        public const String XmlDsigC14NTransformUrl = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
        public const String XmlDsigC14NWithCommentsTransformUrl = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
        public const String XmlDsigC14NTransformPrefix = "c14n";
        public const String XmlDsigExcC14NTransformUrl = "http://www.w3.org/2001/10/xml-exc-c14n#";
        public const String XmlDsigExcC14NTransformPrefix = "exc14n";
        public const String XmlDsigExcC14NWithCommentsTransformUrl = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";
        public const String XmlDsigBase64TransformUrl = XmlDsigNamespaceUrl + "base64";
        public const String XmlDsigXPathTransformUrl = "http://www.w3.org/TR/1999/REC-xpath-19991116";
        public const String XmlDsigXsltTransformUrl = "http://www.w3.org/TR/1999/REC-xslt-19991116";
        public const String XmlDsigEnvelopedSignatureTransformUrl = XmlDsigNamespaceUrl + "enveloped-signature";
        public const String XmlDecryptionTransformUrl = "http://www.w3.org/2002/07/decrypt#XML";
        public const String XmlLicenseTransformUrl = "urn:mpeg:mpeg21:2003:01-REL-R-NS:licenseTransform";

        // GOST 2001 algorithms
        public const String XmlDsigGost3410Url = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102001-gostr3411";
        public const String XmlDsigGost3410ObsoleteUrl = XmlDsigMoreNamespaceUrl + "gostr34102001-gostr3411";
        public const String XmlDsigGost3411Url = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr3411";
        public const String XmlDsigGost3411ObsoleteUrl = XmlDsigMoreNamespaceUrl + "gostr3411";
        public const String XmlDsigGost3411HmacUrl = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:hmac-gostr3411";

        // GOST 2012 algorithms
        public const String XmlDsigGost3410_2012_256_Url = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256";
        public const String XmlDsigGost3411_2012_256_Url = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256";
        public const String XmlDsigGost3411_2012_256_HmacUrl = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:hmac-gostr34112012-256";

        public const String XmlDsigGost3410_2012_512_Url = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-512";
        public const String XmlDsigGost3411_2012_512_Url = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-512";
        public const String XmlDsigGost3411_2012_512_HmacUrl = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:hmac-gostr34112012-512";


        //
        // Symmetric Block Encryption defined under XMLDSIG-MORE URI
        //

        public const String XmlDsigMoreCamellia128Url = XmlDsigMoreNamespaceUrl + "camellia128-cbc";
        public const String XmlDsigMoreCamellia192Url = XmlDsigMoreNamespaceUrl + "camellia192-cbc";
        public const String XmlDsigMoreCamellia256Url = XmlDsigMoreNamespaceUrl + "camellia256-cbc";

        //
        // Symmetric Key Wrap defined under XMLDSIG-MORE URI
        //

        public const String XmlDsigMoreCamellia128KeyWrapUrl = XmlDsigMoreNamespaceUrl + "kw-camellia128";
        public const String XmlDsigMoreCamellia192KeyWrapUrl = XmlDsigMoreNamespaceUrl + "kw-camellia192";
        public const String XmlDsigMoreCamellia256KeyWrapUrl = XmlDsigMoreNamespaceUrl + "kw-camellia256";

        //
        // public constructors
        //

        public SignedXml()
        {
            this.Initialize(null);
        }

        public SignedXml(XmlDocument document)
        {
            if (document == null)
            {
                throw new ArgumentNullException(nameof(document));
            }

            this.Initialize(document.DocumentElement);
        }

        public SignedXml(XmlElement elem)
        {
            if (elem == null)
            {
                throw new ArgumentNullException(nameof(elem));
            }

            this.Initialize(elem);
        }

        private void Initialize(XmlElement element)
        {
            this._containingDocument = (element == null ? null : element.OwnerDocument);
            this._context = element;
            this.m_signature = new Signature();
            this.m_signature.SignedXml = this;
            this.m_signature.SignedInfo = new SignedInfo();
            this._signingKey = null;

            this._safeCanonicalizationMethods = new Collection<String>(KnownCanonicalizationMethods);
        }

        //
        // public properties
        //

        /// <internalonly/>
        public String SigningKeyName
        {
            get { return this.m_strSigningKeyName; }
            set { this.m_strSigningKeyName = value; }
        }

        public XmlResolver Resolver
        {
            // This property only has a setter. The rationale for this is that we don't have a good value
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

        public Func<SignedXml, Boolean> SignatureFormatValidator
        {
            get { return this._signatureFormatValidator; }
            set { this._signatureFormatValidator = value; }
        }

        public Collection<String> SafeCanonicalizationMethods
        {
            get { return this._safeCanonicalizationMethods; }
        }

        public AsymmetricKeyParameter SigningKey
        {
            get { return this._signingKey; }
            set { this._signingKey = value; }
        }

        public EncryptedXml EncryptedXml
        {
            get
            {
                if (this._exml == null)
                {
                    this._exml = new EncryptedXml(this._containingDocument); // default processing rules
                }

                return this._exml;
            }
            set { this._exml = value; }
        }

        public Signature Signature
        {
            get { return this.m_signature; }
        }

        public SignedInfo SignedInfo
        {
            get { return this.m_signature.SignedInfo; }
        }

        public String SignatureMethod
        {
            get { return this.m_signature.SignedInfo.SignatureMethod; }
        }

        public String SignatureLength
        {
            get { return this.m_signature.SignedInfo.SignatureLength; }
        }

        public Byte[] SignatureValue
        {
            get { return this.m_signature.SignatureValue; }
        }

        public KeyInfo KeyInfo
        {
            get { return this.m_signature.KeyInfo; }
            set { this.m_signature.KeyInfo = value; }
        }

        public XmlElement GetXml()
        {
            // If we have a document context, then return a signature element in this context
            if (this._containingDocument != null)
            {
                return this.m_signature.GetXml(this._containingDocument);
            }
            else
            {
                return this.m_signature.GetXml();
            }
        }

        public void LoadXml(XmlElement value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            this.m_signature.LoadXml(value);

            if (this._context == null)
            {
                this._context = value;
            }

            this._bCacheValid = false;
        }

        //
        // public methods
        //

        public void AddReference(Reference reference)
        {
            this.m_signature.SignedInfo.AddReference(reference);
        }

        public void AddObject(DataObject dataObject)
        {
            this.m_signature.AddObject(dataObject);
        }

        public Boolean CheckSignature()
        {
            AsymmetricKeyParameter signingKey;
            return this.CheckSignatureReturningKey(out signingKey);
        }

        public Boolean CheckSignatureReturningKey(out AsymmetricKeyParameter signingKey)
        {
            SignedXmlDebugLog.LogBeginSignatureVerification(this, this._context);

            Int32 count = 0;
            signingKey = null;
            Boolean bRet = false;
            AsymmetricKeyParameter key = null;

            if (!this.CheckSignatureFormat())
            {
                return false;
            }

            do
            {
                key = this.GetPublicKey();
                if (key != null)
                {
                    if (count++ > 0)
                    {
                        this._bCacheValid = false;
                    }

                    bRet = this.CheckSignature(key);
                    SignedXmlDebugLog.LogVerificationResult(this, key, bRet);
                }
            } while (key != null && bRet == false);

            signingKey = key;
            return bRet;
        }

        public Boolean CheckSignature(AsymmetricKeyParameter key)
        {
            if (!this.CheckSignatureFormat())
            {
                return false;
            }

            if (!this.CheckSignedInfo(key))
            {
                SignedXmlDebugLog.LogVerificationFailure(this, SR.Log_VerificationFailed_SignedInfo);
                return false;
            }

            // Now is the time to go through all the references and see if their DigestValues are good
            if (!this.CheckDigestedReferences())
            {
                SignedXmlDebugLog.LogVerificationFailure(this, SR.Log_VerificationFailed_References);
                return false;
            }

            SignedXmlDebugLog.LogVerificationResult(this, key, true);
            return true;
        }

        public Boolean CheckSignature(IMac macAlg)
        {
            if (!this.CheckSignatureFormat())
            {
                return false;
            }

            if (!this.CheckSignedInfo(macAlg))
            {
                SignedXmlDebugLog.LogVerificationFailure(this, SR.Log_VerificationFailed_SignedInfo);
                return false;
            }

            if (!this.CheckDigestedReferences())
            {
                SignedXmlDebugLog.LogVerificationFailure(this, SR.Log_VerificationFailed_References);
                return false;
            }

            SignedXmlDebugLog.LogVerificationResult(this, macAlg, true);
            return true;
        }

        public Boolean CheckSignature(X509Certificate certificate, Boolean verifySignatureOnly)
        {
            if (!verifySignatureOnly)
            {
                // Check key usages to make sure it is good for signing.
                X509Extensions exts = certificate.CertificateStructure.TbsCertificate.Extensions;
                foreach (DerObjectIdentifier extension in exts.ExtensionOids)
                {
                    if (extension.Equals(X509Extensions.KeyUsage))
                    {
                        Boolean[] keyUsage = certificate.GetKeyUsage();
                        Boolean validKeyUsage = (keyUsage[0 /* DigitalSignature */] || keyUsage[1 /* NonRepudiation */]);

                        if (!validKeyUsage)
                        {
                            SignedXmlDebugLog.LogVerificationFailure(this, SR.Log_VerificationFailed_X509KeyUsage);
                            return false;
                        }
                        break;
                    }
                }

                // Do the chain verification to make sure the certificate is valid.
                System.Security.Cryptography.X509Certificates.X509Chain chain = new System.Security.Cryptography.X509Certificates.X509Chain();
                chain.ChainPolicy.ExtraStore.AddRange(this.BuildBagOfCerts().Select(c => new System.Security.Cryptography.X509Certificates.X509Certificate2(c.GetEncoded())).ToArray());
                Boolean chainVerified = chain.Build(new System.Security.Cryptography.X509Certificates.X509Certificate2(certificate.GetEncoded()));
                SignedXmlDebugLog.LogVerifyX509Chain(this, chain, certificate);

                if (!chainVerified)
                {
                    SignedXmlDebugLog.LogVerificationFailure(this, SR.Log_VerificationFailed_X509Chain);
                    return false;
                }
            }

            AsymmetricKeyParameter publicKey = certificate.GetPublicKey();
            if (!this.CheckSignature(publicKey))
            {
                return false;
            }

            SignedXmlDebugLog.LogVerificationResult(this, certificate, true);
            return true;
        }

        public void ComputeSignature()
        {
            this.ComputeSignature(SignedXml.XmlDsigSHA1Url);
        }

        public void ComputeSignature(String digestAlgorithmUrl)
        {
            SignedXmlDebugLog.LogBeginSignatureComputation(this, this._context);
            this.BuildDigestedReferences();

            // Load the key
            AsymmetricKeyParameter key = this.SigningKey;

            if (key == null)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_LoadKeyFailed);
            }

            // Check the signature algorithm associated with the key so that we can accordingly set the signature method
            if (this.SignedInfo.SignatureMethod == null)
            {
                this.SignedInfo.SignatureMethod = SignedXml.GetCorrespondingSignatureMethodUrl(this.SigningKey, digestAlgorithmUrl);
            }

            // See if there is a signature description class defined in the Config file
            ISigner signatureDescription = CryptoHelpers.CreateFromName<ISigner>(this.SignedInfo.SignatureMethod);
            if (signatureDescription == null)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_SignatureDescriptionNotCreated);
            }

            signatureDescription.Init(true, key);
            this.GetC14NDigest(new SignerHashWrapper(signatureDescription));

            SignedXmlDebugLog.LogSigning(this, key, signatureDescription);
            this.m_signature.SignatureValue = signatureDescription.GenerateSignature();
        }

        public void ComputeSignature(IMac macAlg)
        {
            if (macAlg == null)
            {
                throw new ArgumentNullException(nameof(macAlg));
            }

            if (!(macAlg is HMac))
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_SignatureMethodKeyMismatch);
            }

            Int32 signatureLength;
            if (this.m_signature.SignedInfo.SignatureLength == null)
            {
                signatureLength = macAlg.GetMacSize() * 8;
            }
            else
            {
                signatureLength = Convert.ToInt32(this.m_signature.SignedInfo.SignatureLength, null);
            }
            // signatureLength should be less than hash size
            if (signatureLength < 0 || signatureLength > macAlg.GetMacSize() * 8)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidSignatureLength);
            }

            if (signatureLength % 8 != 0)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidSignatureLength2);
            }

            this.BuildDigestedReferences();

            switch (macAlg.AlgorithmName.Substring(0, macAlg.AlgorithmName.IndexOf('/')).ToUpperInvariant())
            {
                case "SHA-1":
                    this.SignedInfo.SignatureMethod = SignedXml.XmlDsigHMACSHA1Url;
                    break;
                case "SHA-256":
                    this.SignedInfo.SignatureMethod = SignedXml.XmlDsigMoreHMACSHA256Url;
                    break;
                case "SHA-384":
                    this.SignedInfo.SignatureMethod = SignedXml.XmlDsigMoreHMACSHA384Url;
                    break;
                case "SHA-512":
                    this.SignedInfo.SignatureMethod = SignedXml.XmlDsigMoreHMACSHA512Url;
                    break;
                case "MD5":
                    this.SignedInfo.SignatureMethod = SignedXml.XmlDsigMoreHMACMD5Url;
                    break;
                case "RIPEMD160":
                    this.SignedInfo.SignatureMethod = SignedXml.XmlDsigMoreHMACRIPEMD160Url;
                    break;
                default:
                    throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_SignatureMethodKeyMismatch);
            }

            this.GetC14NDigest(new MacHashWrapper(macAlg));
            Byte[] hashValue = new Byte[macAlg.GetMacSize()];
            macAlg.DoFinal(hashValue, 0);

            SignedXmlDebugLog.LogSigning(this, macAlg);
            this.m_signature.SignatureValue = new Byte[signatureLength / 8];
            Buffer.BlockCopy(hashValue, 0, this.m_signature.SignatureValue, 0, signatureLength / 8);
        }

        //
        // virtual methods
        //

        protected virtual AsymmetricKeyParameter GetPublicKey()
        {
            if (this.KeyInfo == null)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_KeyInfoRequired);
            }

            if (this._x509Enum != null)
            {
                AsymmetricKeyParameter key = this.GetNextCertificatePublicKey();
                if (key != null)
                {
                    return key;
                }
            }

            if (this._keyInfoEnum == null)
            {
                this._keyInfoEnum = this.KeyInfo.GetEnumerator();
            }

            // In our implementation, we move to the next KeyInfo clause which is an RSAKeyValue, DSAKeyValue or KeyInfoX509Data
            while (this._keyInfoEnum.MoveNext())
            {
                RSAKeyValue rsaKeyValue = this._keyInfoEnum.Current as RSAKeyValue;
                if (rsaKeyValue != null)
                {
                    return rsaKeyValue.Key;
                }

                DSAKeyValue dsaKeyValue = this._keyInfoEnum.Current as DSAKeyValue;
                if (dsaKeyValue != null)
                {
                    return dsaKeyValue.Key;
                }

                KeyInfoX509Data x509Data = this._keyInfoEnum.Current as KeyInfoX509Data;
                if (x509Data != null)
                {
                    this._x509Collection = Utils.BuildBagOfCerts(x509Data, CertUsageType.Verification);
                    if (this._x509Collection.Count > 0)
                    {
                        this._x509Enum = this._x509Collection.GetEnumerator();
                        AsymmetricKeyParameter key = this.GetNextCertificatePublicKey();
                        if (key != null)
                        {
                            return key;
                        }
                    }
                }
            }

            return null;
        }

        private IList<X509Certificate> BuildBagOfCerts()
        {
            List<X509Certificate> collection = new List<X509Certificate>();
            if (this.KeyInfo != null)
            {
                foreach (KeyInfoClause clause in this.KeyInfo)
                {
                    KeyInfoX509Data x509Data = clause as KeyInfoX509Data;
                    if (x509Data != null)
                    {
                        collection.AddRange(Utils.BuildBagOfCerts(x509Data, CertUsageType.Verification));
                    }
                }
            }

            return collection;
        }

        private AsymmetricKeyParameter GetNextCertificatePublicKey()
        {
            while (this._x509Enum.MoveNext())
            {
                X509Certificate certificate = (X509Certificate)this._x509Enum.Current;
                if (certificate != null)
                {
                    return certificate.GetPublicKey();
                }
            }

            return null;
        }

        public virtual XmlElement GetIdElement(XmlDocument document, String idValue)
        {
            return DefaultGetIdElement(document, idValue);
        }

        internal static XmlElement DefaultGetIdElement(XmlDocument document, String idValue)
        {
            if (document == null)
            {
                return null;
            }

            try
            {
                XmlConvert.VerifyNCName(idValue);
            }
            catch (XmlException)
            {
                // Identifiers are required to be an NCName
                //   (xml:id version 1.0, part 4, paragraph 2, bullet 1)
                //
                // If it isn't an NCName, it isn't allowed to match.
                return null;
            }

            // Get the element with idValue
            XmlElement elem = document.GetElementById(idValue);

            if (elem != null)
            {
                // Have to check for duplicate ID values from the DTD.

                XmlDocument docClone = (XmlDocument)document.CloneNode(true);
                XmlElement cloneElem = docClone.GetElementById(idValue);

                // If it's null here we want to know about it, because it means that
                // GetElementById failed to work across the cloning, and our uniqueness
                // test is invalid.
                System.Diagnostics.Debug.Assert(cloneElem != null);

                // Guard against null anyways
                if (cloneElem != null)
                {
                    cloneElem.Attributes.RemoveAll();

                    XmlElement cloneElem2 = docClone.GetElementById(idValue);

                    if (cloneElem2 != null)
                    {
                        throw new System.Security.Cryptography.CryptographicException(
                            SR.Cryptography_Xml_InvalidReference);
                    }
                }

                return elem;
            }

            elem = GetSingleReferenceTarget(document, "Id", idValue);
            if (elem != null)
            {
                return elem;
            }

            elem = GetSingleReferenceTarget(document, "id", idValue);
            if (elem != null)
            {
                return elem;
            }

            elem = GetSingleReferenceTarget(document, "ID", idValue);

            return elem;
        }

        //
        // private methods
        //

        protected Boolean _bCacheValid = false;
        //private byte[] _digestedSignedInfo = null;

        private static Boolean DefaultSignatureFormatValidator(SignedXml signedXml)
        {
            // Reject the signature if it uses a truncated HMAC
            if (signedXml.DoesSignatureUseTruncatedHmac())
            {
                return false;
            }

            // Reject the signature if it uses a canonicalization algorithm other than
            // one of the ones explicitly allowed
            if (!signedXml.DoesSignatureUseSafeCanonicalizationMethod())
            {
                return false;
            }

            // Otherwise accept it
            return true;
        }

        // Validation function to see if the current signature is signed with a truncated HMAC - one which
        // has a signature length of fewer bits than the whole HMAC output.
        private Boolean DoesSignatureUseTruncatedHmac()
        {
            // If we're not using the SignatureLength property, then we're not truncating the signature length
            if (this.SignedInfo.SignatureLength == null)
            {
                return false;
            }

            // See if we're signed witn an HMAC algorithm
            IMac hmac = CryptoHelpers.CreateFromName<IMac>(this.SignatureMethod);
            if (hmac == null)
            {
                // We aren't signed with an HMAC algorithm, so we cannot have a truncated HMAC
                return false;
            }

            // Figure out how many bits the signature is using
            Int32 actualSignatureSize = 0;
            if (!Int32.TryParse(this.SignedInfo.SignatureLength, out actualSignatureSize))
            {
                // If the value wasn't a valid integer, then we'll conservatively reject it all together
                return true;
            }

            // Make sure the full HMAC signature size is the same size that was specified in the XML
            // signature.  If the actual signature size is not exactly the same as the full HMAC size, then
            // reject the signature.
            return actualSignatureSize != hmac.GetMacSize();
        }

        // Validation function to see if the signature uses a canonicalization algorithm from our list
        // of approved algorithm URIs.
        private Boolean DoesSignatureUseSafeCanonicalizationMethod()
        {
            foreach (String safeAlgorithm in this.SafeCanonicalizationMethods)
            {
                if (String.Equals(safeAlgorithm, this.SignedInfo.CanonicalizationMethod, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            SignedXmlDebugLog.LogUnsafeCanonicalizationMethod(this, this.SignedInfo.CanonicalizationMethod, this.SafeCanonicalizationMethods);
            return false;
        }

        private Boolean ReferenceUsesSafeTransformMethods(Reference reference)
        {
            TransformChain transformChain = reference.TransformChain;
            Int32 transformCount = transformChain.Count;

            for (Int32 i = 0; i < transformCount; i++)
            {
                Transform transform = transformChain[i];

                if (!this.IsSafeTransform(transform.Algorithm))
                {
                    return false;
                }
            }

            return true;
        }

        private Boolean IsSafeTransform(String transformAlgorithm)
        {
            // All canonicalization algorithms are valid transform algorithms.
            foreach (String safeAlgorithm in this.SafeCanonicalizationMethods)
            {
                if (String.Equals(safeAlgorithm, transformAlgorithm, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            foreach (String safeAlgorithm in DefaultSafeTransformMethods)
            {
                if (String.Equals(safeAlgorithm, transformAlgorithm, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            SignedXmlDebugLog.LogUnsafeTransformMethod(
                this,
                transformAlgorithm,
                this.SafeCanonicalizationMethods,
                DefaultSafeTransformMethods);

            return false;
        }

        // Get a list of the built in canonicalization algorithms, as well as any that the machine admin has
        // added to the valid set.
        private static IList<String> KnownCanonicalizationMethods
        {
            get
            {
                if (s_knownCanonicalizationMethods == null)
                {
                    // Start with the list that the machine admin added, if any
                    List<String> safeAlgorithms = new List<String>();

                    // Built in algorithms
                    safeAlgorithms.Add(XmlDsigC14NTransformUrl);
                    safeAlgorithms.Add(XmlDsigC14NWithCommentsTransformUrl);
                    safeAlgorithms.Add(XmlDsigExcC14NTransformUrl);
                    safeAlgorithms.Add(XmlDsigExcC14NWithCommentsTransformUrl);

                    s_knownCanonicalizationMethods = safeAlgorithms;
                }

                return s_knownCanonicalizationMethods;
            }
        }

        private static IList<String> DefaultSafeTransformMethods
        {
            get
            {
                if (s_defaultSafeTransformMethods == null)
                {
                    List<String> safeAlgorithms = new List<String>();

                    // Built in algorithms

                    // KnownCanonicalizationMethods don't need to be added here, because
                    // the validator will automatically accept those.
                    //
                    // xmldsig 6.6.1:
                    //     Any canonicalization algorithm that can be used for
                    //     CanonicalizationMethod can be used as a Transform.
                    safeAlgorithms.Add(XmlDsigEnvelopedSignatureTransformUrl);
                    safeAlgorithms.Add(XmlDsigBase64TransformUrl);
                    safeAlgorithms.Add(XmlLicenseTransformUrl);
                    safeAlgorithms.Add(XmlDecryptionTransformUrl);

                    s_defaultSafeTransformMethods = safeAlgorithms;
                }

                return s_defaultSafeTransformMethods;
            }
        }

        private void GetC14NDigest(IHash hash)
        {
            Boolean isKeyedHashAlgorithm = hash is MacHashWrapper;
            if (isKeyedHashAlgorithm || !this._bCacheValid || !this.SignedInfo.CacheValid)
            {
                String baseUri = (this._containingDocument == null ? null : this._containingDocument.BaseURI);
                XmlResolver resolver = (this._bResolverSet ? this._xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), baseUri));
                XmlDocument doc = Utils.PreProcessElementInput(this.SignedInfo.GetXml(), resolver, baseUri);

                // Add non default namespaces in scope
                CanonicalXmlNodeList namespaces = (this._context == null ? null : Utils.GetPropagatedAttributes(this._context));
                SignedXmlDebugLog.LogNamespacePropagation(this, namespaces);
                Utils.AddNamespaces(doc.DocumentElement, namespaces);

                Transform c14nMethodTransform = this.SignedInfo.CanonicalizationMethodObject;
                c14nMethodTransform.Resolver = resolver;
                c14nMethodTransform.BaseURI = baseUri;

                SignedXmlDebugLog.LogBeginCanonicalization(this, c14nMethodTransform);
                c14nMethodTransform.LoadInput(doc);

                /*
                Stream s = (Stream)c14nMethodTransform.GetOutput();
                XmlDocument testDoc = new XmlDocument();
                testDoc.Load(s);
                Console.WriteLine("Canonical SignedProperties:\n{0}", testDoc.DocumentElement.OuterXml);
                */

                SignedXmlDebugLog.LogCanonicalizedOutput(this, c14nMethodTransform);
                c14nMethodTransform.GetDigestedOutput(hash);

                this._bCacheValid = !isKeyedHashAlgorithm;
            }
        }

        private Int32 GetReferenceLevel(Int32 index, ArrayList references)
        {
            if (this._refProcessed[index])
            {
                return this._refLevelCache[index];
            }

            this._refProcessed[index] = true;
            Reference reference = (Reference)references[index];
            if (reference.Uri == null || reference.Uri.Length == 0 || (reference.Uri.Length > 0 && reference.Uri[0] != '#'))
            {
                this._refLevelCache[index] = 0;
                return 0;
            }
            if (reference.Uri.Length > 0 && reference.Uri[0] == '#')
            {
                String idref = Utils.ExtractIdFromLocalUri(reference.Uri);
                if (idref == "xpointer(/)")
                {
                    this._refLevelCache[index] = 0;
                    return 0;
                }
                // If this is pointing to another reference
                for (Int32 j = 0; j < references.Count; ++j)
                {
                    if (((Reference)references[j]).Id == idref)
                    {
                        this._refLevelCache[index] = this.GetReferenceLevel(j, references) + 1;
                        return (this._refLevelCache[index]);
                    }
                }
                // Then the reference points to an object tag
                this._refLevelCache[index] = 0;
                return 0;
            }
            // Malformed reference
            throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidReference);
        }

        internal class ReferenceLevelSortOrder : IComparer
        {
            private ArrayList _references = null;
            public ReferenceLevelSortOrder() { }

            public ArrayList References
            {
                get { return this._references; }
                set { this._references = value; }
            }

            public Int32 Compare(Object a, Object b)
            {
                Reference referenceA = a as Reference;
                Reference referenceB = b as Reference;

                // Get the indexes
                Int32 iIndexA = 0;
                Int32 iIndexB = 0;
                Int32 i = 0;
                foreach (Reference reference in this.References)
                {
                    if (reference == referenceA)
                    {
                        iIndexA = i;
                    }

                    if (reference == referenceB)
                    {
                        iIndexB = i;
                    }

                    i++;
                }

                Int32 iLevelA = referenceA.SignedXml.GetReferenceLevel(iIndexA, this.References);
                Int32 iLevelB = referenceB.SignedXml.GetReferenceLevel(iIndexB, this.References);
                return iLevelA.CompareTo(iLevelB);
            }
        }

        private void BuildDigestedReferences()
        {
            // Default the DigestMethod and Canonicalization
            ArrayList references = this.SignedInfo.References;
            // Reset the cache
            this._refProcessed = new Boolean[references.Count];
            this._refLevelCache = new Int32[references.Count];

            ReferenceLevelSortOrder sortOrder = new ReferenceLevelSortOrder();
            sortOrder.References = references;
            // Don't alter the order of the references array list
            ArrayList sortedReferences = new ArrayList();
            foreach (Reference reference in references)
            {
                sortedReferences.Add(reference);
            }
            sortedReferences.Sort(sortOrder);

            CanonicalXmlNodeList nodeList = new CanonicalXmlNodeList();
            foreach (DataObject obj in this.m_signature.ObjectList)
            {
                nodeList.Add(obj.GetXml());
            }
            foreach (Reference reference in sortedReferences)
            {
                // If no DigestMethod has yet been set, default it to sha1
                if (reference.DigestMethod == null)
                {
                    reference.DigestMethod = Reference.DefaultDigestMethod;
                }

                SignedXmlDebugLog.LogSigningReference(this, reference);

                reference.UpdateHashValue(this._containingDocument, nodeList);
                // If this reference has an Id attribute, add it
                if (reference.Id != null)
                {
                    nodeList.Add(reference.GetXml());
                }
            }
        }

        private Boolean CheckDigestedReferences()
        {
            ArrayList references = this.m_signature.SignedInfo.References;
            for (Int32 i = 0; i < references.Count; ++i)
            {
                Reference digestedReference = (Reference)references[i];

                if (!this.ReferenceUsesSafeTransformMethods(digestedReference))
                {
                    return false;
                }

                SignedXmlDebugLog.LogVerifyReference(this, digestedReference);
                Byte[] calculatedHash = null;
                try
                {
                    calculatedHash = digestedReference.CalculateHashValue(this._containingDocument, this.m_signature.ReferencedItems);
                }
                catch (CryptoSignedXmlRecursionException)
                {
                    SignedXmlDebugLog.LogSignedXmlRecursionLimit(this, digestedReference);
                    return false;
                }
                // Compare both hashes
                SignedXmlDebugLog.LogVerifyReferenceHash(this, digestedReference, calculatedHash, digestedReference.DigestValue);

                if (!CryptographicEquals(calculatedHash, digestedReference.DigestValue))
                {
                    return false;
                }
            }

            return true;
        }

        // Methods _must_ be marked both No Inlining and No Optimization to be fully opted out of optimization.
        // This is because if a candidate method is inlined, its method level attributes, including the NoOptimization
        // attribute, are lost.
        // This method makes no attempt to disguise the length of either of its inputs. It is assumed the attacker has
        // knowledge of the algorithms used, and thus the output length. Length is difficult to properly blind in modern CPUs.
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        private static Boolean CryptographicEquals(Byte[] a, Byte[] b)
        {
            System.Diagnostics.Debug.Assert(a != null);
            System.Diagnostics.Debug.Assert(b != null);

            Int32 result = 0;

            // Short cut if the lengths are not identical
            if (a.Length != b.Length)
            {
                return false;
            }

            unchecked
            {
                // Normally this caching doesn't matter, but with the optimizer off, this nets a non-trivial speedup.
                Int32 aLength = a.Length;

                for (Int32 i = 0; i < aLength; i++)
                {
                    // We use subtraction here instead of XOR because the XOR algorithm gets ever so
                    // slightly faster as more and more differences pile up.
                    // This cannot overflow more than once (and back to 0) because bytes are 1 byte
                    // in length, and result is 4 bytes. The OR propagates all set bytes, so the differences
                    // can't add up and overflow a second time.
                    result = result | (a[i] - b[i]);
                }
            }

            return (0 == result);
        }

        // If we have a signature format validation callback, check to see if this signature's format (not
        // the signautre itself) is valid according to the validator.  A return value of true indicates that
        // the signature format is acceptable, false means that the format is not valid.
        private Boolean CheckSignatureFormat()
        {
            if (this._signatureFormatValidator == null)
            {
                // No format validator means that we default to accepting the signature.  (This is
                // effectively compatibility mode with v3.5).
                return true;
            }

            SignedXmlDebugLog.LogBeginCheckSignatureFormat(this, this._signatureFormatValidator);

            Boolean formatValid = this._signatureFormatValidator(this);
            SignedXmlDebugLog.LogFormatValidationResult(this, formatValid);
            return formatValid;
        }

        private Boolean CheckSignedInfo(AsymmetricKeyParameter key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            SignedXmlDebugLog.LogBeginCheckSignedInfo(this, this.m_signature.SignedInfo);

            ISigner signatureDescription = CryptoHelpers.CreateFromName<ISigner>(this.SignatureMethod);
            if (signatureDescription == null)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_SignatureDescriptionNotCreated);
            }

            // Let's see if the key corresponds with the SignatureMethod
            //ISigner ta = SignerUtilities.GetSigner(signatureDescription.AlgorithmName);
            //if (!IsKeyTheCorrectAlgorithm(key, ta))
            //    return false;

            try
            {
                signatureDescription.Init(false, key);
            }
            catch (Exception)
            {
                return false;
            }

            this.GetC14NDigest(new SignerHashWrapper(signatureDescription));

            /*SignedXmlDebugLog.LogVerifySignedInfo(this,
                                                  key,
                                                  signatureDescription,
                                                  hashAlgorithm,
                                                  asymmetricSignatureDeformatter,
                                                  hashval,
                                                  m_signature.SignatureValue);*/

            return signatureDescription.VerifySignature(this.m_signature.SignatureValue);
        }

        private Boolean CheckSignedInfo(IMac macAlg)
        {
            if (macAlg == null)
            {
                throw new ArgumentNullException(nameof(macAlg));
            }

            SignedXmlDebugLog.LogBeginCheckSignedInfo(this, this.m_signature.SignedInfo);

            Int32 signatureLength;
            if (this.m_signature.SignedInfo.SignatureLength == null)
            {
                signatureLength = macAlg.GetMacSize() * 8;
            }
            else
            {
                signatureLength = Convert.ToInt32(this.m_signature.SignedInfo.SignatureLength, null);
            }

            // signatureLength should be less than hash size
            if (signatureLength < 0 || signatureLength > macAlg.GetMacSize() * 8)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidSignatureLength);
            }

            if (signatureLength % 8 != 0)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidSignatureLength2);
            }

            if (this.m_signature.SignatureValue == null)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_SignatureValueRequired);
            }

            if (this.m_signature.SignatureValue.Length != signatureLength / 8)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidSignatureLength);
            }

            // Calculate the hash
            this.GetC14NDigest(new MacHashWrapper(macAlg));
            Byte[] hashValue = new Byte[macAlg.GetMacSize()];
            macAlg.DoFinal(hashValue, 0);
            SignedXmlDebugLog.LogVerifySignedInfo(this, macAlg, hashValue, this.m_signature.SignatureValue);
            for (Int32 i = 0; i < this.m_signature.SignatureValue.Length; i++)
            {
                if (this.m_signature.SignatureValue[i] != hashValue[i])
                {
                    return false;
                }
            }
            return true;
        }

        private static XmlElement GetSingleReferenceTarget(XmlDocument document, String idAttributeName, String idValue)
        {
            // idValue has already been tested as an NCName (unless overridden for compatibility), so there's no
            // escaping that needs to be done here.
            String xPath = "//*[@" + idAttributeName + "=\"" + idValue + "\"]";

            // http://www.w3.org/TR/xmldsig-core/#sec-ReferenceProcessingModel says that for the form URI="#chapter1":
            //
            //   Identifies a node-set containing the element with ID attribute value 'chapter1' ...
            //
            // Note that it uses the singular. Therefore, if the match is ambiguous, we should consider the document invalid.
            //
            // In this case, we'll treat it the same as having found nothing across all fallbacks (but shortcut so that we don't
            // fall into a trap of finding a secondary element which wasn't the originally signed one).

            XmlNodeList nodeList = document.SelectNodes(xPath);

            if (nodeList == null || nodeList.Count == 0)
            {
                return null;
            }

            if (nodeList.Count == 1)
            {
                return nodeList[0] as XmlElement;
            }

            throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidReference);
        }

        private static Boolean IsKeyTheCorrectAlgorithm(AsymmetricKeyParameter key, ISigner expectedType)
        {
            try
            {
                expectedType.Init(false, key);
            }
            catch (Exception)
            {
                return false;
            }

            return true;
        }

        /// <summary>
        /// <![CDATA[Returns a signature method url by signing private key algorithm and supplied digest algorithm url.
        /// e.g.: signing key is EC private key, and digest algorithm is "http://www.w3.org/2007/05/xmldsig-more#sha3-256",
        /// then the result is "http://www.w3.org/2021/04/xmldsig-more#ecdsa-sha3-256".]]>
        /// </summary>
        /// <param name="signingKey"></param>
        /// <param name="digestAlgorithmUrl"></param>
        /// <returns></returns>
        public static String GetCorrespondingSignatureMethodUrl(AsymmetricKeyParameter signingKey, String digestAlgorithmUrl)
        {
            String signatureMethod = null;
            if (signingKey is ECPrivateKeyParameters)
            {
                switch (digestAlgorithmUrl)
                {
                    case SignedXml.XmlDsigSHA1Url:
                        signatureMethod = XmlDsigMoreECDSASHA1Url;
                        break;
                    case SignedXml.XmlDsigMoreSHA224Url:
                        signatureMethod = XmlDsigMoreECDSASHA224Url;
                        break;
                    case EncryptedXml.XmlEncSHA256Url:
                        signatureMethod = XmlDsigMoreECDSASHA256Url;
                        break;
                    case SignedXml.XmlDsigMoreSHA384Url:
                        signatureMethod = XmlDsigMoreECDSASHA384Url;
                        break;
                    case EncryptedXml.XmlEncSHA512Url:
                        signatureMethod = XmlDsigMoreECDSASHA512Url;
                        break;
                    case SignedXml.XmlDsigMoreSHA3_224Url:
                        signatureMethod = XmlDsigMoreECDSASHA3_224Url;
                        break;
                    case SignedXml.XmlDsigMoreSHA3_256Url:
                        signatureMethod = XmlDsigMoreECDSASHA3_256Url;
                        break;
                    case SignedXml.XmlDsigMoreSHA3_384Url:
                        signatureMethod = XmlDsigMoreECDSASHA3_384Url;
                        break;
                    case SignedXml.XmlDsigMoreSHA3_512Url:
                        signatureMethod = XmlDsigMoreECDSASHA3_512Url;
                        break;
                    default:
                        throw new System.Security.Cryptography.CryptographicException($"Digest algorithm \"{digestAlgorithmUrl}\" for EC key not supported!");
                }
            }
            else if (signingKey is RsaKeyParameters)
            {

                switch (digestAlgorithmUrl)
                {
                    case SignedXml.XmlDsigSHA1Url:
                        signatureMethod = XmlDsigRSASHA1Url;
                        break;
                    case SignedXml.XmlDsigMoreSHA224Url:
                        signatureMethod = XmlDsigMoreRSASHA224Url;
                        break;
                    case EncryptedXml.XmlEncSHA256Url:
                        signatureMethod = XmlDsigMoreRSASHA256Url;
                        break;
                    case SignedXml.XmlDsigMoreSHA384Url:
                        signatureMethod = XmlDsigMoreRSASHA384Url;
                        break;
                    case EncryptedXml.XmlEncSHA512Url:
                        signatureMethod = XmlDsigMoreRSASHA512Url;
                        break;
                    default:
                        throw new System.Security.Cryptography.CryptographicException($"Digest algorithm \"{digestAlgorithmUrl}\" for RSA key not supported!");
                }
            }
            else if (signingKey is DsaKeyParameters)
            {

                switch (digestAlgorithmUrl)
                {
                    case SignedXml.XmlDsigSHA1Url:
                        signatureMethod = XmlDsigDSAUrl;
                        break;
                    case EncryptedXml.XmlEncSHA256Url:
                        signatureMethod = XmlDsig11DSASHA256Url;
                        break;
                    default:
                        throw new System.Security.Cryptography.CryptographicException($"Digest algorithm \"{digestAlgorithmUrl}\" for DSA key not supported!");
                }
            }
            else
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_CreatedKeyFailed);
            }
            return signatureMethod;
        }
    }
}
