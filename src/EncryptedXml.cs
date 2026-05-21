// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    public class EncryptedXml
    {
        //
        // public constant Url identifiers used within the XML Encryption classes
        //

        public const String XmlEncNamespaceUrl = "http://www.w3.org/2001/04/xmlenc#";
        public const String XmlEncNamespacePrefix = "xenc";
        public const String XmlEnc11NamespaceUrl =  "http://www.w3.org/2009/xmlenc11#";
        public const String XmlEnc11NamespacePrefix = "xenc11";
        public const String XmlEncElementUrl = "http://www.w3.org/2001/04/xmlenc#Element";
        public const String XmlEncElementContentUrl = "http://www.w3.org/2001/04/xmlenc#Content";
        public const String XmlEncEncryptedKeyUrl = "http://www.w3.org/2001/04/xmlenc#EncryptedKey";

        //
        // Symmetric Block Encryption
        //

        public const String XmlEncDESUrl = "http://www.w3.org/2001/04/xmlenc#des-cbc";
        public const String XmlEncTripleDESUrl = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc";
        public const String XmlEncAES128Url = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
        public const String XmlEncAES256Url = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
        public const String XmlEncAES192Url = "http://www.w3.org/2001/04/xmlenc#aes192-cbc";

        //
        // Key Transport
        //

        public const String XmlEncRSA15Url = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
        public const String XmlEncRSAOAEPUrl = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";

        //
        // Symmetric Key Wrap
        //

        public const String XmlEncTripleDESKeyWrapUrl = "http://www.w3.org/2001/04/xmlenc#kw-tripledes";
        public const String XmlEncAES128KeyWrapUrl = "http://www.w3.org/2001/04/xmlenc#kw-aes128";
        public const String XmlEncAES256KeyWrapUrl = "http://www.w3.org/2001/04/xmlenc#kw-aes256";
        public const String XmlEncAES192KeyWrapUrl = "http://www.w3.org/2001/04/xmlenc#kw-aes192";

        //
        // Message Digest
        //

        public const String XmlEncRIPEMD1606Url = "http://www.w3.org/2001/04/xmlenc#ripemd160";
        public const String XmlEncSHA256Url = "http://www.w3.org/2001/04/xmlenc#sha256";
        public const String XmlEncSHA512Url = "http://www.w3.org/2001/04/xmlenc#sha512";

        //
        // private members
        //

        private readonly XmlDocument _document;
        private XmlResolver _xmlResolver;
        // hash table defining the key name mapping
        private const Int32 _capacity = 4; // 4 is a reasonable capacity for
                                           // the key name mapping hash table
        private readonly Hashtable _keyNameMapping;
        private String _padding;
        private String _mode;
        private Encoding _encoding;
        private String _recipient;
        private Int32 _xmlDsigSearchDepthCounter = 0;
        private Int32 _xmlDsigSearchDepth;

        //
        // public constructors
        //
        public EncryptedXml() : this(new XmlDocument()) { }

        public EncryptedXml(XmlDocument document)
        {
            this._document = document;
            this._xmlResolver = null;
            // set the default padding to ISO-10126
            this._padding = "ISO10126PADDING";
            // set the default cipher mode to CBC
            this._mode = "CBC";
            // By default the encoding is going to be UTF8
            this._encoding = Encoding.UTF8;
            this._keyNameMapping = new Hashtable(_capacity);
            this._xmlDsigSearchDepth = Utils.XmlDsigSearchDepth;
        }

        /// <summary>
        /// This method validates the _xmlDsigSearchDepthCounter counter
        /// if the counter is over the limit defined by admin or developer.
        /// </summary>
        /// <returns>returns true if the limit has reached otherwise false</returns>
        private Boolean IsOverXmlDsigRecursionLimit()
        {
            if (this._xmlDsigSearchDepthCounter > this.XmlDSigSearchDepth)
            {
                return true;
            }
            return false;
        }

        /// <summary>
        /// Gets / Sets the max limit for recursive search of encryption key in signed XML
        /// </summary>
        public Int32 XmlDSigSearchDepth
        {
            get
            {
                return this._xmlDsigSearchDepth;
            }
            set
            {
                this._xmlDsigSearchDepth = value;
            }
        }

        // The resolver to use for external entities
        public XmlResolver Resolver
        {
            get { return this._xmlResolver; }
            set { this._xmlResolver = value; }
        }

        // The padding to be used. XML Encryption uses ISO 10126
        // but it's nice to provide a way to extend this to include other forms of paddings
        public String Padding
        {
            get { return this._padding; }
            set { this._padding = value; }
        }

        // The cipher mode to be used. XML Encryption uses CBC padding
        // but it's nice to provide a way to extend this to include other cipher modes
        public String Mode
        {
            get { return this._mode; }
            set { this._mode = value; }
        }

        // The encoding of the XML document
        public Encoding Encoding
        {
            get { return this._encoding; }
            set { this._encoding = value; }
        }

        // This is used to specify the EncryptedKey elements that should be considered
        // when an EncyptedData references an EncryptedKey using a CarriedKeyName and Recipient
        public String Recipient
        {
            get
            {
                // an unspecified value for an XmlAttribute is string.Empty
                if (this._recipient == null)
                {
                    this._recipient = String.Empty;
                }

                return this._recipient;
            }
            set { this._recipient = value; }
        }

        //
        // private methods
        //

        private Byte[] GetCipherValue(CipherData cipherData)
        {
            if (cipherData == null)
            {
                throw new ArgumentNullException(nameof(cipherData));
            }

            Stream inputStream = null;

            if (cipherData.CipherValue != null)
            {
                return cipherData.CipherValue;
            }
            else if (cipherData.CipherReference != null)
            {
                if (cipherData.CipherReference.CipherValue != null)
                {
                    return cipherData.CipherReference.CipherValue;
                }

                Stream decInputStream = null;
                if (cipherData.CipherReference.Uri == null)
                {
                    throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_UriNotSupported);
                }
                // See if the CipherReference is a local URI
                if (cipherData.CipherReference.Uri.Length == 0)
                {
                    // self referenced Uri
                    String baseUri = (this._document == null ? null : this._document.BaseURI);
                    TransformChain tc = cipherData.CipherReference.TransformChain;
                    if (tc == null)
                    {
                        throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_UriNotSupported);
                    }
                    decInputStream = tc.TransformToOctetStream(this._document, this._xmlResolver, baseUri);
                }
                else if (cipherData.CipherReference.Uri[0] == '#')
                {
                    String idref = Utils.ExtractIdFromLocalUri(cipherData.CipherReference.Uri);
                    // Serialize
                    XmlElement idElem = this.GetIdElement(this._document, idref);
                    if (idElem == null || idElem.OuterXml == null)
                    {
                        throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_UriNotSupported);
                    }
                    inputStream = new MemoryStream(this._encoding.GetBytes(idElem.OuterXml));
                    String baseUri = (this._document == null ? null : this._document.BaseURI);
                    TransformChain tc = cipherData.CipherReference.TransformChain;
                    if (tc == null)
                    {
                        throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_UriNotSupported);
                    }
                    decInputStream = tc.TransformToOctetStream(inputStream, this._xmlResolver, baseUri);
                }
                else
                {
                    throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_UriNotResolved, cipherData.CipherReference.Uri);
                }
                // read the output stream into a memory stream
                Byte[] cipherValue = null;
                using (MemoryStream ms = new MemoryStream())
                {
                    Utils.Pump(decInputStream, ms);
                    cipherValue = ms.ToArray();
                    // Close the stream and return
                    if (inputStream != null)
                    {
                        inputStream.Close();
                    }

                    decInputStream.Close();
                }

                // cache the cipher value for Perf reasons in case we call this routine twice
                cipherData.CipherReference.CipherValue = cipherValue;
                return cipherValue;
            }

            // Throw a CryptographicException if we were unable to retrieve the cipher data.
            throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_MissingCipherData);
        }

        //
        // public virtual methods
        //

        // This describes how the application wants to associate id references to elements
        public virtual XmlElement GetIdElement(XmlDocument document, String idValue)
        {
            return SignedXml.DefaultGetIdElement(document, idValue);
        }

        // default behaviour is to look for the IV in the CipherValue
        public virtual Byte[] GetDecryptionIV(EncryptedData encryptedData, String symmetricAlgorithmUri)
        {
            if (encryptedData == null)
            {
                throw new ArgumentNullException(nameof(encryptedData));
            }

            Int32 initBytesSize = 0;
            // If the Uri is not provided by the application, try to get it from the EncryptionMethod
            if (symmetricAlgorithmUri == null)
            {
                if (encryptedData.EncryptionMethod == null)
                {
                    throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_MissingAlgorithm);
                }

                symmetricAlgorithmUri = encryptedData.EncryptionMethod.KeyAlgorithm;
            }
            switch (symmetricAlgorithmUri)
            {
                case EncryptedXml.XmlEncDESUrl:
                case EncryptedXml.XmlEncTripleDESUrl:
                    initBytesSize = 8;
                    break;
                case EncryptedXml.XmlEncAES128Url:
                case EncryptedXml.XmlEncAES192Url:
                case EncryptedXml.XmlEncAES256Url:
                    initBytesSize = 16;
                    break;
                default:
                    // The Uri is not supported.
                    throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_UriNotSupported);
            }
            Byte[] IV = new Byte[initBytesSize];
            Byte[] cipherValue = this.GetCipherValue(encryptedData.CipherData);
            Buffer.BlockCopy(cipherValue, 0, IV, 0, IV.Length);
            return IV;
        }

        // default behaviour is to look for keys defined by an EncryptedKey clause
        // either directly or through a KeyInfoRetrievalMethod, and key names in the key mapping
        public virtual ICipherParameters GetDecryptionKey(EncryptedData encryptedData, String symmetricAlgorithmUri)
        {
            if (encryptedData == null)
            {
                throw new ArgumentNullException(nameof(encryptedData));
            }

            if (encryptedData.KeyInfo == null)
            {
                return null;
            }

            IEnumerator keyInfoEnum = encryptedData.KeyInfo.GetEnumerator();
            KeyInfoRetrievalMethod kiRetrievalMethod;
            KeyInfoName kiName;
            KeyInfoEncryptedKey kiEncKey;
            EncryptedKey ek = null;

            while (keyInfoEnum.MoveNext())
            {
                kiName = keyInfoEnum.Current as KeyInfoName;
                if (kiName != null)
                {
                    // Get the decryption key from the key mapping
                    String keyName = kiName.Value;
                    if (this._keyNameMapping[keyName] as ICipherParameters != null)
                    {
                        return (ICipherParameters)this._keyNameMapping[keyName];
                    }
                    // try to get it from a CarriedKeyName
                    XmlNamespaceManager nsm = new XmlNamespaceManager(this._document.NameTable);
                    nsm.AddNamespace(EncryptedXml.XmlEncNamespacePrefix, EncryptedXml.XmlEncNamespaceUrl);
                    XmlNodeList encryptedKeyList = this._document.SelectNodes("//" + EncryptedXml.XmlEncNamespacePrefix + ":EncryptedKey", nsm);
                    if (encryptedKeyList != null)
                    {
                        foreach (XmlNode encryptedKeyNode in encryptedKeyList)
                        {
                            XmlElement encryptedKeyElement = encryptedKeyNode as XmlElement;
                            EncryptedKey ek1 = new EncryptedKey();
                            ek1.LoadXml(encryptedKeyElement);
                            if (ek1.CarriedKeyName == keyName && ek1.Recipient == this.Recipient)
                            {
                                ek = ek1;
                                break;
                            }
                        }
                    }
                    break;
                }
                kiRetrievalMethod = keyInfoEnum.Current as KeyInfoRetrievalMethod;
                if (kiRetrievalMethod != null)
                {
                    String idref = Utils.ExtractIdFromLocalUri(kiRetrievalMethod.Uri);
                    ek = new EncryptedKey();
                    ek.LoadXml(this.GetIdElement(this._document, idref));
                    break;
                }
                kiEncKey = keyInfoEnum.Current as KeyInfoEncryptedKey;
                if (kiEncKey != null)
                {
                    ek = kiEncKey.EncryptedKey;
                    break;
                }
            }

            // if we have an EncryptedKey, decrypt to get the symmetric key
            if (ek != null)
            {
                // now process the EncryptedKey, loop recursively
                // If the Uri is not provided by the application, try to get it from the EncryptionMethod
                if (symmetricAlgorithmUri == null)
                {
                    if (encryptedData.EncryptionMethod == null)
                    {
                        throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_MissingAlgorithm);
                    }

                    symmetricAlgorithmUri = encryptedData.EncryptionMethod.KeyAlgorithm;
                }
                Byte[] key = this.DecryptEncryptedKey(ek);
                if (key == null)
                {
                    throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_MissingDecryptionKey);
                }

                IBufferedCipher symAlg = CryptoHelpers.CreateFromName<IBufferedCipher>(symmetricAlgorithmUri);
                if (symAlg == null)
                {
                    throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_MissingAlgorithm);
                }

                KeyParameter keyParam;
                if (symAlg.AlgorithmName.IndexOf("DESede", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    keyParam = new DesEdeParameters(key);
                }
                else if (symAlg.AlgorithmName.IndexOf("DES", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    keyParam = new DesParameters(key);
                }
                else
                {
                    keyParam = new KeyParameter(key);
                }

                return keyParam;
            }
            return null;
        }

        // Try to decrypt the EncryptedKey given the key mapping
        public virtual Byte[] DecryptEncryptedKey(EncryptedKey encryptedKey, RsaKeyParameters privateKey = null)
        {
            if (encryptedKey == null)
            {
                throw new ArgumentNullException(nameof(encryptedKey));
            }

            if (encryptedKey.KeyInfo == null)
            {
                return null;
            }

            IEnumerator keyInfoEnum = encryptedKey.KeyInfo.GetEnumerator();
            KeyInfoName kiName;
            KeyInfoX509Data kiX509Data;
            KeyInfoRetrievalMethod kiRetrievalMethod;
            KeyInfoEncryptedKey kiEncKey;
            EncryptedKey ek = null;
            Boolean fOAEP = false;

            while (keyInfoEnum.MoveNext())
            {
                kiName = keyInfoEnum.Current as KeyInfoName;
                if (kiName != null)
                {
                    // Get the decryption key from the key mapping
                    String keyName = kiName.Value;
                    Object kek = this._keyNameMapping[keyName];
                    if (kek != null)
                    {
                        if (encryptedKey.CipherData == null || encryptedKey.CipherData.CipherValue == null)
                        {
                            throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_MissingAlgorithm);
                        }
                        // kek is either a SymmetricAlgorithm or an RSA key, otherwise, we wouldn't be able to insert it in the hash table
                        if (kek is KeyParameter kp)
                        {
                            return EncryptedXml.DecryptKey(encryptedKey.CipherData.CipherValue, kp);
                        }
                        else if (kek is ParametersWithIV piv)
                        {
                            return EncryptedXml.DecryptKey(encryptedKey.CipherData.CipherValue, piv.Parameters as KeyParameter);
                        }

                        // kek is an RSA key: get fOAEP from the algorithm, default to false
                        fOAEP = (encryptedKey.EncryptionMethod != null && encryptedKey.EncryptionMethod.KeyAlgorithm == EncryptedXml.XmlEncRSAOAEPUrl);
                        return EncryptedXml.DecryptKey(encryptedKey.CipherData.CipherValue, (RsaKeyParameters)kek, fOAEP);
                    }
                    break;
                }
                kiX509Data = keyInfoEnum.Current as KeyInfoX509Data;
                if (kiX509Data != null)
                {
                    IList<X509Certificate> collection = Utils.BuildBagOfCerts(kiX509Data, CertUsageType.Decryption);
                    foreach (X509Certificate certificate in collection)
                    {
                        if (privateKey != null)
                        {
                            if (encryptedKey.CipherData == null || encryptedKey.CipherData.CipherValue == null)
                            {
                                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_MissingAlgorithm);
                            }
                            fOAEP = (encryptedKey.EncryptionMethod != null && encryptedKey.EncryptionMethod.KeyAlgorithm == EncryptedXml.XmlEncRSAOAEPUrl);
                            return EncryptedXml.DecryptKey(encryptedKey.CipherData.CipherValue, privateKey, fOAEP);
                        }
                    }
                    break;
                }
                kiRetrievalMethod = keyInfoEnum.Current as KeyInfoRetrievalMethod;
                if (kiRetrievalMethod != null)
                {
                    String idref = Utils.ExtractIdFromLocalUri(kiRetrievalMethod.Uri);
                    ek = new EncryptedKey();
                    ek.LoadXml(this.GetIdElement(this._document, idref));
                    try
                    {
                        //Following checks if XML dsig processing is in loop and within the limit defined by machine
                        // admin or developer. Once the recursion depth crosses the defined limit it will throw exception.
                        this._xmlDsigSearchDepthCounter++;
                        if (this.IsOverXmlDsigRecursionLimit())
                        {
                            //Throw exception once recursion limit is hit.
                            throw new CryptoSignedXmlRecursionException();
                        }
                        else
                        {
                            return this.DecryptEncryptedKey(ek, privateKey);
                        }
                    }
                    finally
                    {
                        this._xmlDsigSearchDepthCounter--;
                    }
                }
                kiEncKey = keyInfoEnum.Current as KeyInfoEncryptedKey;
                if (kiEncKey != null)
                {
                    ek = kiEncKey.EncryptedKey;
                    // recursively process EncryptedKey elements
                    Byte[] encryptionKey = this.DecryptEncryptedKey(ek, privateKey);
                    if (encryptionKey != null)
                    {
                        // this is a symmetric algorithm for sure
                        IBlockCipher blockSymAlg = CryptoHelpers.CreateFromName<IBlockCipher>(encryptedKey.EncryptionMethod.KeyAlgorithm);
                        if (blockSymAlg == null)
                        {
                            IBufferedCipher bufferedSymAlg = CryptoHelpers.CreateFromName<IBufferedCipher>(encryptedKey.EncryptionMethod.KeyAlgorithm);
                            if (bufferedSymAlg == null)
                            {
                                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_MissingAlgorithm);
                            }
                        }
                        if (encryptedKey.CipherData == null || encryptedKey.CipherData.CipherValue == null)
                        {
                            throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_MissingAlgorithm);
                        }
                        return EncryptedXml.DecryptKey(encryptedKey.CipherData.CipherValue, new KeyParameter(encryptionKey));
                    }
                }
            }
            return null;
        }

        //
        // public methods
        //

        // defines a key name mapping. Default behaviour is to require the key object
        // to be an RSA key or a SymmetricAlgorithm
        public void AddKeyNameMapping(String keyName, Object keyObject)
        {
            if (keyName == null)
            {
                throw new ArgumentNullException(nameof(keyName));
            }

            if (keyObject == null)
            {
                throw new ArgumentNullException(nameof(keyObject));
            }

            if (!(keyObject is RsaKeyParameters) && !(keyObject is ICipherParameters))
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_NotSupportedCryptographicTransform);
            }

            this._keyNameMapping.Add(keyName, keyObject);
        }

        public void ClearKeyNameMappings()
        {
            this._keyNameMapping.Clear();
        }

        // Encrypts the given element with the certificate specified. The certificate is added as
        // an X509Data KeyInfo to an EncryptedKey (AES session key) generated randomly.
        public EncryptedData Encrypt(XmlElement inputElement, X509Certificate certificate)
        {
            if (inputElement == null)
            {
                throw new ArgumentNullException(nameof(inputElement));
            }

            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            AsymmetricKeyParameter rsaPublicKey = certificate.GetPublicKey();
            if (rsaPublicKey == null || !(rsaPublicKey is RsaKeyParameters))
            {
                throw new NotSupportedException(SR.NotSupported_KeyAlgorithm);
            }

            // Create the EncryptedData object, using an AES-256 session key by default.
            EncryptedData ed = new EncryptedData();
            ed.Type = EncryptedXml.XmlEncElementUrl;
            ed.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url);

            // Include the certificate in the EncryptedKey KeyInfo.
            EncryptedKey ek = new EncryptedKey();
            ek.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSA15Url);
            ek.KeyInfo.AddClause(new KeyInfoX509Data(certificate));

            // Create a random AES session key and encrypt it with the public key associated with the certificate.
            IBufferedCipher rijn = CipherUtilities.GetCipher("RIJNDAEL/CBC/PKCS7");
            KeyParameter keyParam = new KeyParameter(Utils.GenerateRandomBlock(rijn.GetBlockSize()));
            ParametersWithIV rijnKey = new ParametersWithIV(keyParam, Utils.GenerateRandomBlock(rijn.GetBlockSize()));
            ek.CipherData.CipherValue = EncryptedXml.EncryptKey(keyParam.GetKey(), (RsaKeyParameters)rsaPublicKey, false);

            // Encrypt the input element with the random session key that we've created above.
            KeyInfoEncryptedKey kek = new KeyInfoEncryptedKey(ek);
            ed.KeyInfo.AddClause(kek);
            ed.CipherData.CipherValue = this.EncryptData(inputElement, rijnKey, false);

            return ed;
        }

        // Encrypts the given element with the key name specified. A corresponding key name mapping
        // has to be defined before calling this method. The key name is added as
        // a KeyNameInfo KeyInfo to an EncryptedKey (AES session key) generated randomly.
        public EncryptedData Encrypt(XmlElement inputElement, String keyName)
        {
            if (inputElement == null)
            {
                throw new ArgumentNullException(nameof(inputElement));
            }

            if (keyName == null)
            {
                throw new ArgumentNullException(nameof(keyName));
            }

            Object encryptionKey = null;
            if (this._keyNameMapping != null)
            {
                encryptionKey = this._keyNameMapping[keyName];
            }

            if (encryptionKey == null)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_MissingEncryptionKey);
            }

            // kek is either a SymmetricAlgorithm or an RSA key, otherwise, we wouldn't be able to insert it in the hash table
            ParametersWithIV iv = encryptionKey as ParametersWithIV;
            KeyParameter symKey = encryptionKey as KeyParameter;
            RsaKeyParameters rsa = encryptionKey as RsaKeyParameters;

            // Create the EncryptedData object, using an AES-256 session key by default.
            EncryptedData ed = new EncryptedData();
            ed.Type = EncryptedXml.XmlEncElementUrl;
            ed.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url);

            // Include the key name in the EncryptedKey KeyInfo.
            String encryptionMethod = null;
            if (symKey == null && iv == null)
            {
                encryptionMethod = EncryptedXml.XmlEncRSA15Url;
            }
            else if (iv != null)
            {
                symKey = iv.Parameters as KeyParameter;
            }

            if (symKey != null)
            {
                if (symKey is DesParameters)
                {
                    // CMS Triple DES Key Wrap
                    encryptionMethod = EncryptedXml.XmlEncTripleDESKeyWrapUrl;
                }
                else
                {
                    // FIPS AES Key Wrap
                    switch (symKey.GetKey().Length * 8)
                    {
                        case 128:
                            encryptionMethod = EncryptedXml.XmlEncAES128KeyWrapUrl;
                            break;
                        case 192:
                            encryptionMethod = EncryptedXml.XmlEncAES192KeyWrapUrl;
                            break;
                        case 256:
                            encryptionMethod = EncryptedXml.XmlEncAES256KeyWrapUrl;
                            break;
                    }
                }
            }

            EncryptedKey ek = new EncryptedKey();
            ek.EncryptionMethod = new EncryptionMethod(encryptionMethod);
            ek.KeyInfo.AddClause(new KeyInfoName(keyName));

            // Create a random AES session key and encrypt it with the public key associated with the certificate.
            Byte[] keydata = Utils.GenerateRandomBlock(256 / 8);
            Byte[] ivdata = Utils.GenerateRandomBlock(128 / 8);
            ParametersWithIV rijn = new ParametersWithIV(new KeyParameter(keydata), ivdata);
            ek.CipherData.CipherValue = (symKey == null ? EncryptedXml.EncryptKey(keydata, rsa, false) : EncryptedXml.EncryptKey(keydata, symKey));

            // Encrypt the input element with the random session key that we've created above.
            KeyInfoEncryptedKey kek = new KeyInfoEncryptedKey(ek);
            ed.KeyInfo.AddClause(kek);
            ed.CipherData.CipherValue = this.EncryptData(inputElement, rijn, false);

            return ed;
        }

        // decrypts the document using the defined key mapping in GetDecryptionKey
        // The behaviour of this method can be extended because GetDecryptionKey is virtual
        // the document is decrypted in place
        public void DecryptDocument()
        {
            // Look for all EncryptedData elements and decrypt them
            XmlNamespaceManager nsm = new XmlNamespaceManager(this._document.NameTable);
            nsm.AddNamespace(EncryptedXml.XmlEncNamespacePrefix, EncryptedXml.XmlEncNamespaceUrl);
            XmlNodeList encryptedDataList = this._document.SelectNodes("//" + EncryptedXml.XmlEncNamespacePrefix + ":EncryptedData", nsm);
            if (encryptedDataList != null)
            {
                foreach (XmlNode encryptedDataNode in encryptedDataList)
                {
                    XmlElement encryptedDataElement = encryptedDataNode as XmlElement;
                    EncryptedData ed = new EncryptedData();
                    ed.LoadXml(encryptedDataElement);
                    ICipherParameters symAlg = this.GetDecryptionKey(ed, null);
                    if (symAlg == null)
                    {
                        throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_MissingDecryptionKey);
                    }

                    Byte[] decrypted = this.DecryptData(ed, symAlg);
                    this.ReplaceData(encryptedDataElement, decrypted);
                }
            }
        }

        // encrypts the supplied arbitrary data
        public Byte[] EncryptData(Byte[] plaintext, ICipherParameters symmetricAlgorithm)
        {
            if (plaintext == null)
            {
                throw new ArgumentNullException(nameof(plaintext));
            }

            if (symmetricAlgorithm == null)
            {
                throw new ArgumentNullException(nameof(symmetricAlgorithm));
            }

            ParametersWithIV ivParam = symmetricAlgorithm as ParametersWithIV;
            KeyParameter keyParam = ivParam == null ? symmetricAlgorithm as KeyParameter : ivParam.Parameters as KeyParameter;

            IBufferedCipher enc;
            if (keyParam is DesEdeParameters)
            {
                enc = CipherUtilities.GetCipher($"DESede/{this._mode}/{this._padding}");
            }
            else if (keyParam is DesParameters)
            {
                enc = CipherUtilities.GetCipher($"DES/{this._mode}/{this._padding}");
            }
            else
            {
                enc = CipherUtilities.GetCipher($"AES/{this._mode}/{this._padding}");
            }

            enc.Init(true, symmetricAlgorithm);
            Byte[] cipher = enc.DoFinal(plaintext);

            Byte[] output = null;
            if (this._mode.Equals("ECB", StringComparison.OrdinalIgnoreCase))
            {
                output = cipher;
            }
            else
            {
                Byte[] IV = ((ParametersWithIV)symmetricAlgorithm).GetIV();
                output = new Byte[cipher.Length + IV.Length];
                Buffer.BlockCopy(IV, 0, output, 0, IV.Length);
                Buffer.BlockCopy(cipher, 0, output, IV.Length, cipher.Length);
            }
            return output;
        }

        // encrypts the supplied input element
        public Byte[] EncryptData(XmlElement inputElement, ICipherParameters symmetricAlgorithm, Boolean content)
        {
            if (inputElement == null)
            {
                throw new ArgumentNullException(nameof(inputElement));
            }

            if (symmetricAlgorithm == null)
            {
                throw new ArgumentNullException(nameof(symmetricAlgorithm));
            }

            Byte[] plainText = (content ? this._encoding.GetBytes(inputElement.InnerXml) : this._encoding.GetBytes(inputElement.OuterXml));
            return this.EncryptData(plainText, symmetricAlgorithm);
        }

        // decrypts the supplied EncryptedData
        public Byte[] DecryptData(EncryptedData encryptedData, ICipherParameters symmetricAlgorithm)
        {
            if (encryptedData == null)
            {
                throw new ArgumentNullException(nameof(encryptedData));
            }

            if (symmetricAlgorithm == null)
            {
                throw new ArgumentNullException(nameof(symmetricAlgorithm));
            }

            ParametersWithIV ivParam = symmetricAlgorithm as ParametersWithIV;
            KeyParameter keyParam = ivParam == null ? symmetricAlgorithm as KeyParameter : ivParam.Parameters as KeyParameter;

            // get the cipher value and decrypt
            Byte[] cipherValue = this.GetCipherValue(encryptedData.CipherData);

            // read the IV from cipherValue
            Byte[] decryptionIV = null;
            if (!this._mode.Equals("ECB", StringComparison.OrdinalIgnoreCase))
            {
                decryptionIV = this.GetDecryptionIV(encryptedData, null);
            }

            Byte[] output = null;
            Int32 lengthIV = 0;
            if (decryptionIV != null)
            {
                symmetricAlgorithm = new ParametersWithIV(keyParam, decryptionIV);
                lengthIV = decryptionIV.Length;
            }

            IBufferedCipher dec;
            if (keyParam is DesEdeParameters)
            {
                dec = CipherUtilities.GetCipher($"DESede/{this._mode}/{this._padding}");
            }
            else if (keyParam is DesParameters)
            {
                dec = CipherUtilities.GetCipher($"DES/{this._mode}/{this._padding}");
            }
            else
            {
                dec = CipherUtilities.GetCipher($"AES/{this._mode}/{this._padding}");
            }

            dec.Init(false, symmetricAlgorithm);
            output = dec.DoFinal(cipherValue, lengthIV, cipherValue.Length - lengthIV);

            return output;
        }

        // This method replaces an EncryptedData element with the decrypted sequence of bytes
        public void ReplaceData(XmlElement inputElement, Byte[] decryptedData)
        {
            if (inputElement == null)
            {
                throw new ArgumentNullException(nameof(inputElement));
            }

            if (decryptedData == null)
            {
                throw new ArgumentNullException(nameof(decryptedData));
            }

            XmlNode parent = inputElement.ParentNode;
            if (parent.NodeType == XmlNodeType.Document)
            {
                // We're replacing the root element, but we can't just wholesale replace the owner
                // document's InnerXml, since we need to preserve any other top-level XML elements (such as
                // comments or the XML entity declaration.  Instead, create a new document with the
                // decrypted XML, import it into the existing document, and replace just the root element.
                XmlDocument importDocument = new XmlDocument();
                importDocument.PreserveWhitespace = true;
                String decryptedString = this._encoding.GetString(decryptedData);
                using (StringReader sr = new StringReader(decryptedString))
                {
                    using (XmlReader xr = XmlReader.Create(sr, Utils.GetSecureXmlReaderSettings(this._xmlResolver)))
                    {
                        importDocument.Load(xr);
                    }
                }

                XmlNode importedNode = inputElement.OwnerDocument.ImportNode(importDocument.DocumentElement, true);

                parent.RemoveChild(inputElement);
                parent.AppendChild(importedNode);
            }
            else
            {
                XmlNode dummy = parent.OwnerDocument.CreateElement(parent.Prefix, parent.LocalName, parent.NamespaceURI);

                try
                {
                    parent.AppendChild(dummy);

                    // Replace the children of the dummy node with the sequence of bytes passed in.
                    // The string will be parsed into DOM objects in the context of the parent of the EncryptedData element.
                    dummy.InnerXml = this._encoding.GetString(decryptedData);

                    // Move the children of the dummy node up to the parent.
                    XmlNode child = dummy.FirstChild;
                    XmlNode sibling = inputElement.NextSibling;

                    XmlNode nextChild = null;
                    while (child != null)
                    {
                        nextChild = child.NextSibling;
                        parent.InsertBefore(child, sibling);
                        child = nextChild;
                    }
                }
                finally
                {
                    // Remove the dummy element.
                    parent.RemoveChild(dummy);
                }

                // Remove the EncryptedData element
                parent.RemoveChild(inputElement);
            }
        }

        //
        // public static methods
        //

        // replaces the inputElement with the provided EncryptedData
        public static void ReplaceElement(XmlElement inputElement, EncryptedData encryptedData, Boolean content)
        {
            if (inputElement == null)
            {
                throw new ArgumentNullException(nameof(inputElement));
            }

            if (encryptedData == null)
            {
                throw new ArgumentNullException(nameof(encryptedData));
            }

            // First, get the XML representation of the EncryptedData object
            XmlElement elemED = encryptedData.GetXml(inputElement.OwnerDocument);
            switch (content)
            {
                case true:
                    // remove all children of the input element
                    Utils.RemoveAllChildren(inputElement);
                    // then append the encrypted data as a child of the input element
                    inputElement.AppendChild(elemED);
                    break;
                case false:
                    XmlNode parentNode = inputElement.ParentNode;
                    // remove the input element from the containing document
                    parentNode.ReplaceChild(elemED, inputElement);
                    break;
            }
        }

        // wraps the supplied input key data using the provided symmetric algorithm
        public static Byte[] EncryptKey(Byte[] keyData, KeyParameter symmetricAlgorithm)
        {
            if (keyData == null)
            {
                throw new ArgumentNullException(nameof(keyData));
            }

            if (symmetricAlgorithm == null)
            {
                throw new ArgumentNullException(nameof(symmetricAlgorithm));
            }

            if (symmetricAlgorithm is DesParameters)
            {
                // CMS Triple DES Key Wrap
                return SymmetricKeyWrap.TripleDESKeyWrapEncrypt(symmetricAlgorithm.GetKey(), keyData);
            }
            else
            {
                // FIPS AES Key Wrap
                return SymmetricKeyWrap.AESKeyWrapEncrypt(symmetricAlgorithm.GetKey(), keyData);
            }
        }


        // encrypts the supplied input key data using an RSA key and specifies whether we want to use OAEP
        // padding or PKCS#1 v1.5 padding as described in the PKCS specification
        public static Byte[] EncryptKey(Byte[] keyData, RsaKeyParameters rsa, Boolean useOAEP)
        {
            if (keyData == null)
            {
                throw new ArgumentNullException(nameof(keyData));
            }

            if (rsa == null)
            {
                throw new ArgumentNullException(nameof(rsa));
            }

            if (useOAEP)
            {
                RSAOAEPKeyExchangeFormatter rsaFormatter = new RSAOAEPKeyExchangeFormatter(rsa);
                return rsaFormatter.CreateKeyExchange(keyData);
            }
            else
            {
                RSAPKCS1KeyExchangeFormatter rsaFormatter = new RSAPKCS1KeyExchangeFormatter(rsa);
                return rsaFormatter.CreateKeyExchange(keyData);
            }
        }

        // decrypts the supplied wrapped key using the provided symmetric algorithm
        public static Byte[] DecryptKey(Byte[] keyData, KeyParameter symmetricAlgorithm)
        {
            if (keyData == null)
            {
                throw new ArgumentNullException(nameof(keyData));
            }

            if (symmetricAlgorithm == null)
            {
                throw new ArgumentNullException(nameof(symmetricAlgorithm));
            }

            if (symmetricAlgorithm is DesParameters)
            {
                // CMS Triple DES Key Wrap
                return SymmetricKeyWrap.TripleDESKeyWrapDecrypt(symmetricAlgorithm.GetKey(), keyData);
            }
            else
            {
                // FIPS AES Key Wrap
                return SymmetricKeyWrap.AESKeyWrapDecrypt(symmetricAlgorithm.GetKey(), keyData);
            }
        }

        // decrypts the supplied data using an RSA key and specifies whether we want to use OAEP
        // padding or PKCS#1 v1.5 padding as described in the PKCS specification
        public static Byte[] DecryptKey(Byte[] keyData, RsaKeyParameters rsa, Boolean useOAEP)
        {
            if (keyData == null)
            {
                throw new ArgumentNullException(nameof(keyData));
            }

            if (rsa == null)
            {
                throw new ArgumentNullException(nameof(rsa));
            }

            if (useOAEP)
            {
                RSAOAEPKeyExchangeDeformatter rsaDeformatter = new RSAOAEPKeyExchangeDeformatter(rsa);
                return rsaDeformatter.DecryptKeyExchange(keyData);
            }
            else
            {
                RSAPKCS1KeyExchangeDeformatter rsaDeformatter = new RSAPKCS1KeyExchangeDeformatter(rsa);
                return rsaDeformatter.DecryptKeyExchange(keyData);
            }
        }
    }
}
