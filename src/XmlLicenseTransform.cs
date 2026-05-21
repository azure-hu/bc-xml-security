// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.IO;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    public class XmlLicenseTransform : Transform
    {
        private readonly Type[] _inputTypes = { typeof(XmlDocument) };
        private readonly Type[] _outputTypes = { typeof(XmlDocument) };
        private XmlNamespaceManager _namespaceManager = null;
        private XmlDocument _license = null;
        private IRelDecryptor _relDecryptor = null;
        private const String ElementIssuer = "issuer";
        private const String NamespaceUriCore = "urn:mpeg:mpeg21:2003:01-REL-R-NS";

        public XmlLicenseTransform()
        {
            this.Algorithm = SignedXml.XmlLicenseTransformUrl;
        }

        public override Type[] InputTypes
        {
            get { return this._inputTypes; }
        }

        public override Type[] OutputTypes
        {
            get { return this._outputTypes; }
        }

        public IRelDecryptor Decryptor
        {
            get { return this._relDecryptor; }
            set { this._relDecryptor = value; }
        }

        private void DecryptEncryptedGrants(XmlNodeList encryptedGrantList, IRelDecryptor decryptor)
        {
            XmlElement encryptionMethod = null;
            XmlElement keyInfo = null;
            XmlElement cipherData = null;
            EncryptionMethod encryptionMethodObj = null;
            KeyInfo keyInfoObj = null;
            CipherData cipherDataObj = null;

            for (Int32 i = 0, count = encryptedGrantList.Count; i < count; i++)
            {
                encryptionMethod = encryptedGrantList[i].SelectSingleNode("//r:encryptedGrant/" + EncryptedXml.XmlEncNamespacePrefix + ":EncryptionMethod", this._namespaceManager) as XmlElement;
                keyInfo = encryptedGrantList[i].SelectSingleNode("//r:encryptedGrant/" + SignedXml.XmlDsigNamespacePrefix + ":KeyInfo", this._namespaceManager) as XmlElement;
                cipherData = encryptedGrantList[i].SelectSingleNode("//r:encryptedGrant/" + EncryptedXml.XmlEncNamespacePrefix + ":CipherData", this._namespaceManager) as XmlElement;
                if ((encryptionMethod != null) &&
                    (keyInfo != null) &&
                    (cipherData != null))
                {
                    encryptionMethodObj = new EncryptionMethod();
                    keyInfoObj = new KeyInfo();
                    cipherDataObj = new CipherData();

                    encryptionMethodObj.LoadXml(encryptionMethod);
                    keyInfoObj.LoadXml(keyInfo);
                    cipherDataObj.LoadXml(cipherData);

                    MemoryStream toDecrypt = null;
                    Stream decryptedContent = null;
                    StreamReader streamReader = null;

                    try
                    {
                        toDecrypt = new MemoryStream(cipherDataObj.CipherValue);
                        decryptedContent = this._relDecryptor.Decrypt(encryptionMethodObj,
                                                                keyInfoObj, toDecrypt);

                        if ((decryptedContent == null) || (decryptedContent.Length == 0))
                        {
                            throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_XrmlUnableToDecryptGrant);
                        }

                        streamReader = new StreamReader(decryptedContent);
                        String clearContent = streamReader.ReadToEnd();

                        encryptedGrantList[i].ParentNode.InnerXml = clearContent;
                    }
                    finally
                    {
                        if (toDecrypt != null)
                        {
                            toDecrypt.Close();
                        }

                        if (decryptedContent != null)
                        {
                            decryptedContent.Close();
                        }

                        if (streamReader != null)
                        {
                            streamReader.Close();
                        }
                    }

                    encryptionMethodObj = null;
                    keyInfoObj = null;
                    cipherDataObj = null;
                }

                encryptionMethod = null;
                keyInfo = null;
                cipherData = null;
            }
        }

        // License transform has no inner XML elements
        protected override XmlNodeList GetInnerXml()
        {
            return null;
        }

        public override Object GetOutput()
        {
            return this._license;
        }

        public override Object GetOutput(Type type)
        {
            if ((type != typeof(XmlDocument)) && (!type.IsSubclassOf(typeof(XmlDocument))))
            {
                throw new ArgumentException(SR.Cryptography_Xml_TransformIncorrectInputType, nameof(type));
            }

            return this.GetOutput();
        }

        // License transform has no inner XML elements
        public override void LoadInnerXml(XmlNodeList nodeList)
        {
            if (nodeList != null && nodeList.Count > 0)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_UnknownTransform);
            }
        }

        public override void LoadInput(Object obj)
        {
            // Check if the Context property is set before this transform is invoked.
            if (this.Context == null)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_XrmlMissingContext);
            }

            this._license = new XmlDocument();
            this._license.PreserveWhitespace = true;
            this._namespaceManager = new XmlNamespaceManager(this._license.NameTable);
            this._namespaceManager.AddNamespace(SignedXml.XmlDsigNamespacePrefix, SignedXml.XmlDsigNamespaceUrl);
            this._namespaceManager.AddNamespace(EncryptedXml.XmlEncNamespacePrefix, EncryptedXml.XmlEncNamespaceUrl);
            this._namespaceManager.AddNamespace("r", NamespaceUriCore);

            XmlElement currentIssuerContext = null;
            XmlElement currentLicenseContext = null;
            XmlNode signatureNode = null;

            // Get the nearest issuer node
            currentIssuerContext = this.Context.SelectSingleNode("ancestor-or-self::r:issuer[1]", this._namespaceManager) as XmlElement;
            if (currentIssuerContext == null)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_XrmlMissingIssuer);
            }

            signatureNode = currentIssuerContext.SelectSingleNode("descendant-or-self::" + SignedXml.XmlDsigNamespacePrefix + ":Signature[1]", this._namespaceManager) as XmlElement;
            if (signatureNode != null)
            {
                signatureNode.ParentNode.RemoveChild(signatureNode);
            }

            // Get the nearest license node
            currentLicenseContext = currentIssuerContext.SelectSingleNode("ancestor-or-self::r:license[1]", this._namespaceManager) as XmlElement;
            if (currentLicenseContext == null)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_XrmlMissingLicence);
            }

            XmlNodeList issuerList = currentLicenseContext.SelectNodes("descendant-or-self::r:license[1]/r:issuer", this._namespaceManager);

            // Remove all issuer nodes except current
            for (Int32 i = 0, count = issuerList.Count; i < count; i++)
            {
                if (issuerList[i] == currentIssuerContext)
                {
                    continue;
                }

                if ((issuerList[i].LocalName == ElementIssuer) &&
                    (issuerList[i].NamespaceURI == NamespaceUriCore))
                {
                    issuerList[i].ParentNode.RemoveChild(issuerList[i]);
                }
            }

            XmlNodeList encryptedGrantList = currentLicenseContext.SelectNodes("/r:license/r:grant/r:encryptedGrant", this._namespaceManager);

            if (encryptedGrantList.Count > 0)
            {
                if (this._relDecryptor == null)
                {
                    throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_XrmlMissingIRelDecryptor);
                }

                this.DecryptEncryptedGrants(encryptedGrantList, this._relDecryptor);
            }

            this._license.InnerXml = currentLicenseContext.OuterXml;
        }
    }
}
