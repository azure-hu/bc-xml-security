// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    public class RSAKeyValue : KeyInfoClause
    {
        private RsaKeyParameters _key;

        //
        // public constructors
        //

        public RSAKeyValue()
        {
            AsymmetricCipherKeyPair pair = Utils.RSAGenerateKeyPair();
            this._key = (RsaKeyParameters)pair.Public;
        }

        public RSAKeyValue(RsaKeyParameters key)
        {
            this._key = key;
        }

        //
        // public properties
        //

        public RsaKeyParameters Key
        {
            get { return this._key; }
            set { this._key = value; }
        }

        //
        // public methods
        //

        /// <summary>
        /// Create an XML representation.
        /// </summary>
        /// <remarks>
        /// Based upon https://www.w3.org/TR/xmldsig-core/#sec-RSAKeyValue.
        /// </remarks>
        /// <returns>
        /// An <see cref="XmlElement"/> containing the XML representation.
        /// </returns>
        public override XmlElement GetXml()
        {
            XmlDocument xmlDocument = new XmlDocument();
            xmlDocument.PreserveWhitespace = true;
            return this.GetXml(xmlDocument);
        }

        private const String KeyValueElementName = "KeyValue";
        private const String RSAKeyValueElementName = "RSAKeyValue";
        private const String ModulusElementName = "Modulus";
        private const String ExponentElementName = "Exponent";

        internal override XmlElement GetXml(XmlDocument xmlDocument)
        {
            XmlElement keyValueElement = xmlDocument.CreateElement(SignedXml.DefaultXmlDsigNamespacePrefix, KeyValueElementName, SignedXml.XmlDsigNamespaceUrl);
            XmlElement rsaKeyValueElement = xmlDocument.CreateElement(SignedXml.DefaultXmlDsigNamespacePrefix, RSAKeyValueElementName, SignedXml.XmlDsigNamespaceUrl);

            XmlElement modulusElement = xmlDocument.CreateElement(SignedXml.DefaultXmlDsigNamespacePrefix, ModulusElementName, SignedXml.XmlDsigNamespaceUrl);
            modulusElement.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(this._key.Modulus.ToByteArrayUnsigned())));
            rsaKeyValueElement.AppendChild(modulusElement);

            XmlElement exponentElement = xmlDocument.CreateElement(SignedXml.DefaultXmlDsigNamespacePrefix, ExponentElementName, SignedXml.XmlDsigNamespaceUrl);
            exponentElement.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(this._key.Exponent.ToByteArrayUnsigned())));
            rsaKeyValueElement.AppendChild(exponentElement);

            keyValueElement.AppendChild(rsaKeyValueElement);

            return keyValueElement;
        }

        /// <summary>
        /// Deserialize from the XML representation.
        /// </summary>
        /// <remarks>
        /// Based upon https://www.w3.org/TR/xmldsig-core/#sec-RSAKeyValue.
        /// </remarks>
        /// <param name="value">
        /// An <see cref="XmlElement"/> containing the XML representation. This cannot be null.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="value"/> cannot be null.
        /// </exception>
        /// <exception cref="CryptographicException">
        /// The XML has the incorrect schema or the RSA parameters are invalid.
        /// </exception>
        public override void LoadXml(XmlElement value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if (value.LocalName != KeyValueElementName
                || value.NamespaceURI != SignedXml.XmlDsigNamespaceUrl)
            {
                throw new System.Security.Cryptography.CryptographicException($"Root element must be {KeyValueElementName} element in namespace {SignedXml.XmlDsigNamespaceUrl}");
            }

            XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(value.OwnerDocument.NameTable);
            xmlNamespaceManager.AddNamespace(SignedXml.DefaultXmlDsigNamespacePrefix, SignedXml.XmlDsigNamespaceUrl);

            XmlNode rsaKeyValueElement = value.SelectSingleNode($"{SignedXml.DefaultXmlDsigNamespacePrefix}:{RSAKeyValueElementName}", xmlNamespaceManager);
            if (rsaKeyValueElement == null)
            {
                throw new System.Security.Cryptography.CryptographicException($"{KeyValueElementName} must contain child element {RSAKeyValueElementName}");
            }

            try
            {
                this._key = new RsaKeyParameters(false,
                    new Math.BigInteger(1, Convert.FromBase64String(rsaKeyValueElement.SelectSingleNode($"{SignedXml.DefaultXmlDsigNamespacePrefix}:{ModulusElementName}", xmlNamespaceManager).InnerText)),
                    new Math.BigInteger(1, Convert.FromBase64String(rsaKeyValueElement.SelectSingleNode($"{SignedXml.DefaultXmlDsigNamespacePrefix}:{ExponentElementName}", xmlNamespaceManager).InnerText)));
            }
            catch (Exception ex)
            {
                throw new System.Security.Cryptography.CryptographicException($"An error occurred parsing the {ModulusElementName} and {ExponentElementName} elements", ex);
            }
        }
    }
}
