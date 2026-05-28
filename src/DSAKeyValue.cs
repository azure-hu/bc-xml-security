// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    public class DSAKeyValue : KeyInfoClause
    {
        private DsaPublicKeyParameters _key;

        //
        // public constructors
        //

        public DSAKeyValue()
        {
            AsymmetricCipherKeyPair pair = Utils.DSAGenerateKeyPair();
            this._key = (DsaPublicKeyParameters)pair.Public;
        }

        public DSAKeyValue(DsaPublicKeyParameters key)
        {
            this._key = key;
        }

        //
        // public properties
        //

        public DsaPublicKeyParameters Key
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
        /// Based upon https://www.w3.org/TR/xmldsig-core/#sec-DSAKeyValue.
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
        private const String DSAKeyValueElementName = "DSAKeyValue";

        //Optional {P,Q}-Sequence
        private const String PElementName = "P";
        private const String QElementName = "Q";

        //Optional Members
        private const String GElementName = "G";
        private const String JElementName = "J";

        //Mandatory Members
        private const String YElementName = "Y";

        //Optional {Seed,PgenCounter}-Sequence
        private const String SeedElementName = "Seed";
        private const String PgenCounterElementName = "PgenCounter";

        internal override XmlElement GetXml(XmlDocument xmlDocument)
        {
            XmlElement keyValueElement = xmlDocument.CreateElement(SignedXml.DefaultXmlDsigNamespacePrefix, KeyValueElementName, SignedXml.XmlDsigNamespaceUrl);
            XmlElement dsaKeyValueElement = xmlDocument.CreateElement(SignedXml.DefaultXmlDsigNamespacePrefix, DSAKeyValueElementName, SignedXml.XmlDsigNamespaceUrl);

            XmlElement pElement = xmlDocument.CreateElement(SignedXml.DefaultXmlDsigNamespacePrefix, PElementName, SignedXml.XmlDsigNamespaceUrl);
            pElement.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(this._key.Parameters.P.ToByteArrayUnsigned())));
            dsaKeyValueElement.AppendChild(pElement);

            XmlElement qElement = xmlDocument.CreateElement(SignedXml.DefaultXmlDsigNamespacePrefix, QElementName, SignedXml.XmlDsigNamespaceUrl);
            qElement.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(this._key.Parameters.Q.ToByteArrayUnsigned())));
            dsaKeyValueElement.AppendChild(qElement);

            XmlElement gElement = xmlDocument.CreateElement(SignedXml.DefaultXmlDsigNamespacePrefix, GElementName, SignedXml.XmlDsigNamespaceUrl);
            gElement.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(this._key.Parameters.G.ToByteArrayUnsigned())));
            dsaKeyValueElement.AppendChild(gElement);

            XmlElement yElement = xmlDocument.CreateElement(SignedXml.DefaultXmlDsigNamespacePrefix, YElementName, SignedXml.XmlDsigNamespaceUrl);
            yElement.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(this._key.Y.ToByteArrayUnsigned())));
            dsaKeyValueElement.AppendChild(yElement);

            // Add optional components if present
            /*if (dsaParams.J != null)
            {
                XmlElement jElement = xmlDocument.CreateElement(SignedXml.DefaultXmlDsigNamespacePrefix, JElementName, SignedXml.XmlDsigNamespaceUrl);
                jElement.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(dsaParams.J)));
                dsaKeyValueElement.AppendChild(jElement);
            }*/

            if (this._key.Parameters.ValidationParameters != null)
            {  // note we assume counter is correct if Seed is present
                XmlElement seedElement = xmlDocument.CreateElement(SignedXml.DefaultXmlDsigNamespacePrefix, SeedElementName, SignedXml.XmlDsigNamespaceUrl);
                seedElement.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(this._key.Parameters.ValidationParameters.GetSeed())));
                dsaKeyValueElement.AppendChild(seedElement);

                XmlElement counterElement = xmlDocument.CreateElement(SignedXml.DefaultXmlDsigNamespacePrefix, PgenCounterElementName, SignedXml.XmlDsigNamespaceUrl);
                counterElement.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(Utils.ConvertIntToByteArray(this._key.Parameters.ValidationParameters.Counter))));
                dsaKeyValueElement.AppendChild(counterElement);
            }

            keyValueElement.AppendChild(dsaKeyValueElement);

            return keyValueElement;
        }

        /// <summary>
        /// Deserialize from the XML representation.
        /// </summary>
        /// <remarks>
        /// Based upon https://www.w3.org/TR/xmldsig-core/#sec-DSAKeyValue.
        /// </remarks>
        /// <param name="value">
        /// An <see cref="XmlElement"/> containing the XML representation. This cannot be null.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="value"/> cannot be null.
        /// </exception>
        /// <exception cref="CryptographicException">
        /// The XML has the incorrect schema or the DSA parameters are invalid.
        /// </exception>
        public override void LoadXml(XmlElement value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if (value.Name != KeyValueElementName
                || value.NamespaceURI != SignedXml.XmlDsigNamespaceUrl)
            {
                throw new System.Security.Cryptography.CryptographicException($"Root element must be {KeyValueElementName} element in namepsace {SignedXml.XmlDsigNamespaceUrl}");
            }

            XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(value.OwnerDocument.NameTable);
            xmlNamespaceManager.AddNamespace(SignedXml.DefaultXmlDsigNamespacePrefix, SignedXml.XmlDsigNamespaceUrl);

            XmlNode dsaKeyValueElement = value.SelectSingleNode($"{SignedXml.DefaultXmlDsigNamespacePrefix}:{DSAKeyValueElementName}", xmlNamespaceManager);
            if (dsaKeyValueElement == null)
            {
                throw new System.Security.Cryptography.CryptographicException($"{KeyValueElementName} must contain child element {DSAKeyValueElementName}");
            }

            XmlNode yNode = dsaKeyValueElement.SelectSingleNode($"{SignedXml.DefaultXmlDsigNamespacePrefix}:{YElementName}", xmlNamespaceManager);
            if (yNode == null)
            {
                throw new System.Security.Cryptography.CryptographicException($"{YElementName} is missing");
            }

            XmlNode pNode = dsaKeyValueElement.SelectSingleNode($"{SignedXml.DefaultXmlDsigNamespacePrefix}:{PElementName}", xmlNamespaceManager);
            XmlNode qNode = dsaKeyValueElement.SelectSingleNode($"{SignedXml.DefaultXmlDsigNamespacePrefix}:{QElementName}", xmlNamespaceManager);

            if ((pNode == null && qNode != null) || (pNode != null && qNode == null))
            {
                throw new System.Security.Cryptography.CryptographicException($"{PElementName} and {QElementName} can only occour in combination");
            }

            XmlNode gNode = dsaKeyValueElement.SelectSingleNode($"{SignedXml.DefaultXmlDsigNamespacePrefix}:{GElementName}", xmlNamespaceManager);
            XmlNode jNode = dsaKeyValueElement.SelectSingleNode($"{SignedXml.DefaultXmlDsigNamespacePrefix}:{JElementName}", xmlNamespaceManager);

            XmlNode seedNode = dsaKeyValueElement.SelectSingleNode($"{SignedXml.DefaultXmlDsigNamespacePrefix}:{SeedElementName}", xmlNamespaceManager);
            XmlNode pgenCounterNode = dsaKeyValueElement.SelectSingleNode($"{SignedXml.DefaultXmlDsigNamespacePrefix}:{PgenCounterElementName}", xmlNamespaceManager);
            if ((seedNode == null && pgenCounterNode != null) || (seedNode != null && pgenCounterNode == null))
            {
                throw new System.Security.Cryptography.CryptographicException($"{SeedElementName} and {PgenCounterElementName} can only occur in combination");
            }

            try
            {
                this._key = new DsaPublicKeyParameters(new Math.BigInteger(1, Convert.FromBase64String(yNode.InnerText)),
                    new DsaParameters(
                        new Math.BigInteger(1, (pNode != null) ? Convert.FromBase64String(pNode.InnerText) : null),
                        new Math.BigInteger(1, (qNode != null) ? Convert.FromBase64String(qNode.InnerText) : null),
                        new Math.BigInteger(1, (gNode != null) ? Convert.FromBase64String(gNode.InnerText) : null),
                        new DsaValidationParameters(
                            (seedNode != null) ? Convert.FromBase64String(seedNode.InnerText) : null,
                            (pgenCounterNode != null) ? Utils.ConvertByteArrayToInt(Convert.FromBase64String(pgenCounterNode.InnerText)) : 0)));
            }
            catch (Exception ex)
            {
                throw new System.Security.Cryptography.CryptographicException($"An error occurred parsing the key components", ex);
            }
        }
    }
}
