// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    public class ECKeyValue : KeyInfoClause
    {
        //private ECPublicKeyParameters _key;
        private NamedCurve _namedCurve = null;
        private ECPoint _publicKey = null;

        //
        // public constructors
        //
        

        public ECKeyValue() { }
        public ECKeyValue(NamedCurve namedCurve, ECPoint publicKey)
        {
            this._namedCurve = namedCurve;
            this._publicKey = publicKey;
        }

        /*
        public ECKeyValue(ECPublicKeyParameters key)
        {
            this._key = key;
        }

        public ECPublicKeyParameters Key
        {
            get
            {
                return this._key;
            }

            set
            {
                this._key = value;
            }
        }
        */

        //
        // public properties
        //

        public NamedCurve NamedCurve
        {
            get
            {
                return this._namedCurve;
            }

            set
            {
                this._namedCurve = value;
            }
        }

        public ECPoint PublicKey
        {
            get
            {
                return this._publicKey;
            }

            set
            {
                this._publicKey = value;
            }
        }


        //
        // public methods
        //

        /// <summary>
        /// Create an XML representation.
        /// </summary>
        /// <remarks>
        /// Based upon https://www.w3.org/TR/xmldsig-core/#sec-ECKeyValue
        /// </remarks>
        /// <returns>
        /// An <see cref="XmlElement"/> containing the XML representation.
        /// </returns>
        public override XmlElement GetXml()
        {
            XmlDocument xmlDocument = new XmlDocument
            {
                PreserveWhitespace = true
            };
            return this.GetXml(xmlDocument);
        }

        private const String KeyValueElementName = "KeyValue";
        private const String ECKeyValueElementName = "ECKeyValue";

        //Optional ECParameters - NamedCurve Choice
        private const String ECParametersElementName = "ECParameters";
        private const String NamedCurveElementName = "NamedCurve";

        //Optional Members
        private const String IdAttributeName = "Id";

        //Mandatory Members
        private const String PublicKeyElementName = "PublicKey";

        internal override XmlElement GetXml(XmlDocument xmlDocument)
        {
            XmlElement keyValueElement = xmlDocument.CreateElement(SignedXml.DefaultXmlDsigNamespacePrefix, KeyValueElementName, SignedXml.XmlDsigNamespaceUrl);
            XmlElement ecKeyValueElement = xmlDocument.CreateElement(SignedXml.DefaultXmlDsig11NamespacePrefix, ECKeyValueElementName, SignedXml.XmlDsig11NamespaceUrl);

            /*
            DerObjectIdentifier curveOid = this.FindECCurveOid(this._key);
            XmlElement namedCurveElement = xmlDocument.CreateElement(SignedXml.DefaultXmlDsig11NamespacePrefix, NamedCurveElementName, SignedXml.XmlDsig11NamespaceUrl);
            namedCurveElement.AppendChild(xmlDocument.CreateTextNode(String.Format("urn:oid:{0}", curveOid.ToString())));
            */
            if (this.NamedCurve != null)
            {
                XmlElement namedCurveElement = this.NamedCurve.GetXml(xmlDocument);
                ecKeyValueElement.AppendChild(namedCurveElement);
            }

            if (this.PublicKey != null)
            {
                /*
                XmlElement publicKeyElement = xmlDocument.CreateElement(SignedXml.DefaultXmlDsig11NamespacePrefix, PublicKeyElementName, SignedXml.XmlDsig11NamespaceUrl);
                publicKeyElement.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(this._key.Q.GetEncoded(false))));
                */
                XmlElement publicKey = this.PublicKey.GetXml(xmlDocument);
                XmlElement publicKeyElement = xmlDocument.CreateElement(SignedXml.DefaultXmlDsig11NamespacePrefix, PublicKeyElementName, SignedXml.XmlDsig11NamespaceUrl);
                foreach (XmlNode childElement in publicKey.ChildNodes)
                {
                    publicKeyElement.AppendChild(childElement);
                }
                ecKeyValueElement.AppendChild(publicKeyElement);
            }
            keyValueElement.AppendChild(ecKeyValueElement);

            return keyValueElement;
        }

        /// <summary>
        /// Deserialize from the XML representation.
        /// </summary>
        /// <remarks>
        /// Based upon https://www.w3.org/TR/xmldsig-core/#sec-ECKeyValue
        /// </remarks>
        /// <param name="value">
        /// An <see cref="XmlElement"/> containing the XML representation. This cannot be null.
        /// </param>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="value"/> cannot be null.
        /// </exception>
        /// <exception cref="CryptographicException">
        /// The XML has the incorrect schema or the EC parameters are invalid.
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
                throw new System.Security.Cryptography.CryptographicException($"Root element must be {KeyValueElementName} element in namepsace {SignedXml.XmlDsigNamespaceUrl}");
            }

            XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(value.OwnerDocument.NameTable);
            xmlNamespaceManager.AddNamespace(SignedXml.DefaultXmlDsigNamespacePrefix, SignedXml.XmlDsigNamespaceUrl);
            xmlNamespaceManager.AddNamespace(SignedXml.DefaultXmlDsig11NamespacePrefix, SignedXml.XmlDsig11NamespaceUrl);

            XmlNode ecKeyValueElement = value.SelectSingleNode($"{SignedXml.DefaultXmlDsig11NamespacePrefix}:{ECKeyValueElementName}", xmlNamespaceManager);
            if (ecKeyValueElement == null)
            {
                throw new System.Security.Cryptography.CryptographicException($"{KeyValueElementName} must contain child element {ECKeyValueElementName}");
            }

            XmlNode publicKeyNode = ecKeyValueElement.SelectSingleNode($"{SignedXml.DefaultXmlDsig11NamespacePrefix}:{PublicKeyElementName}", xmlNamespaceManager);
            if (publicKeyNode == null)
            {
                throw new System.Security.Cryptography.CryptographicException($"{PublicKeyElementName} is missing");
            }
            this.PublicKey = new ECPoint();
            this.PublicKey.LoadXml(publicKeyNode as XmlElement);
            //Byte[] publicKeyBytes = Convert.FromBase64String(publicKeyNode.InnerText);

            XmlNode ecParametersNode = ecKeyValueElement.SelectSingleNode($"{SignedXml.DefaultXmlDsig11NamespacePrefix}:{ECParametersElementName}", xmlNamespaceManager);
            XmlNode namedCurveNode = ecKeyValueElement.SelectSingleNode($"{SignedXml.DefaultXmlDsig11NamespacePrefix}:{NamedCurveElementName}", xmlNamespaceManager);

            if (ecParametersNode == null && namedCurveNode == null)
            {
                throw new System.Security.Cryptography.CryptographicException($"Either {ECParametersElementName} or {NamedCurveElementName} must exist!");
            }

            if (ecParametersNode != null && namedCurveNode != null)
            {
                throw new System.Security.Cryptography.CryptographicException($"Only {ECParametersElementName} or {NamedCurveElementName} must exist!");
            }

            try
            {
                if (namedCurveNode == null)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    this.NamedCurve = new NamedCurve();
                    this.NamedCurve.LoadXml(namedCurveNode as XmlElement);
                    //this.Key = this.CreatePublicKeyParams(publicKeyBytes, this.NamedCurve.Oid);
                }
            }
            catch (Exception ex)
            {
                throw new System.Security.Cryptography.CryptographicException($"An error occurred parsing the key components", ex);
            }
        }

        /*
        private ECPublicKeyParameters CreatePublicKeyParams(Byte[] publicKeyBytes, DerObjectIdentifier namedCurveOid)
        {
            X9ECParameters ecCurve = ECNamedCurveTable.GetByOid(namedCurveOid);
            ECDomainParameters domainParams = new ECDomainParameters(ecCurve);
            Byte[] decodedBytes;
            using (MemoryStream ms = new MemoryStream(publicKeyBytes))
            {
                Int32 first = ms.ReadByte();

                // Decode the public ephemeral key
                switch (first)
                {
                    case 0x00: // infinity
                        throw new IOException("Sender's public key invalid.");

                    case 0x02: // compressed
                    case 0x03: // Byte length calculated as in ECPoint.getEncoded();
                        decodedBytes = new Byte[1 + (domainParams.Curve.FieldSize + 7) / 8];
                        break;

                    case 0x04: // uncompressed or
                    case 0x06: // hybrid
                    case 0x07: // Byte length calculated as in ECPoint.getEncoded();
                        decodedBytes = new Byte[1 + 2 * ((domainParams.Curve.FieldSize + 7) / 8)];
                        break;

                    default:
                        throw new IOException("Sender's public key has invalid point encoding 0x" + publicKeyBytes[0].ToString("X2"));
                }

                decodedBytes[0] = (Byte)first;
                Streams.ReadFully(ms, decodedBytes, 1, decodedBytes.Length - 1);
            }
            ECPoint q = domainParams.Curve.DecodePoint(decodedBytes);
            return new ECPublicKeyParameters(q, domainParams);
        }
        */
    }
}
