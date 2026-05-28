namespace Org.BouncyCastle.Crypto.Xml
{
    using Org.BouncyCastle.Asn1;
    using Org.BouncyCastle.Asn1.X9;
    using Org.BouncyCastle.Crypto.Parameters;
    using System;
    using System.Xml;

    public class NamedCurve
    {
        private DerObjectIdentifier curveOid = null;
        private const String CurveOidUriPrefix = "urn:oid:";
        private const String namedCurveElementName = "NamedCurve";

        //
        // public constructors
        //

        public NamedCurve() { }

        public NamedCurve(String namedCurveOid)
        {
            this.URI = namedCurveOid;
        }

        //
        // public properties
        //

        public String URI
        {
            get { return String.Concat(CurveOidUriPrefix, this.curveOid.Id); }
            set
            {
                Int32 startIndex = 0;
                if (value.StartsWith(CurveOidUriPrefix))
                {
                    startIndex = CurveOidUriPrefix.Length;
                }

                this.curveOid = new DerObjectIdentifier(value.Substring(startIndex));
                if (Asn1.X9.ECNamedCurveTable.GetByOid(this.curveOid) == null)
                {
                    this.curveOid = null;
                    throw new System.Security.Cryptography.CryptographicException($"Invalid named curve OID: \'{value}\'");
                }
            }
        }

        internal DerObjectIdentifier Oid
        {
            get { return this.curveOid; }
        }

        public static DerObjectIdentifier FindECCurveOid(ECPublicKeyParameters publicKey)
        {
            DerObjectIdentifier curveOid = null;
            ECDomainParameters pubKeyDomainParams = publicKey.Parameters;
            foreach (String curveName in ECNamedCurveTable.Names)
            {
                X9ECParameters curveParams = ECNamedCurveTable.GetByName(curveName);
                if (curveParams.Curve.Equals(pubKeyDomainParams.Curve)
                     && curveParams.G.Equals(pubKeyDomainParams.G)
                     && curveParams.H.Equals(pubKeyDomainParams.H)
                     && curveParams.N.Equals(pubKeyDomainParams.N))
                {
                    curveOid = ECNamedCurveTable.GetOid(curveName);
                }
            }

            return curveOid;
        }

        public XmlElement GetXml()
        {
            XmlDocument xmlDocument = new XmlDocument();
            xmlDocument.PreserveWhitespace = true;
            return this.GetXml(xmlDocument);

        }

        internal XmlElement GetXml(XmlDocument document)
        {

            XmlElement namedCurveElement = (XmlElement)document.CreateElement(SignedXml.DefaultXmlDsig11NamespacePrefix, namedCurveElementName, SignedXml.XmlDsig11NamespaceUrl);
            if (this.curveOid != null)
            {
                namedCurveElement.SetAttribute("URI", this.URI);
            }

            return namedCurveElement;
        }

        public void LoadXml(XmlElement value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }
            if (value.LocalName != namedCurveElementName || value.NamespaceURI != SignedXml.XmlDsig11NamespaceUrl)
            {
                throw new System.Security.Cryptography.CryptographicException($"Root element must be {namedCurveElementName} element in namepsace {SignedXml.XmlDsig11NamespaceUrl}");
            }

            this.URI = value.GetAttribute("URI");
        }

    }
}
