namespace Org.BouncyCastle.Crypto.Xml
{
    using System;
    using System.Xml;

    public class ECPoint
    {
        private Byte[] _binaryData = null;


        //
        // public constructors
        //

        public ECPoint() { }
        public ECPoint(Byte[] ecPoint)
        {
            this._binaryData = ecPoint;
        }


        //
        // public properties
        //

        public Byte[] Data
        {
            get
            {
                return this._binaryData;
            }

            set
            {
                this._binaryData = value;
            }
        }

        public XmlElement GetXml()
        {
            XmlDocument xmlDocument = new XmlDocument
            {
                PreserveWhitespace = true
            };
            return this.GetXml(xmlDocument);
        }

        internal XmlElement GetXml(XmlDocument xmlDocument)
        {
            XmlElement ecPointElement = xmlDocument.CreateElement(SignedXml.DefaultXmlDsig11NamespacePrefix, "ECPoint", SignedXml.XmlDsig11NamespaceUrl);

            if (this.Data != null)
            {
                ecPointElement.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(this.Data)));
            }

            return ecPointElement;
        }

        public void LoadXml(XmlElement value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            this.Data = Convert.FromBase64String(value.InnerText);
        }
    }
}
