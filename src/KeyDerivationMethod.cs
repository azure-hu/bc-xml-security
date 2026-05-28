namespace Org.BouncyCastle.Crypto.Xml
{
    using System;
    using System.Xml;

    public class KeyDerivationMethod : KeyInfoAgreementMethodClause
    {
        private String _algorithm = null;
        private KeyDerivationParamsClause _keyDerivationParams;

        public KeyDerivationMethod()
        {
            this.KeyDerivationParams = null;
        }

        public KeyDerivationMethod(String algorithm) : this()
        {
            this.Algorithm = algorithm;
        }

        //
        // public properties
        //

        public String Algorithm
        {
            get { return this._algorithm; }
            set { this._algorithm = value; }
        }

        public KeyDerivationParamsClause KeyDerivationParams
        {
            get { return this._keyDerivationParams; }
            private set { this._keyDerivationParams = value; }
        }

        public override XmlElement GetXml()
        {
            XmlDocument xmlDocument = new XmlDocument
            {
                PreserveWhitespace = true
            };
            return this.GetXml(xmlDocument);
        }

        internal override XmlElement GetXml(XmlDocument xmlDocument)
        {
            // Create the actual element
            XmlElement keyDerivationMethodElement = xmlDocument.CreateElement(EncryptedXml.DefaultXmlEnc11NamespacePrefix, "KeyDerivationMethod", EncryptedXml.XmlEnc11NamespaceUrl);

            if (!String.IsNullOrEmpty(this.Algorithm))
            {
                keyDerivationMethodElement.SetAttribute("Algorithm", this.Algorithm);
            }

            // Add the clause that go underneath it
            XmlElement xmlElement = this._keyDerivationParams.GetXml(xmlDocument);
            if (xmlElement != null)
            {
                keyDerivationMethodElement.AppendChild(xmlElement);
            }
            return keyDerivationMethodElement;
        }

        public override void LoadXml(XmlElement value)
        {
            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            XmlElement keyDerivationMethodElement = value;

            this.Algorithm = Utils.GetAttribute(value, "Algorithm", SignedXml.XmlDsigNamespaceUrl);

            XmlNode child = keyDerivationMethodElement.FirstChild;
            while (child != null)
            {
                XmlElement elem = child as XmlElement;
                if (elem != null)
                {
                    String kicString = elem.NamespaceURI + " " + elem.LocalName;

                    KeyDerivationParamsClause keyDerivationMethodClause = CryptoHelpers.CreateFromName<KeyDerivationParamsClause>(kicString);
                    // if we don't know what kind of KeyDerivationMethodClause we're looking at, use a generic KeyInfoNode:
                    if (keyDerivationMethodClause == null)
                    {
                        keyDerivationMethodClause = new KeyDerivationParamsNode();
                    }

                    // Ask the create clause to fill itself with the corresponding XML
                    keyDerivationMethodClause.LoadXml(elem);
                    // Add it to our list of KeyInfoClauses
                    this.AddParamsClause(keyDerivationMethodClause);
                }
                child = child.NextSibling;
            }
        }

        public Boolean AddParamsClause(KeyDerivationParamsClause clause)
        {
            if (this.KeyDerivationParams == null)
            {
                this.KeyDerivationParams = clause;
                return true;
            }
            return false;
        }
    }
}
