// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    public class KeyInfoX509Data : KeyInfoClause
    {
        // An array of certificates representing the certificate chain
        private ArrayList _certificates = null;
        // An array of issuer serial structs
        private ArrayList _issuerSerials = null;
        // An array of SKIs
        private ArrayList _subjectKeyIds = null;
        // An array of subject names
        private ArrayList _subjectNames = null;
        // A raw byte data representing a certificate revocation list
        private Byte[] _CRL = null;

        //
        // public constructors
        //

        public KeyInfoX509Data() { }

        public KeyInfoX509Data(Byte[] rgbCert)
        {
            if (rgbCert != null)
            {
                X509CertificateParser parser = new X509CertificateParser();
                this.AddCertificate(parser.ReadCertificate(rgbCert));
            }
        }

        public KeyInfoX509Data(X509Certificate cert)
        {
            this.AddCertificate(Utils.CloneCertificate(cert));
        }

        public KeyInfoX509Data(X509Certificate cert, IEnumerable<X509Certificate> additional, X509IncludeOption includeOption)
        {
            if (cert == null)
            {
                throw new ArgumentNullException(nameof(cert));
            }

            X509Certificate certificate = Utils.CloneCertificate(cert);
            IList<X509Certificate> chain = null;
            switch (includeOption)
            {
                case X509IncludeOption.ExcludeRoot:
                    // Build the certificate chain
                    chain = Utils.BuildCertificateChain(cert, additional);

                    // Can't honor the option if we only have a partial chain.
                    /*if ((chain.ChainStatus.Length > 0) &&
                        ((chain.ChainStatus[0].Status & X509ChainStatusFlags.PartialChain) == X509ChainStatusFlags.PartialChain))
                    {
                        throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Partial_Chain);
                    }*/

                    for (Int32 index = 0; index < (Utils.IsSelfSigned(chain) ? 1 : chain.Count - 1); index++)
                    {
                        this.AddCertificate(chain[index]);
                    }
                    break;
                case X509IncludeOption.EndCertOnly:
                    this.AddCertificate(certificate);
                    break;
                case X509IncludeOption.WholeChain:
                    // Build the certificate chain
                    chain = Utils.BuildCertificateChain(cert, additional);

                    // Can't honor the option if we only have a partial chain.
                    /*if ((chain.ChainStatus.Length > 0) &&
                        ((chain.ChainStatus[0].Status & X509ChainStatusFlags.PartialChain) == X509ChainStatusFlags.PartialChain))
                    {
                        throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Partial_Chain);
                    }*/

                    foreach (X509Certificate element in chain)
                    {
                        this.AddCertificate(element);
                    }
                    break;
            }
        }

        //
        // public properties
        //

        public ArrayList Certificates
        {
            get { return this._certificates; }
        }

        public void AddCertificate(X509Certificate certificate)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            if (this._certificates == null)
            {
                this._certificates = new ArrayList();
            }

            X509Certificate x509 = certificate;
            this._certificates.Add(x509);
        }

        public ArrayList SubjectKeyIds
        {
            get { return this._subjectKeyIds; }
        }

        public void AddSubjectKeyId(Byte[] subjectKeyId)
        {
            if (this._subjectKeyIds == null)
            {
                this._subjectKeyIds = new ArrayList();
            }

            this._subjectKeyIds.Add(subjectKeyId);
        }

        public void AddSubjectKeyId(String subjectKeyId)
        {
            if (this._subjectKeyIds == null)
            {
                this._subjectKeyIds = new ArrayList();
            }

            this._subjectKeyIds.Add(Utils.DecodeHexString(subjectKeyId));
        }

        public ArrayList SubjectNames
        {
            get { return this._subjectNames; }
        }

        public void AddSubjectName(String subjectName)
        {
            if (this._subjectNames == null)
            {
                this._subjectNames = new ArrayList();
            }

            this._subjectNames.Add(subjectName);
        }

        public ArrayList IssuerSerials
        {
            get { return this._issuerSerials; }
        }

        public void AddIssuerSerial(String issuerName, String serialNumber)
        {
            if (String.IsNullOrEmpty(issuerName))
            {
                throw new ArgumentException(SR.Arg_EmptyOrNullString, nameof(issuerName));
            }

            if (String.IsNullOrEmpty(serialNumber))
            {
                throw new ArgumentException(SR.Arg_EmptyOrNullString, nameof(serialNumber));
            }

            BigInteger h;
            try
            {
                h = new BigInteger(serialNumber);
            }
            catch (Exception)
            {
                throw new ArgumentException(SR.Cryptography_Xml_InvalidX509IssuerSerialNumber, nameof(serialNumber));
            }

            if (this._issuerSerials == null)
            {
                this._issuerSerials = new ArrayList();
            }

            this._issuerSerials.Add(Utils.CreateX509IssuerSerial(issuerName, h.ToString()));
        }

        // When we load an X509Data from Xml, we know the serial number is in decimal representation.
        internal void InternalAddIssuerSerial(String issuerName, String serialNumber)
        {
            if (this._issuerSerials == null)
            {
                this._issuerSerials = new ArrayList();
            }

            this._issuerSerials.Add(Utils.CreateX509IssuerSerial(issuerName, serialNumber));
        }

        public Byte[] CRL
        {
            get { return this._CRL; }
            set { this._CRL = value; }
        }

        //
        // private methods
        //

        private void Clear()
        {
            this._CRL = null;
            if (this._subjectKeyIds != null)
            {
                this._subjectKeyIds.Clear();
            }

            if (this._subjectNames != null)
            {
                this._subjectNames.Clear();
            }

            if (this._issuerSerials != null)
            {
                this._issuerSerials.Clear();
            }

            if (this._certificates != null)
            {
                this._certificates.Clear();
            }
        }

        //
        // public methods
        //

        public override XmlElement GetXml()
        {
            XmlDocument xmlDocument = new XmlDocument();
            xmlDocument.PreserveWhitespace = true;
            return this.GetXml(xmlDocument);
        }

        internal override XmlElement GetXml(XmlDocument xmlDocument)
        {
            XmlElement x509DataElement = xmlDocument.CreateElement(SignedXml.XmlDsigNamespacePrefix, "X509Data", SignedXml.XmlDsigNamespaceUrl);

            if (this._issuerSerials != null)
            {
                foreach (X509IssuerSerial issuerSerial in this._issuerSerials)
                {
                    XmlElement issuerSerialElement = xmlDocument.CreateElement(SignedXml.XmlDsigNamespacePrefix, "X509IssuerSerial", SignedXml.XmlDsigNamespaceUrl);
                    XmlElement issuerNameElement = xmlDocument.CreateElement(SignedXml.XmlDsigNamespacePrefix, "X509IssuerName", SignedXml.XmlDsigNamespaceUrl);
                    issuerNameElement.AppendChild(xmlDocument.CreateTextNode(issuerSerial.IssuerName));
                    issuerSerialElement.AppendChild(issuerNameElement);
                    XmlElement serialNumberElement = xmlDocument.CreateElement(SignedXml.XmlDsigNamespacePrefix, "X509SerialNumber", SignedXml.XmlDsigNamespaceUrl);
                    serialNumberElement.AppendChild(xmlDocument.CreateTextNode(issuerSerial.SerialNumber));
                    issuerSerialElement.AppendChild(serialNumberElement);
                    x509DataElement.AppendChild(issuerSerialElement);
                }
            }

            if (this._subjectKeyIds != null)
            {
                foreach (Byte[] subjectKeyId in this._subjectKeyIds)
                {
                    XmlElement subjectKeyIdElement = xmlDocument.CreateElement(SignedXml.XmlDsigNamespacePrefix, "X509SKI", SignedXml.XmlDsigNamespaceUrl);
                    subjectKeyIdElement.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(subjectKeyId)));
                    x509DataElement.AppendChild(subjectKeyIdElement);
                }
            }

            if (this._subjectNames != null)
            {
                foreach (String subjectName in this._subjectNames)
                {
                    XmlElement subjectNameElement = xmlDocument.CreateElement(SignedXml.XmlDsigNamespacePrefix, "X509SubjectName", SignedXml.XmlDsigNamespaceUrl);
                    subjectNameElement.AppendChild(xmlDocument.CreateTextNode(subjectName));
                    x509DataElement.AppendChild(subjectNameElement);
                }
            }

            if (this._certificates != null)
            {
                foreach (X509Certificate certificate in this._certificates)
                {
                    XmlElement x509Element = xmlDocument.CreateElement(SignedXml.XmlDsigNamespacePrefix, "X509Certificate", SignedXml.XmlDsigNamespaceUrl);
                    x509Element.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(certificate.GetEncoded())));
                    x509DataElement.AppendChild(x509Element);
                }
            }

            if (this._CRL != null)
            {
                XmlElement crlElement = xmlDocument.CreateElement(SignedXml.XmlDsigNamespacePrefix, "X509CRL", SignedXml.XmlDsigNamespaceUrl);
                crlElement.AppendChild(xmlDocument.CreateTextNode(Convert.ToBase64String(this._CRL)));
                x509DataElement.AppendChild(crlElement);
            }

            return x509DataElement;
        }

        public override void LoadXml(XmlElement element)
        {
            if (element == null)
            {
                throw new ArgumentNullException(nameof(element));
            }

            XmlNamespaceManager nsm = new XmlNamespaceManager(element.OwnerDocument.NameTable);
            nsm.AddNamespace(SignedXml.XmlDsigNamespacePrefix, SignedXml.XmlDsigNamespaceUrl);

            XmlNodeList x509IssuerSerialNodes = element.SelectNodes(SignedXml.XmlDsigNamespacePrefix + ":X509IssuerSerial", nsm);
            XmlNodeList x509SKINodes = element.SelectNodes(SignedXml.XmlDsigNamespacePrefix + ":X509SKI", nsm);
            XmlNodeList x509SubjectNameNodes = element.SelectNodes(SignedXml.XmlDsigNamespacePrefix + ":X509SubjectName", nsm);
            XmlNodeList x509CertificateNodes = element.SelectNodes(SignedXml.XmlDsigNamespacePrefix + ":X509Certificate", nsm);
            XmlNodeList x509CRLNodes = element.SelectNodes(SignedXml.XmlDsigNamespacePrefix + ":X509CRL", nsm);

            if ((x509CRLNodes.Count == 0 && x509IssuerSerialNodes.Count == 0 && x509SKINodes.Count == 0
                    && x509SubjectNameNodes.Count == 0 && x509CertificateNodes.Count == 0)) // Bad X509Data tag, or Empty tag
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidElement, "X509Data");
            }

            // Flush anything in the lists
            this.Clear();

            if (x509CRLNodes.Count != 0)
            {
                this._CRL = Convert.FromBase64String(Utils.DiscardWhiteSpaces(x509CRLNodes.Item(0).InnerText));
            }

            foreach (XmlNode issuerSerialNode in x509IssuerSerialNodes)
            {
                XmlNode x509IssuerNameNode = issuerSerialNode.SelectSingleNode(SignedXml.XmlDsigNamespacePrefix + ":X509IssuerName", nsm);
                XmlNode x509SerialNumberNode = issuerSerialNode.SelectSingleNode(SignedXml.XmlDsigNamespacePrefix + ":X509SerialNumber", nsm);
                if (x509IssuerNameNode == null || x509SerialNumberNode == null)
                {
                    throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidElement, "IssuerSerial");
                }

                this.InternalAddIssuerSerial(x509IssuerNameNode.InnerText.Trim(), x509SerialNumberNode.InnerText.Trim());
            }

            foreach (XmlNode node in x509SKINodes)
            {
                this.AddSubjectKeyId(Convert.FromBase64String(Utils.DiscardWhiteSpaces(node.InnerText)));
            }

            foreach (XmlNode node in x509SubjectNameNodes)
            {
                this.AddSubjectName(node.InnerText.Trim());
            }

            X509CertificateParser parser = new X509CertificateParser();
            foreach (XmlNode node in x509CertificateNodes)
            {
                Byte[] cert = Convert.FromBase64String(Utils.DiscardWhiteSpaces(node.InnerText));
                this.AddCertificate(parser.ReadCertificate(cert));
            }
        }
    }
}
