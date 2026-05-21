// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.IO;
using System.Xml;
using System.Xml.XPath;
using System.Xml.Xsl;

namespace Org.BouncyCastle.Crypto.Xml
{
    public class XmlDsigXsltTransform : Transform
    {
        private readonly Type[] _inputTypes = { typeof(Stream), typeof(XmlDocument), typeof(XmlNodeList) };
        private readonly Type[] _outputTypes = { typeof(Stream) };
        private XmlNodeList _xslNodes;
        private String _xslFragment;
        private Stream _inputStream;
        private readonly Boolean _includeComments = false;

        public XmlDsigXsltTransform()
        {
            this.Algorithm = SignedXml.XmlDsigXsltTransformUrl;
        }

        public XmlDsigXsltTransform(Boolean includeComments)
        {
            this._includeComments = includeComments;
            this.Algorithm = SignedXml.XmlDsigXsltTransformUrl;
        }

        public override Type[] InputTypes
        {
            get
            {
                return this._inputTypes;
            }
        }

        public override Type[] OutputTypes
        {
            get
            {
                return this._outputTypes;
            }
        }

        public override void LoadInnerXml(XmlNodeList nodeList)
        {
            if (nodeList == null)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_UnknownTransform);
            }
            // check that the XSLT element is well formed
            XmlElement firstDataElement = null;
            Int32 count = 0;
            foreach (XmlNode node in nodeList)
            {
                // ignore whitespace, but make sure only one child element is present
                if (node is XmlWhitespace)
                {
                    continue;
                }

                if (node is XmlElement)
                {
                    if (count != 0)
                    {
                        throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_UnknownTransform);
                    }

                    firstDataElement = node as XmlElement;
                    count++;
                    continue;
                }
                // Only allow whitespace
                count++;
            }
            if (count != 1 || firstDataElement == null)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_UnknownTransform);
            }

            this._xslNodes = nodeList;
            this._xslFragment = firstDataElement.OuterXml.Trim(null);
        }

        protected override XmlNodeList GetInnerXml()
        {
            return this._xslNodes;
        }

        public override void LoadInput(Object obj)
        {
            if (this._inputStream != null)
            {
                this._inputStream.Close();
            }

            this._inputStream = new MemoryStream();
            if (obj is Stream)
            {
                this._inputStream = (Stream)obj;
            }
            else if (obj is XmlNodeList)
            {
                CanonicalXml xmlDoc = new CanonicalXml((XmlNodeList)obj, null, this._includeComments);
                Byte[] buffer = xmlDoc.GetBytes();
                if (buffer == null)
                {
                    return;
                }

                this._inputStream.Write(buffer, 0, buffer.Length);
                this._inputStream.Flush();
                this._inputStream.Position = 0;
            }
            else if (obj is XmlDocument)
            {
                CanonicalXml xmlDoc = new CanonicalXml((XmlDocument)obj, null, this._includeComments);
                Byte[] buffer = xmlDoc.GetBytes();
                if (buffer == null)
                {
                    return;
                }

                this._inputStream.Write(buffer, 0, buffer.Length);
                this._inputStream.Flush();
                this._inputStream.Position = 0;
            }
        }

        public override Object GetOutput()
        {
            //  XSL transforms expose many powerful features by default:
            //  1- we need to pass a null evidence to prevent script execution.
            //  2- XPathDocument will expand entities, we don't want this, so set the resolver to null
            //  3- We don't want the document function feature of XslTransforms.

            // load the XSL Transform
            XslCompiledTransform xslt = new XslCompiledTransform();
            XmlReaderSettings settings = new XmlReaderSettings();
            settings.XmlResolver = null;
            settings.MaxCharactersFromEntities = Utils.MaxCharactersFromEntities;
            settings.MaxCharactersInDocument = Utils.MaxCharactersInDocument;
            using (StringReader sr = new StringReader(this._xslFragment))
            {
                XmlReader readerXsl = XmlReader.Create(sr, settings, (String)null);
                xslt.Load(readerXsl, XsltSettings.Default, null);

                // Now load the input stream, XmlDocument can be used but is less efficient
                XmlReader reader = XmlReader.Create(this._inputStream, settings, this.BaseURI);
                XPathDocument inputData = new XPathDocument(reader, XmlSpace.Preserve);

                // Create an XmlTextWriter
                MemoryStream ms = new MemoryStream();
                XmlWriter writer = new XmlTextWriter(ms, null);

                // Transform the data and send the output to the memory stream
                xslt.Transform(inputData, null, writer);
                ms.Position = 0;
                return ms;
            }
        }

        public override Object GetOutput(Type type)
        {
            if (type != typeof(Stream) && !type.IsSubclassOf(typeof(Stream)))
            {
                throw new ArgumentException(SR.Cryptography_Xml_TransformIncorrectInputType, nameof(type));
            }

            return (Stream)this.GetOutput();
        }
    }
}
