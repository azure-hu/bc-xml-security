// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.IO;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    public class XmlDsigC14NTransform : Transform
    {
        private readonly Type[] _inputTypes = { typeof(Stream), typeof(XmlDocument), typeof(XmlNodeList) };
        private readonly Type[] _outputTypes = { typeof(Stream) };
        private CanonicalXml _cXml;
        private readonly Boolean _includeComments = false;

        public XmlDsigC14NTransform()
        {
            this.Algorithm = SignedXml.XmlDsigC14NTransformUrl;
        }

        public XmlDsigC14NTransform(Boolean includeComments)
        {
            this._includeComments = includeComments;
            this.Algorithm = (includeComments ? SignedXml.XmlDsigC14NWithCommentsTransformUrl : SignedXml.XmlDsigC14NTransformUrl);
        }

        public override Type[] InputTypes
        {
            get { return this._inputTypes; }
        }

        public override Type[] OutputTypes
        {
            get { return this._outputTypes; }
        }

        public override void LoadInnerXml(XmlNodeList nodeList)
        {
            if (nodeList != null && nodeList.Count > 0)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_UnknownTransform);
            }
        }

        protected override XmlNodeList GetInnerXml()
        {
            return null;
        }

        public override void LoadInput(Object obj)
        {
            XmlResolver resolver = (this.ResolverSet ? this._xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), this.BaseURI));
            if (obj is Stream)
            {
                this._cXml = new CanonicalXml((Stream)obj, this._includeComments, resolver, this.BaseURI);
                return;
            }
            if (obj is XmlDocument)
            {
                this._cXml = new CanonicalXml((XmlDocument)obj, resolver, this._includeComments);
                return;
            }
            if (obj is XmlNodeList)
            {
                this._cXml = new CanonicalXml((XmlNodeList)obj, resolver, this._includeComments);
            }
            else
            {
                throw new ArgumentException(SR.Cryptography_Xml_IncorrectObjectType, nameof(obj));
            }
        }

        public override Object GetOutput()
        {
            return new MemoryStream(this._cXml.GetBytes());
        }

        public override Object GetOutput(Type type)
        {
            if (type != typeof(Stream) && !type.IsSubclassOf(typeof(Stream)))
            {
                throw new ArgumentException(SR.Cryptography_Xml_TransformIncorrectInputType, nameof(type));
            }

            return new MemoryStream(this._cXml.GetBytes());
        }

        public override void GetDigestedOutput(IHash hash)
        {
            this._cXml.GetDigestedBytes(hash);
        }
    }
}
