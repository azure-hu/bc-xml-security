// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    public abstract class KeyDerivationParamsClause
    {
        //
        // protected constructors
        //

        protected KeyDerivationParamsClause() { }

        //
        // public properties
        //

        public abstract String Algorithm { get; }

        //
        // public methods
        //

        public abstract XmlElement GetXml();
        internal virtual XmlElement GetXml(XmlDocument xmlDocument)
        {
            XmlElement keyInfo = this.GetXml();
            return (XmlElement)xmlDocument.ImportNode(keyInfo, true);
        }

        public abstract void LoadXml(XmlElement element);
    }
}
