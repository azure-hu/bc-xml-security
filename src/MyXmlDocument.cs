// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    internal class MyXmlDocument : XmlDocument
    {
        protected override XmlAttribute CreateDefaultAttribute(System.String prefix, System.String localName, System.String namespaceURI)
        {
            return this.CreateAttribute(prefix, localName, namespaceURI);
        }
    }
}
