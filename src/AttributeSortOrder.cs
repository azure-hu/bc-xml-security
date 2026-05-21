// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    // This class does lexicographic sorting by NamespaceURI first and then by LocalName.
    internal class AttributeSortOrder : IComparer
    {
        internal AttributeSortOrder() { }

        public Int32 Compare(Object a, Object b)
        {
            XmlNode nodeA = a as XmlNode;
            XmlNode nodeB = b as XmlNode;
            if ((nodeA == null) || (nodeB == null))
            {
                throw new ArgumentException();
            }

            Int32 namespaceCompare = String.CompareOrdinal(nodeA.NamespaceURI, nodeB.NamespaceURI);
            if (namespaceCompare != 0)
            {
                return namespaceCompare;
            }

            return String.CompareOrdinal(nodeA.LocalName, nodeB.LocalName);
        }
    }
}
