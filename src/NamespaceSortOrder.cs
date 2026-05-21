// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    internal class NamespaceSortOrder : IComparer
    {
        internal NamespaceSortOrder() { }

        public Int32 Compare(Object a, Object b)
        {
            XmlNode nodeA = a as XmlNode;
            XmlNode nodeB = b as XmlNode;
            if ((nodeA == null) || (nodeB == null))
            {
                throw new ArgumentException();
            }

            Boolean nodeAdefault = Utils.IsDefaultNamespaceNode(nodeA);
            Boolean nodeBdefault = Utils.IsDefaultNamespaceNode(nodeB);
            if (nodeAdefault && nodeBdefault)
            {
                return 0;
            }

            if (nodeAdefault)
            {
                return -1;
            }

            if (nodeBdefault)
            {
                return 1;
            }

            return String.CompareOrdinal(nodeA.LocalName, nodeB.LocalName);
        }
    }
}
