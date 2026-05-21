// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    internal abstract class AncestralNamespaceContextManager
    {
        internal ArrayList _ancestorStack = new ArrayList();

        internal NamespaceFrame GetScopeAt(Int32 i)
        {
            return (NamespaceFrame)this._ancestorStack[i];
        }

        internal NamespaceFrame GetCurrentScope()
        {
            return this.GetScopeAt(this._ancestorStack.Count - 1);
        }

        protected XmlAttribute GetNearestRenderedNamespaceWithMatchingPrefix(String nsPrefix, out Int32 depth)
        {
            XmlAttribute attr = null;
            depth = -1;
            for (Int32 i = this._ancestorStack.Count - 1; i >= 0; i--)
            {
                if ((attr = this.GetScopeAt(i).GetRendered(nsPrefix)) != null)
                {
                    depth = i;
                    return attr;
                }
            }
            return null;
        }

        protected XmlAttribute GetNearestUnrenderedNamespaceWithMatchingPrefix(String nsPrefix, out Int32 depth)
        {
            XmlAttribute attr = null;
            depth = -1;
            for (Int32 i = this._ancestorStack.Count - 1; i >= 0; i--)
            {
                if ((attr = this.GetScopeAt(i).GetUnrendered(nsPrefix)) != null)
                {
                    depth = i;
                    return attr;
                }
            }
            return null;
        }

        internal void EnterElementContext()
        {
            this._ancestorStack.Add(new NamespaceFrame());
        }

        internal void ExitElementContext()
        {
            this._ancestorStack.RemoveAt(this._ancestorStack.Count - 1);
        }

        internal abstract void TrackNamespaceNode(XmlAttribute attr, SortedList nsListToRender, Hashtable nsLocallyDeclared);
        internal abstract void TrackXmlNamespaceNode(XmlAttribute attr, SortedList nsListToRender, SortedList attrListToRender, Hashtable nsLocallyDeclared);
        internal abstract void GetNamespacesToRender(XmlElement element, SortedList attrListToRender, SortedList nsListToRender, Hashtable nsLocallyDeclared);

        internal void LoadUnrenderedNamespaces(Hashtable nsLocallyDeclared)
        {
            Object[] attrs = new Object[nsLocallyDeclared.Count];
            nsLocallyDeclared.Values.CopyTo(attrs, 0);
            foreach (Object attr in attrs)
            {
                this.AddUnrendered((XmlAttribute)attr);
            }
        }

        internal void LoadRenderedNamespaces(SortedList nsRenderedList)
        {
            foreach (Object attr in nsRenderedList.GetKeyList())
            {
                this.AddRendered((XmlAttribute)attr);
            }
        }

        internal void AddRendered(XmlAttribute attr)
        {
            this.GetCurrentScope().AddRendered(attr);
        }

        internal void AddUnrendered(XmlAttribute attr)
        {
            this.GetCurrentScope().AddUnrendered(attr);
        }
    }
}
