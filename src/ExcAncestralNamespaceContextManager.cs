// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    // the stack of currently active NamespaceFrame contexts. this
    // object also maintains the inclusive prefix list in a tokenized form.
    internal class ExcAncestralNamespaceContextManager : AncestralNamespaceContextManager
    {
        private readonly Hashtable _inclusivePrefixSet = null;

        internal ExcAncestralNamespaceContextManager(System.String inclusiveNamespacesPrefixList)
        {
            this._inclusivePrefixSet = Utils.TokenizePrefixListString(inclusiveNamespacesPrefixList);
        }

        private System.Boolean HasNonRedundantInclusivePrefix(XmlAttribute attr)
        {
            System.Int32 tmp;
            System.String nsPrefix = Utils.GetNamespacePrefix(attr);
            return this._inclusivePrefixSet.ContainsKey(nsPrefix) &&
                Utils.IsNonRedundantNamespaceDecl(attr, this.GetNearestRenderedNamespaceWithMatchingPrefix(nsPrefix, out tmp));
        }

        private void GatherNamespaceToRender(System.String nsPrefix, SortedList nsListToRender, Hashtable nsLocallyDeclared)
        {
            foreach (System.Object a in nsListToRender.GetKeyList())
            {
                if (Utils.HasNamespacePrefix((XmlAttribute)a, nsPrefix))
                {
                    return;
                }
            }

            System.Int32 rDepth;
            XmlAttribute local = (XmlAttribute)nsLocallyDeclared[nsPrefix];
            XmlAttribute rAncestral = this.GetNearestRenderedNamespaceWithMatchingPrefix(nsPrefix, out rDepth);

            if (local != null)
            {
                if (Utils.IsNonRedundantNamespaceDecl(local, rAncestral))
                {
                    nsLocallyDeclared.Remove(nsPrefix);
                    nsListToRender.Add(local, null);
                }
            }
            else
            {
                System.Int32 uDepth;
                XmlAttribute uAncestral = this.GetNearestUnrenderedNamespaceWithMatchingPrefix(nsPrefix, out uDepth);
                if (uAncestral != null && uDepth > rDepth && Utils.IsNonRedundantNamespaceDecl(uAncestral, rAncestral))
                {
                    nsListToRender.Add(uAncestral, null);
                }
            }
        }

        internal override void GetNamespacesToRender(XmlElement element, SortedList attrListToRender, SortedList nsListToRender, Hashtable nsLocallyDeclared)
        {
            this.GatherNamespaceToRender(element.Prefix, nsListToRender, nsLocallyDeclared);
            foreach (System.Object attr in attrListToRender.GetKeyList())
            {
                System.String prefix = ((XmlAttribute)attr).Prefix;
                if (prefix.Length > 0)
                {
                    this.GatherNamespaceToRender(prefix, nsListToRender, nsLocallyDeclared);
                }
            }
        }

        internal override void TrackNamespaceNode(XmlAttribute attr, SortedList nsListToRender, Hashtable nsLocallyDeclared)
        {
            if (!Utils.IsXmlPrefixDefinitionNode(attr))
            {
                if (this.HasNonRedundantInclusivePrefix(attr))
                {
                    nsListToRender.Add(attr, null);
                }
                else
                {
                    nsLocallyDeclared.Add(Utils.GetNamespacePrefix(attr), attr);
                }
            }
        }

        internal override void TrackXmlNamespaceNode(XmlAttribute attr, SortedList nsListToRender, SortedList attrListToRender, Hashtable nsLocallyDeclared)
        {
            // exclusive canonicalization treats Xml namespaces as simple attributes. They are not propagated.
            attrListToRender.Add(attr, null);
        }
    }
}
