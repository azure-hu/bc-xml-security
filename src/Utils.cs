// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Store;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    internal class Utils
    {
        // The maximum number of characters in an XML document (0 means no limit).
        internal const Int32 MaxCharactersInDocument = 0;

        // The entity expansion limit. This is used to prevent entity expansion denial of service attacks.
        internal const Int64 MaxCharactersFromEntities = (Int64)1e7;

        // The default XML Dsig recursion limit.
        // This should be within limits of real world scenarios.
        // Keeping this number low will preserve some stack space
        internal const Int32 XmlDsigSearchDepth = 20;

        private Utils() { }

        private static Boolean HasNamespace(XmlElement element, String prefix, String value)
        {
            if (IsCommittedNamespace(element, prefix, value))
            {
                return true;
            }

            if (element.Prefix == prefix && element.NamespaceURI == value)
            {
                return true;
            }

            return false;
        }

        // A helper function that determines if a namespace node is a committed attribute
        internal static Boolean IsCommittedNamespace(XmlElement element, String prefix, String value)
        {
            if (element == null)
            {
                throw new ArgumentNullException(nameof(element));
            }

            String name = ((prefix.Length > 0) ? "xmlns:" + prefix : "xmlns");
            if (element.HasAttribute(name) && element.GetAttribute(name) == value)
            {
                return true;
            }

            return false;
        }

        internal static Boolean IsRedundantNamespace(XmlElement element, String prefix, String value)
        {
            if (element == null)
            {
                throw new ArgumentNullException(nameof(element));
            }

            XmlNode ancestorNode = ((XmlNode)element).ParentNode;
            while (ancestorNode != null)
            {
                XmlElement ancestorElement = ancestorNode as XmlElement;
                if (ancestorElement != null)
                {
                    if (HasNamespace(ancestorElement, prefix, value))
                    {
                        return true;
                    }
                }

                ancestorNode = ancestorNode.ParentNode;
            }

            return false;
        }

        internal static String GetAttribute(XmlElement element, String localName, String namespaceURI)
        {
            String s = (element.HasAttribute(localName) ? element.GetAttribute(localName) : null);
            if (s == null && element.HasAttribute(localName, namespaceURI))
            {
                s = element.GetAttribute(localName, namespaceURI);
            }

            return s;
        }

        internal static Boolean HasAttribute(XmlElement element, String localName, String namespaceURI)
        {
            return element.HasAttribute(localName) || element.HasAttribute(localName, namespaceURI);
        }

        internal static Boolean VerifyAttributes(XmlElement element, String expectedAttrName)
        {
            return VerifyAttributes(element, expectedAttrName == null ? null : new String[] { expectedAttrName });
        }

        internal static Boolean VerifyAttributes(XmlElement element, String[] expectedAttrNames)
        {
            foreach (XmlAttribute attr in element.Attributes)
            {
                // There are a few Xml Special Attributes that are always allowed on any node. Make sure we allow those here.
                Boolean attrIsAllowed = attr.Name == "xmlns" || attr.Name.StartsWith("xmlns:") || attr.Name == "xml:space" || attr.Name == "xml:lang" || attr.Name == "xml:base";
                Int32 expectedInd = 0;
                while (!attrIsAllowed && expectedAttrNames != null && expectedInd < expectedAttrNames.Length)
                {
                    attrIsAllowed = attr.Name == expectedAttrNames[expectedInd];
                    expectedInd++;
                }
                if (!attrIsAllowed)
                {
                    return false;
                }
            }
            return true;
        }

        internal static Boolean IsNamespaceNode(XmlNode n)
        {
            return n.NodeType == XmlNodeType.Attribute && (n.Prefix.Equals("xmlns") || (n.Prefix.Length == 0 && n.LocalName.Equals("xmlns")));
        }

        internal static Boolean IsXmlNamespaceNode(XmlNode n)
        {
            return n.NodeType == XmlNodeType.Attribute && n.Prefix.Equals("xml");
        }

        // We consider xml:space style attributes as default namespace nodes since they obey the same propagation rules
        internal static Boolean IsDefaultNamespaceNode(XmlNode n)
        {
            Boolean b1 = n.NodeType == XmlNodeType.Attribute && n.Prefix.Length == 0 && n.LocalName.Equals("xmlns");
            Boolean b2 = IsXmlNamespaceNode(n);
            return b1 || b2;
        }

        internal static Boolean IsEmptyDefaultNamespaceNode(XmlNode n)
        {
            return IsDefaultNamespaceNode(n) && n.Value.Length == 0;
        }

        internal static String GetNamespacePrefix(XmlAttribute a)
        {
            Debug.Assert(IsNamespaceNode(a) || IsXmlNamespaceNode(a));
            return a.Prefix.Length == 0 ? String.Empty : a.LocalName;
        }

        internal static Boolean HasNamespacePrefix(XmlAttribute a, String nsPrefix)
        {
            return GetNamespacePrefix(a).Equals(nsPrefix);
        }

        internal static Boolean IsNonRedundantNamespaceDecl(XmlAttribute a, XmlAttribute nearestAncestorWithSamePrefix)
        {
            if (nearestAncestorWithSamePrefix == null)
            {
                return !IsEmptyDefaultNamespaceNode(a);
            }
            else
            {
                return !nearestAncestorWithSamePrefix.Value.Equals(a.Value);
            }
        }

        internal static Boolean IsXmlPrefixDefinitionNode(XmlAttribute a)
        {
            return false;
            //            return a.Prefix.Equals("xmlns") && a.LocalName.Equals("xml") && a.Value.Equals(NamespaceUrlForXmlPrefix);
        }

        internal static String DiscardWhiteSpaces(String inputBuffer)
        {
            return DiscardWhiteSpaces(inputBuffer, 0, inputBuffer.Length);
        }


        internal static String DiscardWhiteSpaces(String inputBuffer, Int32 inputOffset, Int32 inputCount)
        {
            Int32 i, iCount = 0;
            for (i = 0; i < inputCount; i++)
            {
                if (Char.IsWhiteSpace(inputBuffer[inputOffset + i]))
                {
                    iCount++;
                }
            }

            Char[] rgbOut = new Char[inputCount - iCount];
            iCount = 0;
            for (i = 0; i < inputCount; i++)
            {
                if (!Char.IsWhiteSpace(inputBuffer[inputOffset + i]))
                {
                    rgbOut[iCount++] = inputBuffer[inputOffset + i];
                }
            }

            return new String(rgbOut);
        }

        internal static void SBReplaceCharWithString(StringBuilder sb, Char oldChar, String newString)
        {
            Int32 i = 0;
            Int32 newStringLength = newString.Length;
            while (i < sb.Length)
            {
                if (sb[i] == oldChar)
                {
                    sb.Remove(i, 1);
                    sb.Insert(i, newString);
                    i += newStringLength;
                }
                else
                {
                    i++;
                }
            }
        }

        internal static XmlReader PreProcessStreamInput(Stream inputStream, XmlResolver xmlResolver, String baseUri)
        {
            XmlReaderSettings settings = GetSecureXmlReaderSettings(xmlResolver);
            XmlReader reader = XmlReader.Create(inputStream, settings, baseUri);
            return reader;
        }

        internal static XmlReaderSettings GetSecureXmlReaderSettings(XmlResolver xmlResolver)
        {
            XmlReaderSettings settings = new XmlReaderSettings();
            settings.XmlResolver = xmlResolver;
            settings.DtdProcessing = DtdProcessing.Parse;
            settings.MaxCharactersFromEntities = MaxCharactersFromEntities;
            settings.MaxCharactersInDocument = MaxCharactersInDocument;
            return settings;
        }

        internal static XmlDocument PreProcessDocumentInput(XmlDocument document, XmlResolver xmlResolver, String baseUri)
        {
            if (document == null)
            {
                throw new ArgumentNullException(nameof(document));
            }

            MyXmlDocument doc = new MyXmlDocument();
            doc.PreserveWhitespace = document.PreserveWhitespace;

            // Normalize the document
            using (TextReader stringReader = new StringReader(document.OuterXml))
            {
                XmlReaderSettings settings = new XmlReaderSettings();
                settings.XmlResolver = xmlResolver;
                settings.DtdProcessing = DtdProcessing.Parse;
                settings.MaxCharactersFromEntities = MaxCharactersFromEntities;
                settings.MaxCharactersInDocument = MaxCharactersInDocument;
                XmlReader reader = XmlReader.Create(stringReader, settings, baseUri);
                doc.Load(reader);
            }
            return doc;
        }

        internal static XmlDocument PreProcessElementInput(XmlElement elem, XmlResolver xmlResolver, String baseUri)
        {
            if (elem == null)
            {
                throw new ArgumentNullException(nameof(elem));
            }

            MyXmlDocument doc = new MyXmlDocument();
            doc.PreserveWhitespace = true;
            // Normalize the document
            using (TextReader stringReader = new StringReader(elem.OuterXml))
            {
                XmlReaderSettings settings = new XmlReaderSettings();
                settings.XmlResolver = xmlResolver;
                settings.DtdProcessing = DtdProcessing.Parse;
                settings.MaxCharactersFromEntities = MaxCharactersFromEntities;
                settings.MaxCharactersInDocument = MaxCharactersInDocument;
                XmlReader reader = XmlReader.Create(stringReader, settings, baseUri);
                doc.Load(reader);
            }
            return doc;
        }

        internal static XmlDocument DiscardComments(XmlDocument document)
        {
            XmlNodeList nodeList = document.SelectNodes("//comment()");
            if (nodeList != null)
            {
                foreach (XmlNode node1 in nodeList)
                {
                    node1.ParentNode.RemoveChild(node1);
                }
            }
            return document;
        }

        internal static XmlNodeList AllDescendantNodes(XmlNode node, Boolean includeComments)
        {
            CanonicalXmlNodeList nodeList = new CanonicalXmlNodeList();
            CanonicalXmlNodeList elementList = new CanonicalXmlNodeList();
            CanonicalXmlNodeList attribList = new CanonicalXmlNodeList();
            CanonicalXmlNodeList namespaceList = new CanonicalXmlNodeList();

            Int32 index = 0;
            elementList.Add(node);

            do
            {
                XmlNode rootNode = (XmlNode)elementList[index];
                // Add the children nodes
                XmlNodeList childNodes = rootNode.ChildNodes;
                if (childNodes != null)
                {
                    foreach (XmlNode node1 in childNodes)
                    {
                        if (includeComments || (!(node1 is XmlComment)))
                        {
                            elementList.Add(node1);
                        }
                    }
                }
                // Add the attribute nodes
                XmlAttributeCollection attribNodes = rootNode.Attributes;
                if (attribNodes != null)
                {
                    foreach (XmlNode attribNode in rootNode.Attributes)
                    {
                        if (attribNode.LocalName == "xmlns" || attribNode.Prefix == "xmlns")
                        {
                            namespaceList.Add(attribNode);
                        }
                        else
                        {
                            attribList.Add(attribNode);
                        }
                    }
                }
                index++;
            } while (index < elementList.Count);
            foreach (XmlNode elementNode in elementList)
            {
                nodeList.Add(elementNode);
            }
            foreach (XmlNode attribNode in attribList)
            {
                nodeList.Add(attribNode);
            }
            foreach (XmlNode namespaceNode in namespaceList)
            {
                nodeList.Add(namespaceNode);
            }

            return nodeList;
        }

        internal static Boolean NodeInList(XmlNode node, XmlNodeList nodeList)
        {
            foreach (XmlNode nodeElem in nodeList)
            {
                if (nodeElem == node)
                {
                    return true;
                }
            }
            return false;
        }

        internal static String GetIdFromLocalUri(String uri, out Boolean discardComments)
        {
            String idref = uri.Substring(1);
            // initialize the return value
            discardComments = true;

            // Deal with XPointer of type #xpointer(id("ID")). Other XPointer support isn't handled here and is anyway optional
            if (idref.StartsWith("xpointer(id(", StringComparison.Ordinal))
            {
                Int32 startId = idref.IndexOf("id(", StringComparison.Ordinal);
                Int32 endId = idref.IndexOf(")", StringComparison.Ordinal);
                if (endId < 0 || endId < startId + 3)
                {
                    throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidReference);
                }

                idref = idref.Substring(startId + 3, endId - startId - 3);
                idref = idref.Replace("\'", "");
                idref = idref.Replace("\"", "");
                discardComments = false;
            }
            return idref;
        }

        internal static String ExtractIdFromLocalUri(String uri)
        {
            String idref = uri.Substring(1);

            // Deal with XPointer of type #xpointer(id("ID")). Other XPointer support isn't handled here and is anyway optional
            if (idref.StartsWith("xpointer(id(", StringComparison.Ordinal))
            {
                Int32 startId = idref.IndexOf("id(", StringComparison.Ordinal);
                Int32 endId = idref.IndexOf(")", StringComparison.Ordinal);
                if (endId < 0 || endId < startId + 3)
                {
                    throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_InvalidReference);
                }

                idref = idref.Substring(startId + 3, endId - startId - 3);
                idref = idref.Replace("\'", "");
                idref = idref.Replace("\"", "");
            }
            return idref;
        }

        // This removes all children of an element.
        internal static void RemoveAllChildren(XmlElement inputElement)
        {
            XmlNode child = inputElement.FirstChild;
            XmlNode sibling = null;

            while (child != null)
            {
                sibling = child.NextSibling;
                inputElement.RemoveChild(child);
                child = sibling;
            }
        }

        // Writes one stream (starting from the current position) into
        // an output stream, connecting them up and reading until
        // hitting the end of the input stream.
        // returns the number of bytes copied
        internal static Int64 Pump(Stream input, Stream output)
        {
            // Use MemoryStream's WriteTo(Stream) method if possible
            MemoryStream inputMS = input as MemoryStream;
            if (inputMS != null && inputMS.Position == 0)
            {
                inputMS.WriteTo(output);
                return inputMS.Length;
            }

            const Int32 count = 4096;
            Byte[] bytes = new Byte[count];
            Int32 numBytes;
            Int64 totalBytes = 0;

            while ((numBytes = input.Read(bytes, 0, count)) > 0)
            {
                output.Write(bytes, 0, numBytes);
                totalBytes += numBytes;
            }

            return totalBytes;
        }

        internal static Hashtable TokenizePrefixListString(String s)
        {
            Hashtable set = new Hashtable();
            if (s != null)
            {
                String[] prefixes = s.Split(null);
                foreach (String prefix in prefixes)
                {
                    if (prefix.Equals("#default"))
                    {
                        set.Add(String.Empty, true);
                    }
                    else if (prefix.Length > 0)
                    {
                        set.Add(prefix, true);
                    }
                }
            }
            return set;
        }

        internal static String EscapeWhitespaceData(String data)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(data);
            Utils.SBReplaceCharWithString(sb, (Char)13, "&#xD;");
            return sb.ToString();
            ;
        }

        internal static String EscapeTextData(String data)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(data);
            sb.Replace("&", "&amp;");
            sb.Replace("<", "&lt;");
            sb.Replace(">", "&gt;");
            SBReplaceCharWithString(sb, (Char)13, "&#xD;");
            return sb.ToString();
            ;
        }

        internal static String EscapeCData(String data)
        {
            return EscapeTextData(data);
        }

        internal static String EscapeAttributeValue(String value)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(value);
            sb.Replace("&", "&amp;");
            sb.Replace("<", "&lt;");
            sb.Replace("\"", "&quot;");
            SBReplaceCharWithString(sb, (Char)9, "&#x9;");
            SBReplaceCharWithString(sb, (Char)10, "&#xA;");
            SBReplaceCharWithString(sb, (Char)13, "&#xD;");
            return sb.ToString();
        }

        internal static XmlDocument GetOwnerDocument(XmlNodeList nodeList)
        {
            foreach (XmlNode node in nodeList)
            {
                if (node.OwnerDocument != null)
                {
                    return node.OwnerDocument;
                }
            }
            return null;
        }

        internal static void AddNamespaces(XmlElement elem, CanonicalXmlNodeList namespaces)
        {
            if (namespaces != null)
            {
                foreach (XmlNode attrib in namespaces)
                {
                    String name = ((attrib.Prefix.Length > 0) ? attrib.Prefix + ":" + attrib.LocalName : attrib.LocalName);
                    // Skip the attribute if one with the same qualified name already exists
                    if (elem.HasAttribute(name) || (name.Equals("xmlns") && elem.Prefix.Length == 0))
                    {
                        continue;
                    }

                    XmlAttribute nsattrib = (XmlAttribute)elem.OwnerDocument.CreateAttribute(name);
                    nsattrib.Value = attrib.Value;
                    elem.SetAttributeNode(nsattrib);
                }
            }
        }

        internal static void AddNamespaces(XmlElement elem, Hashtable namespaces)
        {
            if (namespaces != null)
            {
                foreach (String key in namespaces.Keys)
                {
                    if (elem.HasAttribute(key))
                    {
                        continue;
                    }

                    XmlAttribute nsattrib = (XmlAttribute)elem.OwnerDocument.CreateAttribute(key);
                    nsattrib.Value = namespaces[key] as String;
                    elem.SetAttributeNode(nsattrib);
                }
            }
        }

        // This method gets the attributes that should be propagated
        internal static CanonicalXmlNodeList GetPropagatedAttributes(XmlElement elem)
        {
            if (elem == null)
            {
                return null;
            }

            CanonicalXmlNodeList namespaces = new CanonicalXmlNodeList();
            XmlNode ancestorNode = elem;
            Boolean bDefNamespaceToAdd = true;

            while (ancestorNode != null)
            {
                XmlElement ancestorElement = ancestorNode as XmlElement;
                if (ancestorElement == null)
                {
                    ancestorNode = ancestorNode.ParentNode;
                    continue;
                }
                if (!Utils.IsCommittedNamespace(ancestorElement, ancestorElement.Prefix, ancestorElement.NamespaceURI))
                {
                    // Add the namespace attribute to the collection if needed
                    if (!Utils.IsRedundantNamespace(ancestorElement, ancestorElement.Prefix, ancestorElement.NamespaceURI))
                    {
                        String name = ((ancestorElement.Prefix.Length > 0) ? "xmlns:" + ancestorElement.Prefix : "xmlns");
                        XmlAttribute nsattrib = elem.OwnerDocument.CreateAttribute(name);
                        nsattrib.Value = ancestorElement.NamespaceURI;
                        namespaces.Add(nsattrib);
                    }
                }
                if (ancestorElement.HasAttributes)
                {
                    XmlAttributeCollection attribs = ancestorElement.Attributes;
                    foreach (XmlAttribute attrib in attribs)
                    {
                        // Add a default namespace if necessary
                        if (bDefNamespaceToAdd && attrib.LocalName == "xmlns")
                        {
                            XmlAttribute nsattrib = elem.OwnerDocument.CreateAttribute("xmlns");
                            nsattrib.Value = attrib.Value;
                            namespaces.Add(nsattrib);
                            bDefNamespaceToAdd = false;
                            continue;
                        }
                        // retain the declarations of type 'xml:*' as well
                        if (attrib.Prefix == "xmlns" || attrib.Prefix == "xml")
                        {
                            namespaces.Add(attrib);
                            continue;
                        }
                        if (attrib.NamespaceURI.Length > 0)
                        {
                            if (!Utils.IsCommittedNamespace(ancestorElement, attrib.Prefix, attrib.NamespaceURI))
                            {
                                // Add the namespace attribute to the collection if needed
                                if (!Utils.IsRedundantNamespace(ancestorElement, attrib.Prefix, attrib.NamespaceURI))
                                {
                                    String name = ((attrib.Prefix.Length > 0) ? "xmlns:" + attrib.Prefix : "xmlns");
                                    XmlAttribute nsattrib = elem.OwnerDocument.CreateAttribute(name);
                                    nsattrib.Value = attrib.NamespaceURI;
                                    namespaces.Add(nsattrib);
                                }
                            }
                        }
                    }
                }
                ancestorNode = ancestorNode.ParentNode;
            }

            return namespaces;
        }

        // output of this routine is always big endian
        internal static Byte[] ConvertIntToByteArray(Int32 dwInput)
        {
            Byte[] rgbTemp = new Byte[8]; // int can never be greater than Int64
            Int32 t1;  // t1 is remaining value to account for
            Int32 t2;  // t2 is t1 % 256
            Int32 i = 0;

            if (dwInput == 0)
            {
                return new Byte[1];
            }

            t1 = dwInput;
            while (t1 > 0)
            {
                t2 = t1 % 256;
                rgbTemp[i] = (Byte)t2;
                t1 = (t1 - t2) / 256;
                i++;
            }
            // Now, copy only the non-zero part of rgbTemp and reverse
            Byte[] rgbOutput = new Byte[i];
            // copy and reverse in one pass
            for (Int32 j = 0; j < i; j++)
            {
                rgbOutput[j] = rgbTemp[i - j - 1];
            }
            return rgbOutput;
        }

        internal static Int32 ConvertByteArrayToInt(Byte[] input)
        {
            // Input to this routine is always big endian
            Int32 dwOutput = 0;
            for (Int32 i = 0; i < input.Length; i++)
            {
                dwOutput *= 256;
                dwOutput += input[i];
            }
            return (dwOutput);
        }

        internal static Int32 GetHexArraySize(Byte[] hex)
        {
            Int32 index = hex.Length;
            while (index-- > 0)
            {
                if (hex[index] != 0)
                {
                    break;
                }
            }
            return index + 1;
        }

        // Mimic the behavior of the X509IssuerSerial constructor with null and empty checks
        internal static X509IssuerSerial CreateX509IssuerSerial(String issuerName, String serialNumber)
        {
            if (issuerName == null || issuerName.Length == 0)
            {
                throw new ArgumentException(SR.Arg_EmptyOrNullString, nameof(issuerName));
            }

            if (serialNumber == null || serialNumber.Length == 0)
            {
                throw new ArgumentException(SR.Arg_EmptyOrNullString, nameof(serialNumber));
            }

            return new X509IssuerSerial()
            {
                IssuerName = issuerName,
                SerialNumber = serialNumber
            };
        }

        internal static IList<X509Certificate> BuildBagOfCerts(KeyInfoX509Data keyInfoX509Data, CertUsageType certUsageType)
        {
            List<X509Certificate> collection = new List<X509Certificate>();
            ArrayList decryptionIssuerSerials = (certUsageType == CertUsageType.Decryption ? new ArrayList() : null);
            if (keyInfoX509Data.Certificates != null)
            {
                foreach (X509Certificate certificate in keyInfoX509Data.Certificates)
                {
                    switch (certUsageType)
                    {
                        case CertUsageType.Verification:
                            collection.Add(certificate);
                            break;
                        case CertUsageType.Decryption:
                            decryptionIssuerSerials.Add(Utils.CreateX509IssuerSerial(certificate.IssuerDN.ToString(), certificate.SerialNumber.ToString()));
                            break;
                    }
                }
            }

            if (keyInfoX509Data.SubjectNames == null && keyInfoX509Data.IssuerSerials == null &&
                keyInfoX509Data.SubjectKeyIds == null && decryptionIssuerSerials == null)
            {
                return collection;
            }

            // Open LocalMachine and CurrentUser "Other People"/"My" stores.
            /*
            X509Store[] stores = new X509Store[2];
            string storeName = (certUsageType == CertUsageType.Verification ? "AddressBook" : "My");
            stores[0] = new X509Store(storeName, StoreLocation.CurrentUser);
            stores[1] = new X509Store(storeName, StoreLocation.LocalMachine);

            for (int index = 0; index < stores.Length; index++)
            {
                if (stores[index] != null)
                {
                    X509Certificate2Collection filters = null;
                    // We don't care if we can't open the store.
                    try
                    {
                        stores[index].Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                        filters = stores[index].Certificates;
                        stores[index].Close();
                        if (keyInfoX509Data.SubjectNames != null)
                        {
                            foreach (string subjectName in keyInfoX509Data.SubjectNames)
                            {
                                filters = filters.Find(X509FindType.FindBySubjectDistinguishedName, subjectName, false);
                            }
                        }
                        if (keyInfoX509Data.IssuerSerials != null)
                        {
                            foreach (X509IssuerSerial issuerSerial in keyInfoX509Data.IssuerSerials)
                            {
                                filters = filters.Find(X509FindType.FindByIssuerDistinguishedName, issuerSerial.IssuerName, false);
                                filters = filters.Find(X509FindType.FindBySerialNumber, issuerSerial.SerialNumber, false);
                            }
                        }
                        if (keyInfoX509Data.SubjectKeyIds != null)
                        {
                            foreach (byte[] ski in keyInfoX509Data.SubjectKeyIds)
                            {
                                string hex = EncodeHexString(ski);
                                filters = filters.Find(X509FindType.FindBySubjectKeyIdentifier, hex, false);
                            }
                        }
                        if (decryptionIssuerSerials != null)
                        {
                            foreach (X509IssuerSerial issuerSerial in decryptionIssuerSerials)
                            {
                                filters = filters.Find(X509FindType.FindByIssuerDistinguishedName, issuerSerial.IssuerName, false);
                                filters = filters.Find(X509FindType.FindBySerialNumber, issuerSerial.SerialNumber, false);
                            }
                        }
                    }
                    // Store doesn't exist, no read permissions, other system error
                    catch (System.Security.Cryptography.CryptographicException) { }
                    // Opening LocalMachine stores (other than Root or CertificateAuthority) on Linux
                    catch (PlatformNotSupportedException) { }

                    if (filters != null)
                        collection.AddRange(filters);
                }
            }
            */
            return collection;
        }

        private static readonly Char[] s_hexValues = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        internal static String EncodeHexString(Byte[] sArray)
        {
            return EncodeHexString(sArray, 0, (UInt32)sArray.Length);
        }

        internal static String EncodeHexString(Byte[] sArray, UInt32 start, UInt32 end)
        {
            String result = null;
            if (sArray != null)
            {
                Char[] hexOrder = new Char[(end - start) * 2];
                UInt32 digit;
                for (UInt32 i = start, j = 0; i < end; i++)
                {
                    digit = (UInt32)((sArray[i] & 0xf0) >> 4);
                    hexOrder[j++] = s_hexValues[digit];
                    digit = (UInt32)(sArray[i] & 0x0f);
                    hexOrder[j++] = s_hexValues[digit];
                }
                result = new String(hexOrder);
            }
            return result;
        }

        internal static Byte[] DecodeHexString(String s)
        {
            String hexString = Utils.DiscardWhiteSpaces(s);
            UInt32 cbHex = (UInt32)hexString.Length / 2;
            Byte[] hex = new Byte[cbHex];
            Int32 i = 0;
            for (Int32 index = 0; index < cbHex; index++)
            {
                hex[index] = (Byte)((HexToByte(hexString[i]) << 4) | HexToByte(hexString[i + 1]));
                i += 2;
            }
            return hex;
        }

        internal static Byte HexToByte(Char val)
        {
            if (val <= '9' && val >= '0')
            {
                return (Byte)(val - '0');
            }
            else if (val >= 'a' && val <= 'f')
            {
                return (Byte)((val - 'a') + 10);
            }
            else if (val >= 'A' && val <= 'F')
            {
                return (Byte)((val - 'A') + 10);
            }
            else
            {
                return 0xFF;
            }
        }

        internal static Boolean IsSelfSigned(IList<X509Certificate> chain)
        {
            if (chain.Count != 1)
            {
                return false;
            }

            X509Certificate certificate = chain[0];
            if (String.Compare(certificate.SubjectDN.ToString(), certificate.IssuerDN.ToString(), StringComparison.OrdinalIgnoreCase) == 0)
            {
                return true;
            }

            return false;
        }

        internal static IList<X509Certificate> BuildCertificateChain(X509Certificate primaryCertificate, IEnumerable<X509Certificate> additionalCertificates)
        {
            X509CertificateParser parser = new X509CertificateParser();
            PkixCertPathBuilder builder = new PkixCertPathBuilder();

            // Separate root from itermediate
            List<X509Certificate> intermediateCerts = new List<X509Certificate>();
            HashSet<TrustAnchor> rootCerts = new HashSet<TrustAnchor>();

            foreach (X509Certificate cert in additionalCertificates)
            {
                // Separate root and subordinate certificates
                if (cert.IssuerDN.Equivalent(cert.SubjectDN))
                {
                    rootCerts.Add(new TrustAnchor(cert, null));
                }
                else
                {
                    intermediateCerts.Add(cert);
                }
            }

            // Create chain for this certificate
            X509CertStoreSelector holder = new X509CertStoreSelector();
            holder.Certificate = primaryCertificate;

            // WITHOUT THIS LINE BUILDER CANNOT BEGIN BUILDING THE CHAIN
            intermediateCerts.Add(holder.Certificate);

            PkixBuilderParameters builderParams = new PkixBuilderParameters(rootCerts, holder);
            builderParams.IsRevocationEnabled = false;
            builderParams.AddStoreCert(new X509CertificateStore(intermediateCerts));

            PkixCertPathBuilderResult result = builder.Build(builderParams);

            return result.CertPath.Certificates.Cast<X509Certificate>().ToList();
        }

        internal static AsymmetricKeyParameter GetAnyPublicKey(X509Certificate certificate)
        {
            return certificate.GetPublicKey();
        }

        internal const Int32 MaxTransformsPerReference = 10;
        internal const Int32 MaxReferencesPerSignedInfo = 100;

        internal static IDigest GetSignerDigest(ISigner signer)
        {
            FieldInfo[] fields = signer.GetType().GetFields(BindingFlags.Instance | BindingFlags.NonPublic);
            Type digestType = typeof(IDigest);
            foreach (FieldInfo field in fields)
            {
                if (digestType.IsAssignableFrom(field.FieldType))
                {
                    return (IDigest)field.GetValue(signer);
                }
            }
            throw new InvalidOperationException();
        }

        internal static X509Certificate CloneCertificate(X509Certificate cert)
        {
            cert = cert ?? throw new ArgumentNullException(nameof(cert));
            X509CertificateParser parser = new X509CertificateParser();
            return parser.ReadCertificate(cert.GetEncoded());
        }

        internal static AsymmetricCipherKeyPair DSAGenerateKeyPair()
        {
            IAsymmetricCipherKeyPairGenerator keyGen = GeneratorUtilities.GetKeyPairGenerator("DSA");
            SecureRandom rand = new SecureRandom();
            DsaParametersGenerator pGen = new DsaParametersGenerator();
            pGen.Init(512, 80, rand);
            keyGen.Init(new DsaKeyGenerationParameters(rand, pGen.GenerateParameters()));
            return keyGen.GenerateKeyPair();
        }

        internal static AsymmetricCipherKeyPair RSAGenerateKeyPair()
        {
            IAsymmetricCipherKeyPairGenerator keyGen = GeneratorUtilities.GetKeyPairGenerator("RSA");
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 1024));
            return keyGen.GenerateKeyPair();
        }

        internal static Byte[] GenerateRandomBlock(Int32 sizeInBytes)
        {
            SecureRandom random = new SecureRandom();
            Byte[] keyBytes = new Byte[sizeInBytes];
            random.NextBytes(keyBytes);
            return keyBytes;
        }

        private class X509CertificateStore : IStore<X509Certificate>
        {
            private readonly IEnumerable<X509Certificate> _local;

            public X509CertificateStore(IEnumerable<X509Certificate> collection)
            {
                this._local = collection;
            }

            public IEnumerable<X509Certificate> EnumerateMatches(ISelector<X509Certificate> selector)
            {
                return selector == null ? this._local : this._local.Where(selector.Match).ToArray();
            }
        }
    }
}
