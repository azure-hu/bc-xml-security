// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Org.BouncyCastle.Crypto.Agreement.Kdf;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    // Based on: https://github.com/unofficial-shibboleth-mirror/java-opensaml/blob/main/opensaml-xmlsec-impl/src/main/java/org/opensaml/xmlsec/derivation/impl/ConcatKDF.java


/// <summary>
/// <![CDATA[Implementation of ConcatKDF key derivation as defined in XML Encryption 1.1.
///
/// The following rules apply to the concatenation parameters: [ AlgorithmID, PartyUInfo, PartyVInfo, SuppPubInfo, SuppPrivInfo]
/// 
/// Configured parameter string values must conform to the XML <code>Binary</code> representation defined in
/// XML Encryption 1.1, section 5.4.1, except in <b>unpadded</b> form, with number of padding bits not indicated.
/// Per the recommendation in the XML Encryption specification, this implementation only supports whole byte
/// (bye-aligned) values, not arbitrary length bit-strings as theoretically allowed in the NIST specification,
/// so the # of padding bits for each parameter value in the XML representation must and will always be 0.
/// This means the methods {@link #unpadParam(String, String)} and {@link #fromXMLObject(KeyDerivationMethod)}
/// which consume external values from the XML representation will throw if the number of indicated padding bits
/// is non-zero. Similarly {@link #buildXMLObject()} will always emit values which indicate 0 padding bits.]]>
/// </summary>
public class ConcatKDFParams : KeyDerivationParamsClause
{
    private class ConcatenationParam
    {
        private readonly String _str;
        public ConcatenationParam(String str)
        {
            this._str = UnpadParam(str);
        }

        public static implicit operator String(ConcatenationParam str)
        {
            return PadParam(str._str);
        }

        public static implicit operator ConcatenationParam(String str)
        {
            return new ConcatenationParam(str);
        }

        /// <summary>
        /// <![CDATA[Pad the specified concatenation parameter value for output in the formed
        /// required by XML Encryption 1.1.
        /// No syntactic validation is done on the input value.
        /// Since only whole byte-aligned values are supported, this method merely prepends "00" to indicate 0 padding bits.
        /// ]]>
        /// </summary>
        /// <param name="value">the value to process</param>
        /// <returns>the padded value, which may be null</returns>
        protected static String PadParam(String value)
        {
            if (String.IsNullOrWhiteSpace(value))
            {
                return null;
            }
            String trimmed = value.Trim();
            return "00" + trimmed;

        }

        /// <summary>
        /// <![CDATA[Unpad the specified concatenation parameter value from the padded form
        /// required by XML Encryption 1.1 for input to the derivation operation.
        /// Since only whole byte-aligned values are supported, this method requires input values
        /// to begin with "00", indicating 0 padding bits.
        /// ]]>
        /// </summary>
        /// <param name="value">the value to process</param>
        /// <returns>the unpadded value, which may be null</returns>
        protected static String UnpadParam(String value)
        {

            if (String.IsNullOrWhiteSpace(value))
            {
                return null;
            }

            String trimmed = value.Trim();
            if (trimmed.Length < 2)
            {
                throw new ArgumentException("ConcatKDF parameter was not a valid padded Binary value (too short)");
            }
            if (trimmed.Length % 2 != 0)
            {
                throw new ArgumentException("ConcatKDF parameter was not a valid padded Binary value (odd number of  digits)");
            }

            // We only support whole byte-aligned values, so # of padding bits must always be 0
            if (!trimmed.StartsWith("00"))
            {
                throw new ArgumentException("ConcatKDF parameter was not a valid padded Binary value (non-byte-aligned)");
            }

            // As of OSJ-355, we treat "00" as a legal value, representing an empty bitstring.
            // The following will return "" in that case, which is ok.

            return trimmed.Substring(2);
        }

        /// <summary>
        /// Decodes the concatenation parameter value for input to the derivation operation.
        /// </summary>
        /// <returns>the decoded value, which may be an empty array</returns>
        public Byte[] Decode()
        {
            String value = this._str;

            if (String.IsNullOrWhiteSpace(value))
            {
                return new Byte[] { };
            }
            String trimmed = value.Trim();

            Byte[] decoded;
            try
            {
                decoded = Hex.Decode(trimmed);
            }
            catch (Exception e)
            {
                throw new ArgumentException("ConcatKDF parameter was not valid -encoded value", e);
            }
            return decoded;
        }
    }

    private const String algorithmUri = "http://www.w3.org/2009/xmlenc11#ConcatKDF";

    private DigestMethod _digestMethod;
    private ConcatenationParam _algorithmId;
    private ConcatenationParam _partyUInfo;
    private ConcatenationParam _partyVInfo;
    private ConcatenationParam _suppPubInfo;
    private ConcatenationParam _suppPrivInfo;

    //
    // public constructors
    //

    public ConcatKDFParams() { }
    public ConcatKDFParams(DigestMethod digestMethod) { this._digestMethod = digestMethod; }

    public ConcatKDFParams(DigestMethod digestMethod, String algorithmId, String partyUInfo, String partyVInfo,
        String suppPubInfo, String suppPrivInfo) : this(digestMethod)
    {
        this._algorithmId = algorithmId;
        this._partyUInfo = partyUInfo;
        this._partyVInfo = partyVInfo;
        this._suppPubInfo = suppPubInfo;
        this._suppPrivInfo = suppPrivInfo;
        ;
    }

    private static Byte[] Concatenate(params ConcatenationParam[] concatParams)
    {
        IList<Byte[]> arrays = new List<Byte[]>(concatParams.Length);
        foreach (ConcatenationParam param in concatParams)
        {
            arrays.Add(param.Decode());
        }

        Byte[] rv = new Byte[arrays.Sum(a => a.Length)];
        Int32 offset = 0;
        foreach (Byte[] array in arrays)
        {
            Buffer.BlockCopy(array, 0, rv, offset, array.Length);
            offset += array.Length;
        }
        return rv;
    }


    public override String Algorithm { get { return algorithmUri; } }

    //
    // public methods
    //

    public Byte[] DeriveKey(Int32 keyLength, Byte[] sharedSecret)
    {
        Boolean le = BitConverter.IsLittleEndian;

        // Concatenate other info
        Byte[] otherInfo = Concatenate(this._algorithmId, this._partyUInfo, this._partyVInfo, this._suppPubInfo, this._suppPrivInfo);

        Byte[] derivedKey = new Byte[keyLength];

        // derive key
        IDigest digest = CryptoHelpers.CreateFromName<IDigest>(this._digestMethod.Algorithm);
        ConcatenationKdfGenerator concatKdf = new ConcatenationKdfGenerator(digest);
        KdfParameters kdfParams = new KdfParameters(sharedSecret, otherInfo);
        concatKdf.Init(kdfParams);
        concatKdf.GenerateBytes(derivedKey, 0, keyLength);
        return derivedKey;

    }

    public Byte[] DeriveKeyEncryptionKey(String keyEncryptionMethod, Byte[] sharedSecret)
    {

        Int32 keyEncryptionKeySize = XmlSecAlgorithmUtil.GetKeySize(keyEncryptionMethod);
        Int32 keyEncryptionKeyLength = keyEncryptionKeySize / 8;

        return this.DeriveKey(keyEncryptionKeyLength, sharedSecret);
    }

    public override XmlElement GetXml()
    {
        XmlDocument xmlDocument = new XmlDocument();
        xmlDocument.PreserveWhitespace = true;
        return this.GetXml(xmlDocument);
    }

    internal override XmlElement GetXml(XmlDocument xmlDocument)
    {
        XmlElement concatKdfParamsElement = xmlDocument.CreateElement(EncryptedXml.DefaultXmlEnc11NamespacePrefix, "ConcatKDFParams", EncryptedXml.XmlEnc11NamespaceUrl);
        XmlElement digestMethodElement = this._digestMethod.GetXml(xmlDocument);
        concatKdfParamsElement.AppendChild(digestMethodElement);
        concatKdfParamsElement.SetAttribute("AlgorithmID", (this._algorithmId ?? String.Empty));
        concatKdfParamsElement.SetAttribute("PartyUInfo", (this._partyUInfo ?? String.Empty));
        concatKdfParamsElement.SetAttribute("PartyVInfo", (this._partyVInfo ?? String.Empty));
        concatKdfParamsElement.SetAttribute("SuppPubInfo", (this._suppPubInfo ?? String.Empty));
        concatKdfParamsElement.SetAttribute("SuppPrivInfo", (this._suppPrivInfo ?? String.Empty));
        return concatKdfParamsElement;
    }

    public override void LoadXml(XmlElement value)
    {
        if (value == null)
        {
            throw new ArgumentNullException(nameof(value));
        }

        this._algorithmId = Utils.GetAttribute(value, "AlgorithmID", EncryptedXml.XmlEnc11NamespaceUrl);
        this._partyUInfo = Utils.GetAttribute(value, "PartyUInfo", EncryptedXml.XmlEnc11NamespaceUrl);
        this._partyVInfo = Utils.GetAttribute(value, "PartyVInfo", EncryptedXml.XmlEnc11NamespaceUrl);
        this._suppPubInfo = Utils.GetAttribute(value, "SuppPubInfo", EncryptedXml.XmlEnc11NamespaceUrl);
        this._suppPrivInfo = Utils.GetAttribute(value, "SuppPrivInfo", EncryptedXml.XmlEnc11NamespaceUrl);

        XmlNamespaceManager nsm = new XmlNamespaceManager(value.OwnerDocument.NameTable);
        nsm.AddNamespace(SignedXml.DefaultXmlDsigNamespacePrefix, SignedXml.XmlDsigNamespaceUrl);
        nsm.AddNamespace(EncryptedXml.DefaultXmlEncNamespacePrefix, EncryptedXml.XmlEncNamespaceUrl);


        XmlNode digestMethodNode = value.SelectSingleNode(SignedXml.DefaultXmlDsigNamespacePrefix + ":DigestMethod", nsm);
        if (digestMethodNode != null)
        {
            DigestMethod digestMethod = new DigestMethod();
            digestMethod.LoadXml(digestMethodNode as XmlElement);
            this._digestMethod = digestMethod;
        }
    }
}
}
