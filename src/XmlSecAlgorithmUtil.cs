using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Ntt;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.TeleTrust;
using System;
using System.Collections.Generic;

namespace Org.BouncyCastle.Crypto.Xml
{
    public static class XmlSecAlgorithmUtil
    {
        private struct AlgorithmInfo
        {
            public DerObjectIdentifier Oid { get; }
            public Int32 KeySize { get; }

            public AlgorithmInfo(DerObjectIdentifier oid, Int32 keySize)
            {
                this.Oid = oid;
                this.KeySize = keySize;
            }
        }

        private static readonly Dictionary<String, AlgorithmInfo> uriInfoMap;

        static XmlSecAlgorithmUtil()
        {
            uriInfoMap = new Dictionary<String, AlgorithmInfo>();
            uriInfoMap.Add("http://www.w3.org/2001/04/xmldsig-more#md5", new AlgorithmInfo(PkcsObjectIdentifiers.MD5, 128));
            uriInfoMap.Add("http://www.w3.org/2001/04/xmlenc#ripemd160", new AlgorithmInfo(TeleTrusTObjectIdentifiers.RipeMD160, 160));
            uriInfoMap.Add("http://www.w3.org/2007/05/xmldsig-more#whirlpool", new AlgorithmInfo(new DerObjectIdentifier("1.0.10118.3.0.55"), 512));

            // SHA-1
            uriInfoMap.Add(SignedXml.XmlDsigSHA1Url, new AlgorithmInfo(OiwObjectIdentifiers.IdSha1, 160));

            // SHA-2
            uriInfoMap.Add(SignedXml.XmlDsigMoreSHA224Url, new AlgorithmInfo(NistObjectIdentifiers.IdSha224, 224));
            uriInfoMap.Add(EncryptedXml.XmlEncSHA256Url, new AlgorithmInfo(NistObjectIdentifiers.IdSha256, 256));
            uriInfoMap.Add(SignedXml.XmlDsigMoreSHA384Url, new AlgorithmInfo(NistObjectIdentifiers.IdSha384, 384));
            uriInfoMap.Add(EncryptedXml.XmlEncSHA512Url, new AlgorithmInfo(NistObjectIdentifiers.IdSha512, 512));

            // SHA-3
            uriInfoMap.Add(SignedXml.XmlDsigMoreSHA3_224Url, new AlgorithmInfo(NistObjectIdentifiers.IdSha3_224, 224));
            uriInfoMap.Add(SignedXml.XmlDsigMoreSHA3_256Url, new AlgorithmInfo(NistObjectIdentifiers.IdSha3_256, 256));
            uriInfoMap.Add(SignedXml.XmlDsigMoreSHA3_384Url, new AlgorithmInfo(NistObjectIdentifiers.IdSha3_384, 384));
            uriInfoMap.Add(SignedXml.XmlDsigMoreSHA3_512Url, new AlgorithmInfo(NistObjectIdentifiers.IdSha3_512, 512));

            // AES-CBC
            uriInfoMap.Add(EncryptedXml.XmlEncAES128Url, new AlgorithmInfo(NistObjectIdentifiers.IdAes128Cbc, 128));
            uriInfoMap.Add(EncryptedXml.XmlEncAES192Url, new AlgorithmInfo(NistObjectIdentifiers.IdAes192Cbc, 192));
            uriInfoMap.Add(EncryptedXml.XmlEncAES256Url, new AlgorithmInfo(NistObjectIdentifiers.IdAes256Cbc, 256));

            // AES-GCM
            uriInfoMap.Add("http://www.w3.org/2009/xmlenc11#aes128-gcm", new AlgorithmInfo(NistObjectIdentifiers.IdAes128Gcm, 128));
            uriInfoMap.Add("http://www.w3.org/2009/xmlenc11#aes192-gcm", new AlgorithmInfo(NistObjectIdentifiers.IdAes192Gcm, 192));
            uriInfoMap.Add("http://www.w3.org/2009/xmlenc11#aes256-gcm", new AlgorithmInfo(NistObjectIdentifiers.IdAes256Gcm, 256));

            // AES-KW
            uriInfoMap.Add(EncryptedXml.XmlEncAES128KeyWrapUrl, new AlgorithmInfo(NistObjectIdentifiers.IdAes128Wrap, 128));
            uriInfoMap.Add(EncryptedXml.XmlEncAES192KeyWrapUrl, new AlgorithmInfo(NistObjectIdentifiers.IdAes192Wrap, 192));
            uriInfoMap.Add(EncryptedXml.XmlEncAES256KeyWrapUrl, new AlgorithmInfo(NistObjectIdentifiers.IdAes256Wrap, 256));

            // AES-KW-PAD
            uriInfoMap.Add(EncryptedXml.XmlEnc11AES128KeyWrapPadUrl, new AlgorithmInfo(NistObjectIdentifiers.IdAes128WrapPad, 128));
            uriInfoMap.Add(EncryptedXml.XmlEnc11AES256KeyWrapPadUrl, new AlgorithmInfo(NistObjectIdentifiers.IdAes192WrapPad, 192));
            uriInfoMap.Add(EncryptedXml.XmlEnc11AES256KeyWrapPadUrl, new AlgorithmInfo(NistObjectIdentifiers.IdAes256WrapPad, 256));

            // CAMELLIA-CBC
            uriInfoMap.Add(SignedXml.XmlDsigMoreCamellia128Url, new AlgorithmInfo(NttObjectIdentifiers.IdCamellia128Cbc, 128));
            uriInfoMap.Add(SignedXml.XmlDsigMoreCamellia192Url, new AlgorithmInfo(NttObjectIdentifiers.IdCamellia192Cbc, 192));
            uriInfoMap.Add(SignedXml.XmlDsigMoreCamellia256Url, new AlgorithmInfo(NttObjectIdentifiers.IdCamellia256Cbc, 256));


            // CAMELLIA-KW
            uriInfoMap.Add(SignedXml.XmlDsigMoreCamellia128KeyWrapUrl, new AlgorithmInfo(NttObjectIdentifiers.IdCamellia128Wrap, 128));
            uriInfoMap.Add(SignedXml.XmlDsigMoreCamellia192KeyWrapUrl, new AlgorithmInfo(NttObjectIdentifiers.IdCamellia192Wrap, 192));
            uriInfoMap.Add(SignedXml.XmlDsigMoreCamellia256KeyWrapUrl, new AlgorithmInfo(NttObjectIdentifiers.IdCamellia256Wrap, 256));
        }

        public static DerObjectIdentifier GetOid(String xmlAgorithmUri)
        {
            if (uriInfoMap.ContainsKey(xmlAgorithmUri))
            {
                return uriInfoMap[xmlAgorithmUri].Oid;
            }
            return null;
        }

        public static Int32 GetKeySize(String xmlAgorithmUri)
        {
            if (uriInfoMap.ContainsKey(xmlAgorithmUri))
            {
                return uriInfoMap[xmlAgorithmUri].KeySize;
            }
            return -1;
        }
    }
}
