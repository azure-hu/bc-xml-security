// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;
using System.Diagnostics.CodeAnalysis;

namespace Org.BouncyCastle.Crypto.Xml
{
    // abstract class providing symmetric key wrap implementation
    internal static class SymmetricKeyWrap
    {
        private static readonly Byte[] s_rgbTripleDES_KW_IV = { 0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05 };
        private static readonly Byte[] s_rgbAES_KW_IV = { 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6 };

        //
        // internal static methods
        //

        // CMS TripleDES KeyWrap as described in "http://www.w3.org/2001/04/xmlenc#kw-tripledes"
        [SuppressMessage("Microsoft.Cryptography", "CA5350", Justification = "Explicitly requested by the message contents")]
        internal static Byte[] TripleDESKeyWrapEncrypt(Byte[] rgbKey, Byte[] rgbWrappedKeyData)
        {
            Byte[] rgbCKS;

            IDigest sha = DigestUtilities.GetDigest("SHA-1");
            // checksum the key
            rgbCKS = new Byte[sha.GetDigestSize()];
            sha.BlockUpdate(rgbWrappedKeyData, 0, rgbWrappedKeyData.Length);
            sha.DoFinal(rgbCKS, 0);

            // generate a random IV
            Byte[] rgbIV = new Byte[8];
            SecureRandom rng = new SecureRandom();
            rng.NextBytes(rgbIV);

            // rgbWKCS = rgbWrappedKeyData | (first 8 bytes of the hash)
            Byte[] rgbWKCKS = new Byte[rgbWrappedKeyData.Length + 8];
            IBufferedCipher enc1 = null;
            IBufferedCipher enc2 = null;

            try
            {
                // Don't add padding, use CBC mode: for example, a 192 bits key will yield 40 bytes of encrypted data
                enc1 = CipherUtilities.GetCipher("DESEDE/CBC/NOPADDING");
                enc2 = CipherUtilities.GetCipher("DESEDE/CBC/NOPADDING");
                enc1.Init(true, new ParametersWithIV(new DesEdeParameters(rgbKey), rgbIV));
                enc2.Init(true, new ParametersWithIV(new DesEdeParameters(rgbKey), s_rgbTripleDES_KW_IV));

                Buffer.BlockCopy(rgbWrappedKeyData, 0, rgbWKCKS, 0, rgbWrappedKeyData.Length);
                Buffer.BlockCopy(rgbCKS, 0, rgbWKCKS, rgbWrappedKeyData.Length, 8);
                Byte[] temp1 = enc1.DoFinal(rgbWKCKS);
                Byte[] temp2 = new Byte[rgbIV.Length + temp1.Length];
                Buffer.BlockCopy(rgbIV, 0, temp2, 0, rgbIV.Length);
                Buffer.BlockCopy(temp1, 0, temp2, rgbIV.Length, temp1.Length);
                // temp2 = REV (rgbIV | E_k(rgbWrappedKeyData | rgbCKS))
                Array.Reverse(temp2);

                return enc2.DoFinal(temp2);
            }
            finally
            {

            }
        }

        [SuppressMessage("Microsoft.Cryptography", "CA5350", Justification = "Explicitly requested by the message contents")]
        internal static Byte[] TripleDESKeyWrapDecrypt(Byte[] rgbKey, Byte[] rgbEncryptedWrappedKeyData)
        {
            // Check to see whether the length of the encrypted key is reasonable
            if (rgbEncryptedWrappedKeyData.Length != 32 && rgbEncryptedWrappedKeyData.Length != 40
                && rgbEncryptedWrappedKeyData.Length != 48)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_KW_BadKeySize);
            }

            IBufferedCipher dec1 = null;
            IBufferedCipher dec2 = null;

            try
            {
                // Assume no padding, use CBC mode
                dec1 = CipherUtilities.GetCipher("DESEDE/CBC/NOPADDING");
                dec2 = CipherUtilities.GetCipher("DESEDE/CBC/NOPADDING");

                dec1.Init(false, new ParametersWithIV(new DesEdeParameters(rgbKey), s_rgbTripleDES_KW_IV));

                Byte[] temp2 = dec1.DoFinal(rgbEncryptedWrappedKeyData);
                Array.Reverse(temp2);
                // Get the IV and temp1
                Byte[] rgbIV = new Byte[8];
                Buffer.BlockCopy(temp2, 0, rgbIV, 0, 8);
                Byte[] temp1 = new Byte[temp2.Length - rgbIV.Length];
                Buffer.BlockCopy(temp2, 8, temp1, 0, temp1.Length);

                dec2.Init(false, new ParametersWithIV(new DesEdeParameters(rgbKey), rgbIV));
                Byte[] rgbWKCKS = dec2.DoFinal(temp1);

                // checksum the key
                Byte[] rgbWrappedKeyData = new Byte[rgbWKCKS.Length - 8];
                Buffer.BlockCopy(rgbWKCKS, 0, rgbWrappedKeyData, 0, rgbWrappedKeyData.Length);
                IDigest sha = DigestUtilities.GetDigest("SHA-1");
                Byte[] rgbCKS = new Byte[sha.GetDigestSize()];
                sha.BlockUpdate(rgbWrappedKeyData, 0, rgbWrappedKeyData.Length);
                sha.DoFinal(rgbCKS, 0);
                for (Int32 index = rgbWrappedKeyData.Length, index1 = 0; index < rgbWKCKS.Length; index++, index1++)
                {
                    if (rgbWKCKS[index] != rgbCKS[index1])
                    {
                        throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_BadWrappedKeySize);
                    }
                }

                return rgbWrappedKeyData;
            }
            finally
            {

            }
        }

        // AES KeyWrap described in "http://www.w3.org/2001/04/xmlenc#kw-aes***", as suggested by NIST
        internal static Byte[] AESKeyWrapEncrypt(Byte[] rgbKey, Byte[] rgbWrappedKeyData)
        {
            Int32 N = rgbWrappedKeyData.Length >> 3;
            // The information wrapped need not actually be a key, but it needs to be a multiple of 64 bits
            if ((rgbWrappedKeyData.Length % 8 != 0) || N <= 0)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_KW_BadKeySize);
            }

            IBufferedCipher enc = null;

            try
            {
                // Use ECB mode, no padding
                enc = CipherUtilities.GetCipher("AES/ECB/NOPADDING");
                enc.Init(true, new KeyParameter(rgbKey));
                // special case: only 1 block -- 8 bytes
                if (N == 1)
                {
                    // temp = 0xa6a6a6a6a6a6a6a6 | P(1)
                    Byte[] temp = new Byte[s_rgbAES_KW_IV.Length + rgbWrappedKeyData.Length];
                    Buffer.BlockCopy(s_rgbAES_KW_IV, 0, temp, 0, s_rgbAES_KW_IV.Length);
                    Buffer.BlockCopy(rgbWrappedKeyData, 0, temp, s_rgbAES_KW_IV.Length, rgbWrappedKeyData.Length);
                    return enc.DoFinal(temp);
                }
                // second case: more than 1 block
                Int64 t = 0;
                Byte[] rgbOutput = new Byte[(N + 1) << 3];
                // initialize the R_i's
                Buffer.BlockCopy(rgbWrappedKeyData, 0, rgbOutput, 8, rgbWrappedKeyData.Length);
                Byte[] rgbA = new Byte[8];
                Byte[] rgbBlock = new Byte[16];
                Buffer.BlockCopy(s_rgbAES_KW_IV, 0, rgbA, 0, 8);
                for (Int32 j = 0; j <= 5; j++)
                {
                    for (Int32 i = 1; i <= N; i++)
                    {
                        t = i + j * N;
                        Buffer.BlockCopy(rgbA, 0, rgbBlock, 0, 8);
                        Buffer.BlockCopy(rgbOutput, 8 * i, rgbBlock, 8, 8);
                        Byte[] rgbB = enc.DoFinal(rgbBlock);
                        for (Int32 k = 0; k < 8; k++)
                        {
                            Byte tmp = (Byte)((t >> (8 * (7 - k))) & 0xFF);
                            rgbA[k] = (Byte)(tmp ^ rgbB[k]);
                        }
                        Buffer.BlockCopy(rgbB, 8, rgbOutput, 8 * i, 8);
                    }
                }
                // Set the first block of rgbOutput to rgbA
                Buffer.BlockCopy(rgbA, 0, rgbOutput, 0, 8);
                return rgbOutput;
            }
            finally
            {

            }
        }

        internal static Byte[] AESKeyWrapDecrypt(Byte[] rgbKey, Byte[] rgbEncryptedWrappedKeyData)
        {
            Int32 N = (rgbEncryptedWrappedKeyData.Length >> 3) - 1;
            // The information wrapped need not actually be a key, but it needs to be a multiple of 64 bits
            if ((rgbEncryptedWrappedKeyData.Length % 8 != 0) || N <= 0)
            {
                throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_KW_BadKeySize);
            }

            Byte[] rgbOutput = new Byte[N << 3];
            IBufferedCipher dec = null;

            try
            {
                // Use ECB mode, no padding
                dec = CipherUtilities.GetCipher("AES/ECB/NOPADDING");
                dec.Init(false, new KeyParameter(rgbKey));

                // special case: only 1 block -- 8 bytes
                if (N == 1)
                {
                    Byte[] temp = dec.DoFinal(rgbEncryptedWrappedKeyData);
                    // checksum the key
                    for (Int32 index = 0; index < 8; index++)
                    {
                        if (temp[index] != s_rgbAES_KW_IV[index])
                        {
                            throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_BadWrappedKeySize);
                        }
                    }
                    // rgbOutput is LSB(temp)
                    Buffer.BlockCopy(temp, 8, rgbOutput, 0, 8);
                    return rgbOutput;
                }
                // second case: more than 1 block
                Int64 t = 0;
                // initialize the C_i's
                Buffer.BlockCopy(rgbEncryptedWrappedKeyData, 8, rgbOutput, 0, rgbOutput.Length);
                Byte[] rgbA = new Byte[8];
                Byte[] rgbBlock = new Byte[16];
                Buffer.BlockCopy(rgbEncryptedWrappedKeyData, 0, rgbA, 0, 8);
                for (Int32 j = 5; j >= 0; j--)
                {
                    for (Int32 i = N; i >= 1; i--)
                    {
                        t = i + j * N;
                        for (Int32 k = 0; k < 8; k++)
                        {
                            Byte tmp = (Byte)((t >> (8 * (7 - k))) & 0xFF);
                            rgbA[k] ^= tmp;
                        }
                        Buffer.BlockCopy(rgbA, 0, rgbBlock, 0, 8);
                        Buffer.BlockCopy(rgbOutput, 8 * (i - 1), rgbBlock, 8, 8);
                        Byte[] rgbB = dec.DoFinal(rgbBlock);
                        Buffer.BlockCopy(rgbB, 8, rgbOutput, 8 * (i - 1), 8);
                        Buffer.BlockCopy(rgbB, 0, rgbA, 0, 8);
                    }
                }
                // checksum the key
                for (Int32 index = 0; index < 8; index++)
                {
                    if (rgbA[index] != s_rgbAES_KW_IV[index])
                    {
                        throw new System.Security.Cryptography.CryptographicException(SR.Cryptography_Xml_BadWrappedKeySize);
                    }
                }

                return rgbOutput;
            }
            finally
            {

            }
        }
    }
}
