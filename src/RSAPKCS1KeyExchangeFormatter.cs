// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;

namespace Org.BouncyCastle.Crypto.Xml
{
    public class RSAPKCS1KeyExchangeFormatter
    {
        private RsaKeyParameters _rsaKey;
        private SecureRandom RngValue;

        public RSAPKCS1KeyExchangeFormatter() { }

        public RSAPKCS1KeyExchangeFormatter(RsaKeyParameters key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            this._rsaKey = key;
        }

        public String Parameters
        {
            get
            {
                return "<enc:KeyEncryptionMethod enc:Algorithm=\"http://www.microsoft.com/xml/security/algorithm/PKCS1-v1.5-KeyEx\" xmlns:enc=\"http://www.microsoft.com/xml/security/encryption/v1.0\" />";
            }
        }

        public SecureRandom Rng
        {
            get { return this.RngValue; }
            set { this.RngValue = value; }
        }

        public void SetKey(RsaKeyParameters key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            this._rsaKey = key;
        }

        public Byte[] CreateKeyExchange(Byte[] rgbData, Type symAlgType)
        {
            return this.CreateKeyExchange(rgbData);
        }

        public Byte[] CreateKeyExchange(Byte[] rgbData)
        {
            if (this._rsaKey == null)
            {
                throw new System.Security.Cryptography.CryptographicUnexpectedOperationException(SR.Cryptography_MissingKey);
            }

            IBufferedCipher rsa = CipherUtilities.GetCipher("RSA//PKCS1PADDING");
            rsa.Init(true, this._rsaKey);

            return rsa.DoFinal(rgbData);
        }
    }
}
