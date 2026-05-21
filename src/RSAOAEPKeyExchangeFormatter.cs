// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System;

namespace Org.BouncyCastle.Crypto.Xml
{
    public class RSAOAEPKeyExchangeFormatter
    {
        private Byte[] ParameterValue;
        private RsaKeyParameters _rsaKey;
        private SecureRandom RngValue;

        public RSAOAEPKeyExchangeFormatter() { }
        public RSAOAEPKeyExchangeFormatter(RsaKeyParameters key)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            this._rsaKey = key;
        }

        public Byte[] Parameter
        {
            get
            {
                if (this.ParameterValue != null)
                {
                    return (Byte[])this.ParameterValue.Clone();
                }

                return null;
            }
            set
            {
                if (value != null)
                {
                    this.ParameterValue = (Byte[])value.Clone();
                }
                else
                {
                    this.ParameterValue = null;
                }
            }
        }

        public String Parameters
        {
            get { return null; }
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

            IBufferedCipher rsa = CipherUtilities.GetCipher("RSA//OAEPPADDING");
            rsa.Init(true, this._rsaKey);

            return rsa.DoFinal(rgbData);
        }
    }
}
