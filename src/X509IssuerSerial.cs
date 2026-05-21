// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Org.BouncyCastle.Crypto.Xml;
using System;

namespace Org.BouncyCastle.X509
{
    public struct X509IssuerSerial
    {
        private String _issuerName;
        private String _serialNumber;

        internal X509IssuerSerial(String issuerName, String serialNumber)
        {
            if (issuerName == null || issuerName.Length == 0)
            {
                throw new ArgumentException(SR.Arg_EmptyOrNullString, "issuerName");
            }

            if (serialNumber == null || serialNumber.Length == 0)
            {
                throw new ArgumentException(SR.Arg_EmptyOrNullString, "serialNumber");
            }

            this._issuerName = issuerName;
            this._serialNumber = serialNumber;
        }


        public String IssuerName
        {
            get
            {
                return this._issuerName;
            }
            set
            {
                this._issuerName = value;
            }
        }

        public String SerialNumber
        {
            get
            {
                return this._serialNumber;
            }
            set
            {
                this._serialNumber = value;
            }
        }
    }
}
