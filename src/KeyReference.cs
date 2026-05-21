// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace Org.BouncyCastle.Crypto.Xml
{
    public sealed class KeyReference : EncryptedReference
    {
        public KeyReference() : base()
        {
            this.ReferenceType = "KeyReference";
        }

        public KeyReference(System.String uri) : base(uri)
        {
            this.ReferenceType = "KeyReference";
        }

        public KeyReference(System.String uri, TransformChain transformChain) : base(uri, transformChain)
        {
            this.ReferenceType = "KeyReference";
        }
    }
}
