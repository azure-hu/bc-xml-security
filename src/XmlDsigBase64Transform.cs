// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace Org.BouncyCastle.Crypto.Xml
{
    // A class representing conversion from Base64 using CryptoStream
    public class XmlDsigBase64Transform : Transform
    {
        private readonly Type[] _inputTypes = { typeof(Stream), typeof(XmlNodeList), typeof(XmlDocument) };
        private readonly Type[] _outputTypes = { typeof(Stream) };
        private CryptoStream _cs = null;

        public XmlDsigBase64Transform()
        {
            this.Algorithm = SignedXml.XmlDsigBase64TransformUrl;
        }

        public override Type[] InputTypes
        {
            get { return this._inputTypes; }
        }

        public override Type[] OutputTypes
        {
            get { return this._outputTypes; }
        }

        public override void LoadInnerXml(XmlNodeList nodeList)
        {
        }

        protected override XmlNodeList GetInnerXml()
        {
            return null;
        }

        public override void LoadInput(Object obj)
        {
            if (obj is Stream)
            {
                this.LoadStreamInput((Stream)obj);
                return;
            }
            if (obj is XmlNodeList)
            {
                this.LoadXmlNodeListInput((XmlNodeList)obj);
                return;
            }
            if (obj is XmlDocument)
            {
                this.LoadXmlNodeListInput(((XmlDocument)obj).SelectNodes("//."));
                return;
            }
        }

        private void LoadStreamInput(Stream inputStream)
        {
            if (inputStream == null)
            {
                throw new ArgumentException("obj");
            }

            MemoryStream ms = new MemoryStream();
            Byte[] buffer = new Byte[1024];
            Int32 bytesRead;
            do
            {
                bytesRead = inputStream.Read(buffer, 0, 1024);
                if (bytesRead > 0)
                {
                    Int32 i = 0;
                    Int32 j = 0;
                    while ((j < bytesRead) && (!Char.IsWhiteSpace((Char)buffer[j])))
                    {
                        j++;
                    }

                    i = j;
                    j++;
                    while (j < bytesRead)
                    {
                        if (!Char.IsWhiteSpace((Char)buffer[j]))
                        {
                            buffer[i] = buffer[j];
                            i++;
                        }
                        j++;
                    }
                    ms.Write(buffer, 0, i);
                }
            } while (bytesRead > 0);
            ms.Position = 0;
            this._cs = new CryptoStream(ms, new FromBase64Transform(), CryptoStreamMode.Read);
        }

        private void LoadXmlNodeListInput(XmlNodeList nodeList)
        {
            StringBuilder sb = new StringBuilder();
            foreach (XmlNode node in nodeList)
            {
                XmlNode result = node.SelectSingleNode("self::text()");
                if (result != null)
                {
                    sb.Append(result.OuterXml);
                }
            }
            UTF8Encoding utf8 = new UTF8Encoding(false);
            Byte[] buffer = utf8.GetBytes(sb.ToString());
            Int32 i = 0;
            Int32 j = 0;
            while ((j < buffer.Length) && (!Char.IsWhiteSpace((Char)buffer[j])))
            {
                j++;
            }

            i = j;
            j++;
            while (j < buffer.Length)
            {
                if (!Char.IsWhiteSpace((Char)buffer[j]))
                {
                    buffer[i] = buffer[j];
                    i++;
                }
                j++;
            }
            MemoryStream ms = new MemoryStream(buffer, 0, i);
            this._cs = new CryptoStream(ms, new FromBase64Transform(), CryptoStreamMode.Read);
        }

        public override Object GetOutput()
        {
            return this._cs;
        }

        public override Object GetOutput(Type type)
        {
            if (type != typeof(Stream) && !type.IsSubclassOf(typeof(Stream)))
            {
                throw new ArgumentException(SR.Cryptography_Xml_TransformIncorrectInputType, nameof(type));
            }

            return this._cs;
        }
    }
}
