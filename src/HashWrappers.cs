using System;

namespace Org.BouncyCastle.Crypto.Xml
{
    public interface IHash
    {
        void Reset();
        void BlockUpdate(Byte[] input, Int32 inOff, Int32 length);
        Int32 GetHashSize();
        Int32 DoFinal(Byte[] output, Int32 outOff);
    }

    public class SignerHashWrapper : IHash
    {
        private readonly ISigner _signer;

        public SignerHashWrapper(ISigner signer)
        {
            this._signer = signer;
        }

        public void BlockUpdate(Byte[] input, Int32 inOff, Int32 length)
        {
            this._signer.BlockUpdate(input, inOff, length);
        }

        public Int32 DoFinal(Byte[] output, Int32 outOff)
        {
            throw new NotSupportedException();
        }

        public Int32 GetHashSize()
        {
            throw new NotSupportedException();
        }

        public void Reset()
        {
            this._signer.Reset();
        }
    }

    public class MacHashWrapper : IHash
    {
        private readonly IMac _mac;

        public MacHashWrapper(IMac mac)
        {
            this._mac = mac;
        }

        public void BlockUpdate(Byte[] input, Int32 inOff, Int32 length)
        {
            this._mac.BlockUpdate(input, inOff, length);
        }

        public Int32 DoFinal(Byte[] output, Int32 outOff)
        {
            return this._mac.DoFinal(output, outOff);
        }

        public Int32 GetHashSize()
        {
            return this._mac.GetMacSize();
        }

        public void Reset()
        {
            this._mac.Reset();
        }
    }

    public class DigestHashWrapper : IHash
    {
        private readonly IDigest _digest;

        public DigestHashWrapper(IDigest digest)
        {
            this._digest = digest;
        }

        public void BlockUpdate(Byte[] input, Int32 inOff, Int32 length)
        {
            this._digest.BlockUpdate(input, inOff, length);
        }

        public Int32 DoFinal(Byte[] output, Int32 outOff)
        {
            return this._digest.DoFinal(output, outOff);
        }

        public Int32 GetHashSize()
        {
            return this._digest.GetDigestSize();
        }

        public void Reset()
        {
            this._digest.Reset();
        }
    }
}
