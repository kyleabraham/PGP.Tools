using Org.BouncyCastle.Bcpg.OpenPgp;
using PGP.Tools.Standard.Enums;
using System;

namespace PGP.Tools.Standard.PGP
{
    public class BaseEncryptDecrypt : IDisposable
    {
        protected const int BufferSize = 0x10000;

        public CompressionAlgorithm CompressionAlgorithm { get; set; }
        public SymmetricKeyAlgorithm SymmetricKeyAlgorithm { get; set; }
        public PublicKeyAlgorithm PublicKeyAlgorithm { get; set; }
        public PGPFileType FileType { get; set; }
        public int PgpSignatureType { get; set; }

        #region Constructor

        public BaseEncryptDecrypt()
        {
            CompressionAlgorithm = CompressionAlgorithm.Uncompressed;
            SymmetricKeyAlgorithm = SymmetricKeyAlgorithm.TripleDes;
            PgpSignatureType = PgpSignature.DefaultCertification;
            PublicKeyAlgorithm = PublicKeyAlgorithm.RsaGeneral;
            FileType = PGPFileType.Binary;
        }

        #endregion Constructor

        #region Shared Methods

        protected char FileTypeToChar()
        {
            if (FileType == PGPFileType.UTF8)
                return PgpLiteralData.Utf8;
            else if (FileType == PGPFileType.Text)
                return PgpLiteralData.Text;
            else
                return PgpLiteralData.Binary;

        }

        #endregion

        public void Dispose()
        {
        }
    }
}
