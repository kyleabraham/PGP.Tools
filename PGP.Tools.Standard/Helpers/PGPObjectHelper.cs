using Org.BouncyCastle.Bcpg.OpenPgp;
using System.IO;

namespace PGP.Tools.Standard.Helpers
{
    public class PGPObjectHelper
    {
        public static PgpPublicKeyEncryptedData ExtractPublicKeyEncryptedData(System.IO.Stream inputStream)
        {
            System.IO.Stream encodedFile = PgpUtilities.GetDecoderStream(inputStream);
            PgpEncryptedDataList encryptedDataList = GetEncryptedDataList(encodedFile);
            PgpPublicKeyEncryptedData publicKeyED = ExtractPublicKey(encryptedDataList);
            return publicKeyED;
        }

        public static PgpObject ProcessCompressedMessage(PgpObject message)
        {
            PgpCompressedData compressedData = (PgpCompressedData)message;
            Stream compressedDataStream = compressedData.GetDataStream();
            PgpObjectFactory compressedFactory = new PgpObjectFactory(compressedDataStream);
            message = CheckforOnePassSignatureList(message, compressedFactory);
            return message;
        }

        public static PgpObject CheckforOnePassSignatureList(PgpObject message, PgpObjectFactory compressedFactory)
        {
            message = compressedFactory.NextPgpObject();
            if (message is PgpOnePassSignatureList)
            {
                message = compressedFactory.NextPgpObject();
            }
            return message;
        }

        internal static PgpObject GetClearCompressedMessage(PgpPublicKeyEncryptedData publicKeyED, PGP.EncryptionKeys encryptionKeys)
        {
            PgpObjectFactory clearFactory = GetClearDataStream(encryptionKeys.PrivateKey, publicKeyED);
            PgpObject message = clearFactory.NextPgpObject();
            if (message is PgpOnePassSignatureList)
                message = clearFactory.NextPgpObject();
            return message;
        }

        public static PgpObjectFactory GetClearDataStream(PgpPrivateKey privateKey, PgpPublicKeyEncryptedData publicKeyED)
        {
            Stream clearStream = publicKeyED.GetDataStream(privateKey);
            PgpObjectFactory clearFactory = new PgpObjectFactory(clearStream);
            return clearFactory;
        }

        public static PgpPublicKeyEncryptedData ExtractPublicKey(PgpEncryptedDataList encryptedDataList)
        {
            PgpPublicKeyEncryptedData publicKeyED = null;
            foreach (PgpPublicKeyEncryptedData privateKeyED in encryptedDataList.GetEncryptedDataObjects())
            {
                if (privateKeyED != null)
                {
                    publicKeyED = privateKeyED;
                    break;
                }
            }
            return publicKeyED;
        }

        public static PgpEncryptedDataList GetEncryptedDataList(Stream encodedFile)
        {
            PgpObjectFactory factory = new PgpObjectFactory(encodedFile);
            PgpObject pgpObject = factory.NextPgpObject();

            PgpEncryptedDataList encryptedDataList;

            if (pgpObject is PgpEncryptedDataList)
            {
                encryptedDataList = (PgpEncryptedDataList)pgpObject;
            }
            else
            {
                encryptedDataList = (PgpEncryptedDataList)factory.NextPgpObject();
            }
            return encryptedDataList;
        }
    }
}
