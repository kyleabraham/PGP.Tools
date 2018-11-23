using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Utilities.IO;
using PGP.Tools.Standard.Extensions;
using PGP.Tools.Standard.Helpers;
using System;
using System.IO;
using System.Threading.Tasks;

namespace PGP.Tools.Standard.PGP
{
    public class Decrypt : BaseEncryptDecrypt
    {
        public static readonly Decrypt Instance = new Decrypt();

        public Decrypt() : base() { }

        #region Decrypt

        public async Task DecryptFileWithStringAsync(string inputFilePath, string outputFilePath, string privateKeyString, string passPhrase)
        {
            await Task.Run(() => DecryptFileWithStringKey(inputFilePath: inputFilePath, outputFilePath: outputFilePath, privateKeyString: privateKeyString, passPhrase: passPhrase));
        }
        public async Task DecryptFileWithPathAsync(string inputFilePath, string outputFilePath, string privateKeyFilePath, string passPhrase)
        {
            await Task.Run(() => DecryptFileWithPath(inputFilePath, outputFilePath, privateKeyFilePath, passPhrase));
        }
        public async Task DecryptFileWithStreamAsync(string inputFilePath, string outputFilePath, Stream privateKeyStream, string passPhrase)
        {
            await Task.Run(() => DecryptFileWithStream(inputFilePath, outputFilePath, privateKeyStream, passPhrase));
        }

        public void DecryptFileWithStringKey(string inputFilePath, string outputFilePath, string privateKeyString, string passPhrase)
        {
            if (string.IsNullOrEmpty(privateKeyString))
                throw new ArgumentException("publicKeyString");
            using (Stream keySteam = privateKeyString.ToStream())
            {
                this.DecryptFileWithStream(
                    inputFilePath: inputFilePath,
                    outputFilePath: outputFilePath,
                    privateKeyStream: keySteam,
                    passPhrase: passPhrase);
            }
        }
        /// <summary>
        /// PGP decrypt a given file.
        /// </summary>
        /// <param name="inputFilePath"></param>
        /// <param name="outputFilePath"></param>
        /// <param name="privateKeyFilePath"></param>
        /// <param name="passPhrase"></param>
        public void DecryptFileWithPath(string inputFilePath, string outputFilePath, string privateKeyFilePath, string passPhrase)
        {
            if (string.IsNullOrEmpty(privateKeyFilePath))
                throw new ArgumentException("PrivateKeyFilePath");
            if (!File.Exists(privateKeyFilePath))
                throw new FileNotFoundException(string.Format("Private Key File [{0}] not found.", privateKeyFilePath));

            using (Stream keyStream = File.OpenRead(privateKeyFilePath))
            {
                DecryptFileWithStream(inputFilePath: inputFilePath, outputFilePath: outputFilePath, privateKeyStream: keyStream, passPhrase: passPhrase);
            }
        }
        public void DecryptFileWithStream(string inputFilePath, string outputFilePath, Stream privateKeyStream, string passPhrase)
        {
            if (string.IsNullOrEmpty(inputFilePath))
                throw new ArgumentException("InputFilePath");
            if (string.IsNullOrEmpty(outputFilePath))
                throw new ArgumentException("OutputFilePath");
            if (passPhrase == null)
                passPhrase = string.Empty;

            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException(string.Format("Encrypted File [{0}] not found.", inputFilePath));

            using (Stream inputStream = File.OpenRead(inputFilePath))
            {
                using (Stream outStream = File.Create(outputFilePath))
                    DecryptStream(inputStream, outStream, privateKeyStream, passPhrase);
            }
        }

        /*
        * PGP decrypt a given stream.
        */
        private void DecryptStream(Stream inputStream, Stream outputStream, Stream privateKeyStream, string passPhrase)
        {
            if (inputStream == null)
                throw new ArgumentException("InputStream");
            if (outputStream == null)
                throw new ArgumentException("outputStream");
            if (privateKeyStream == null)
                throw new ArgumentException("privateKeyStream");
            if (passPhrase == null)
                passPhrase = string.Empty;

            PgpObjectFactory objFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
            // find secret key
            PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));

            PgpObject obj = null;
            if (objFactory != null)
                obj = objFactory.NextPgpObject();

            // the first object might be a PGP marker packet.
            PgpEncryptedDataList enc = null;
            if (obj is PgpEncryptedDataList)
                enc = (PgpEncryptedDataList)obj;
            else
                enc = (PgpEncryptedDataList)objFactory.NextPgpObject();

            // decrypt
            PgpPrivateKey privateKey = null;
            PgpPublicKeyEncryptedData pbe = null;
            foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
            {
                privateKey = PGPKeyHelper.FindSecretKey(pgpSec, pked.KeyId, passPhrase.ToCharArray());

                if (privateKey != null)
                {
                    pbe = pked;
                    break;
                }
            }

            if (privateKey == null)
                throw new ArgumentException("Secret key for message not found.");

            PgpObjectFactory plainFact = null;

            using (Stream clear = pbe.GetDataStream(privateKey))
            {
                plainFact = new PgpObjectFactory(clear);
            }

            PgpObject message = plainFact.NextPgpObject();
            if (message is PgpOnePassSignatureList)
                message = plainFact.NextPgpObject();

            if (message is PgpCompressedData)
            {
                PgpCompressedData cData = (PgpCompressedData)message;
                PgpObjectFactory of = null;

                using (Stream compDataIn = cData.GetDataStream())
                {
                    of = new PgpObjectFactory(compDataIn);
                }

                message = of.NextPgpObject();
                if (message is PgpOnePassSignatureList)
                {
                    message = of.NextPgpObject();
                    PgpLiteralData Ld = null;
                    Ld = (PgpLiteralData)message;
                    Stream unc = Ld.GetInputStream();
                    Streams.PipeAll(unc, outputStream);
                }
                else
                {
                    PgpLiteralData Ld = null;
                    Ld = (PgpLiteralData)message;
                    Stream unc = Ld.GetInputStream();
                    Streams.PipeAll(unc, outputStream);
                }
            }
            else if (message is PgpLiteralData)
            {
                PgpLiteralData ld = (PgpLiteralData)message;
                string outFileName = ld.FileName;

                Stream unc = ld.GetInputStream();
                Streams.PipeAll(unc, outputStream);
            }
            else if (message is PgpOnePassSignatureList)
                throw new PgpException("Encrypted message contains a signed message - not literal data.");
            else
                throw new PgpException("Message is not a simple encrypted file.");
        }

        public async Task DecryptFileAndVerifyAsync(string inputFilePath, string outputFilePath, string publicKeyFilePath, string privateKeyFilePath, string passPhrase)
        {
            await Task.Run(() => DecryptFileAndVerify(inputFilePath, outputFilePath, publicKeyFilePath, privateKeyFilePath, passPhrase));
        }

        public void DecryptFileAndVerify(string inputFilePath, string outputFilePath, string publicKeyFilePath, string privateKeyFilePath, string passPhrase)
        {
            if (string.IsNullOrEmpty(inputFilePath))
                throw new ArgumentException("InputFilePath");
            if (string.IsNullOrEmpty(outputFilePath))
                throw new ArgumentException("OutputFilePath");
            if (string.IsNullOrEmpty(publicKeyFilePath))
                throw new ArgumentException("PublicKeyFilePath");
            if (string.IsNullOrEmpty(privateKeyFilePath))
                throw new ArgumentException("PrivateKeyFilePath");
            if (passPhrase == null)
                passPhrase = string.Empty;

            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException(string.Format("Encrypted File [{0}] not found.", inputFilePath));
            if (!File.Exists(publicKeyFilePath))
                throw new FileNotFoundException(string.Format("Public Key File [{0}] not found.", publicKeyFilePath));
            if (!File.Exists(privateKeyFilePath))
                throw new FileNotFoundException(string.Format("Private Key File [{0}] not found.", privateKeyFilePath));

            PGP.EncryptionKeys encryptionKeys = new PGP.EncryptionKeys(publicKeyFilePath, privateKeyFilePath, passPhrase);

            if (encryptionKeys == null)
                throw new ArgumentNullException("Encryption Key not found.");

            using (Stream inputStream = File.OpenRead(inputFilePath))
            {
                PgpPublicKeyEncryptedData publicKeyED = PGPObjectHelper.ExtractPublicKeyEncryptedData(inputStream);
                if (publicKeyED.KeyId != encryptionKeys.PublicKey.KeyId)
                    throw new PgpException(string.Format("Failed to verify file."));

                PgpObject message = PGPObjectHelper.GetClearCompressedMessage(publicKeyED, encryptionKeys);

                if (message is PgpCompressedData)
                {
                    message = PGPObjectHelper.ProcessCompressedMessage(message);
                    PgpLiteralData literalData = (PgpLiteralData)message;
                    using (Stream outputFile = File.Create(outputFilePath))
                    {
                        using (Stream literalDataStream = literalData.GetInputStream())
                        {
                            Streams.PipeAll(literalDataStream, outputFile);
                        }
                    }
                }
                else if (message is PgpLiteralData)
                {
                    PgpLiteralData literalData = (PgpLiteralData)message;
                    using (Stream outputFile = File.Create(outputFilePath))
                    {
                        using (Stream literalDataStream = literalData.GetInputStream())
                        {
                            Streams.PipeAll(literalDataStream, outputFile);
                        }
                    }
                }
                else
                    throw new PgpException("Message is not a simple encrypted file.");
            }

            return;
        }

        #endregion Decrypt
    }
}
