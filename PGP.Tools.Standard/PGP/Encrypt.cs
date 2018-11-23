using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using PGP.Tools.Standard.Enums;
using PGP.Tools.Standard.Extensions;
using PGP.Tools.Standard.Helpers;
using System;
using System.IO;
using System.Threading.Tasks;

namespace PGP.Tools.Standard.PGP
{
    public class Encrypt : BaseEncryptDecrypt
    {
        public static readonly Encrypt Instance = new Encrypt();

        public Encrypt() : base() { }

        #region Encrypt

        public async Task EncryptFileWithStringKeyAsync(string inputFilePath, string outputFilePath, string publicKeyString, bool armor = true, bool withIntegrityCheck = true)
        {
            await Task.Run(() => EncryptFileWithStringKey(inputFilePath: inputFilePath, outputFilePath: outputFilePath, publicKeyString: publicKeyString, armor: armor, withIntegrityCheck: withIntegrityCheck));
        }

        public async Task EncryptFileWithPathKeyAsync(string inputFilePath, string outputFilePath, string publicKeyFilePath, bool armor = true, bool withIntegrityCheck = true)
        {
            await Task.Run(() => EncryptFileWithPathKey(inputFilePath: inputFilePath, outputFilePath: outputFilePath, publicKeyFilePath: publicKeyFilePath, armor: armor, withIntegrityCheck: withIntegrityCheck));
        }

        public async Task EncryptFileWithStreamKeyAsync(string inputFilePath, string outputFilePath, Stream publicKeyStream, bool armor = true, bool withIntegrityCheck = true)
        {
            await Task.Run(() => EncryptFileWithStreamKey(inputFilePath: inputFilePath, outputFilePath: outputFilePath, publicKeyStream: publicKeyStream, armor: armor, withIntegrityCheck: withIntegrityCheck));
        }

        public void EncryptFileWithStringKey(string inputFilePath, string outputFilePath, string publicKeyString, bool armor = true, bool withIntegrityCheck = true)
        {
            if (string.IsNullOrEmpty(publicKeyString))
                throw new ArgumentException("publicKeyString");
            using (Stream publicKStream = publicKeyString.ToStream())
            {
                this.EncryptFileWithStreamKey(
                    inputFilePath: inputFilePath,
                    outputFilePath: outputFilePath,
                    publicKeyStream: publicKStream,
                    armor: armor,
                    withIntegrityCheck: withIntegrityCheck);
            }
        }

        public void EncryptFileWithPathKey(string inputFilePath, string outputFilePath, string publicKeyFilePath, bool armor = true, bool withIntegrityCheck = true)
        {
            if (string.IsNullOrEmpty(publicKeyFilePath))
                throw new ArgumentException("publicKeyFilePath");
            if (!File.Exists(publicKeyFilePath))
                throw new FileNotFoundException(string.Format("Public Key file [{0}] does not exist.", publicKeyFilePath));

            using (Stream pkStream = File.OpenRead(publicKeyFilePath))
            {
                this.EncryptFileWithStreamKey(inputFilePath: inputFilePath, outputFilePath: outputFilePath, publicKeyStream: pkStream, armor: armor, withIntegrityCheck: withIntegrityCheck);
            }
        }

        /// <summary>
        /// PGP Encrypt the file.
        /// </summary>
        /// <param name="inputFilePath"></param>
        /// <param name="outputFilePath"></param>
        /// <param name="publicKeyFilePath"></param>
        /// <param name="armor"></param>
        /// <param name="withIntegrityCheck"></param>
        public void EncryptFileWithStreamKey(string inputFilePath, string outputFilePath, Stream publicKeyStream, bool armor = true, bool withIntegrityCheck = true)
        {
            if (string.IsNullOrEmpty(inputFilePath))
                throw new ArgumentException("inputFilePath");
            if (string.IsNullOrEmpty(outputFilePath))
                throw new ArgumentException("inputFilePath");

            if (!File.Exists(inputFilePath))
                throw new FileNotFoundException(string.Format("Input file [{0}] does not exist.", inputFilePath));

            using (Stream pkStream = publicKeyStream)
            {
                using (MemoryStream @out = new MemoryStream())
                {
                    if (CompressionAlgorithm != CompressionAlgorithm.Uncompressed)
                    {
                        PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator((CompressionAlgorithmTag)(int)CompressionAlgorithm);
                        PgpUtilities.WriteFileToLiteralData(comData.Open(@out), FileTypeToChar(), new FileInfo(inputFilePath));
                        comData.Close();
                    }
                    else
                        PgpUtilities.WriteFileToLiteralData(@out, FileTypeToChar(), new FileInfo(inputFilePath));

                    PgpEncryptedDataGenerator pk = new PgpEncryptedDataGenerator((SymmetricKeyAlgorithmTag)(int)SymmetricKeyAlgorithm, withIntegrityCheck, new SecureRandom());
                    pk.AddMethod(PGPKeyHelper.ReadPublicKey(pkStream));

                    byte[] bytes = @out.ToArray();

                    using (Stream outStream = File.Create(outputFilePath))
                    {
                        if (armor)
                        {
                            using (ArmoredOutputStream armoredStream = new ArmoredOutputStream(outStream))
                            {
                                using (Stream armoredOutStream = pk.Open(armoredStream, bytes.Length))
                                {
                                    armoredOutStream.Write(bytes, 0, bytes.Length);
                                }
                            }
                        }
                        else
                        {
                            using (Stream plainStream = pk.Open(outStream, bytes.Length))
                            {
                                plainStream.Write(bytes, 0, bytes.Length);
                            }
                        }
                    }
                }
            }
        }

        #endregion Encrypt

        #region Encrypt and Sign

        public async Task EncryptFileAndSignAsync(string inputFilePath, string outputFilePath, string publicKeyFilePath, string privateKeyFilePath, string passPhrase, bool armor = true, bool withIntegrityCheck = true)
        {
            await Task.Run(() => EncryptFileAndSign(inputFilePath: inputFilePath, outputFilePath: outputFilePath, publicKeyFilePath: publicKeyFilePath, privateKeyFilePath: privateKeyFilePath, passPhrase: passPhrase, armor: armor, withIntegrityCheck: withIntegrityCheck));
        }

        /// <summary>
        /// Encrypt and sign the file pointed to by unencryptedFileInfo and
        /// </summary>
        /// <param name="inputFilePath"></param>
        /// <param name="outputFilePath"></param>
        /// <param name="publicKeyFilePath"></param>
        /// <param name="privateKeyFilePath"></param>
        /// <param name="passPhrase"></param>
        /// <param name="armor"></param>
        public void EncryptFileAndSign(string inputFilePath, string outputFilePath, string publicKeyFilePath, string privateKeyFilePath, string passPhrase, bool armor = true, bool withIntegrityCheck = true)
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
                throw new FileNotFoundException(string.Format("Input file [{0}] does not exist.", inputFilePath));
            if (!File.Exists(publicKeyFilePath))
                throw new FileNotFoundException(string.Format("Public Key file [{0}] does not exist.", publicKeyFilePath));
            if (!File.Exists(privateKeyFilePath))
                throw new FileNotFoundException(string.Format("Private Key file [{0}] does not exist.", privateKeyFilePath));

            PGP.EncryptionKeys encryptionKeys = new PGP.EncryptionKeys(publicKeyFilePath, privateKeyFilePath, passPhrase);

            if (encryptionKeys == null)
                throw new ArgumentNullException("Encryption Key not found.");

            using (Stream outputStream = File.Create(outputFilePath))
            {
                if (armor)
                {
                    using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream))
                    {
                        OutputEncrypted(inputFilePath, armoredOutputStream, encryptionKeys, withIntegrityCheck);
                    }
                }
                else
                    OutputEncrypted(inputFilePath, outputStream, encryptionKeys, withIntegrityCheck);
            }
        }

        private void OutputEncrypted(string inputFilePath, Stream outputStream, PGP.EncryptionKeys encryptionKeys, bool withIntegrityCheck)
        {
            using (Stream encryptedOut = ChainEncryptedOut(outputStream, encryptionKeys, withIntegrityCheck))
            {
                FileInfo unencryptedFileInfo = new FileInfo(inputFilePath);
                using (Stream compressedOut = ChainCompressedOut(encryptedOut))
                {
                    PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut, encryptionKeys);
                    using (Stream literalOut = ChainLiteralOut(compressedOut, unencryptedFileInfo))
                    {
                        using (FileStream inputFileStream = unencryptedFileInfo.OpenRead())
                        {
                            WriteOutputAndSign(compressedOut, literalOut, inputFileStream, signatureGenerator);
                            inputFileStream.Close();
                        }
                    }
                }
            }
        }

        private void WriteOutputAndSign(Stream compressedOut, Stream literalOut, FileStream inputFilePath, PgpSignatureGenerator signatureGenerator)
        {
            int length = 0;
            byte[] buf = new byte[BufferSize];
            while ((length = inputFilePath.Read(buf, 0, buf.Length)) > 0)
            {
                literalOut.Write(buf, 0, length);
                signatureGenerator.Update(buf, 0, length);
            }
            signatureGenerator.Generate().Encode(compressedOut);
        }

        private Stream ChainEncryptedOut(Stream outputStream, PGP.EncryptionKeys encryptionKeys, bool withIntegrityCheck)
        {
            PgpEncryptedDataGenerator encryptedDataGenerator;
            encryptedDataGenerator = new PgpEncryptedDataGenerator((SymmetricKeyAlgorithmTag)(int)SymmetricKeyAlgorithm, withIntegrityCheck, new SecureRandom());
            encryptedDataGenerator.AddMethod(encryptionKeys.PublicKey);
            return encryptedDataGenerator.Open(outputStream, new byte[BufferSize]);
        }

        private Stream ChainCompressedOut(Stream encryptedOut)
        {
            if (CompressionAlgorithm != CompressionAlgorithm.Uncompressed)
            {
                PgpCompressedDataGenerator compressedDataGenerator = new PgpCompressedDataGenerator((CompressionAlgorithmTag)(int)CompressionAlgorithm);
                return compressedDataGenerator.Open(encryptedOut);
            }
            else
                return encryptedOut;
        }

        private Stream ChainLiteralOut(Stream compressedOut, FileInfo file)
        {
            PgpLiteralDataGenerator pgpLiteralDataGenerator = new PgpLiteralDataGenerator();
            return pgpLiteralDataGenerator.Open(compressedOut, FileTypeToChar(), file);
        }

        private PgpSignatureGenerator InitSignatureGenerator(Stream compressedOut, PGP.EncryptionKeys encryptionKeys)
        {
            PublicKeyAlgorithmTag tag = encryptionKeys.SecretKey.PublicKey.Algorithm;
            PgpSignatureGenerator pgpSignatureGenerator = new PgpSignatureGenerator(tag, HashAlgorithmTag.Sha1);
            pgpSignatureGenerator.InitSign(PgpSignature.BinaryDocument, encryptionKeys.PrivateKey);
            foreach (string userId in encryptionKeys.SecretKey.PublicKey.GetUserIds())
            {
                PgpSignatureSubpacketGenerator subPacketGenerator = new PgpSignatureSubpacketGenerator();
                subPacketGenerator.SetSignerUserId(false, userId);
                pgpSignatureGenerator.SetHashedSubpackets(subPacketGenerator.Generate());
                // Just the first one!
                break;
            }
            pgpSignatureGenerator.GenerateOnePassVersion(false).Encode(compressedOut);
            return pgpSignatureGenerator;
        }

        #endregion Encrypt and Sign
    }
}
