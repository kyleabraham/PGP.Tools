//using Org.BouncyCastle.Bcpg;
//using Org.BouncyCastle.Bcpg.OpenPgp;
//using Org.BouncyCastle.Crypto;
//using Org.BouncyCastle.Crypto.Generators;
//using Org.BouncyCastle.Crypto.Parameters;
//using Org.BouncyCastle.Math;
//using Org.BouncyCastle.Security;
//using Org.BouncyCastle.Utilities.IO;
//using System;
//using System.IO;
//using System.Threading.Tasks;

//namespace PGP.Tools.Standard
//{
//    public enum PGPFileType { Binary, Text, UTF8 }
//    public enum CompressionAlgorithm
//    {
//        Uncompressed = 0,
//        Zip = 1,
//        ZLib = 2,
//        BZip2 = 3
//    }
//    public enum SymmetricKeyAlgorithm
//    {
//        Null = 0,
//        Idea = 1,
//        TripleDes = 2,
//        Cast5 = 3,
//        Blowfish = 4,
//        Safer = 5,
//        Des = 6,
//        Aes128 = 7,
//        Aes192 = 8,
//        Aes256 = 9,
//        Twofish = 10,
//        Camellia128 = 11,
//        Camellia192 = 12,
//        Camellia256 = 13
//    }
//    public enum PublicKeyAlgorithm
//    {
//        RsaGeneral = 1,
//        RsaEncrypt = 2,
//        RsaSign = 3,
//        ElGamalEncrypt = 16,
//        Dsa = 17,
//        EC = 18,
//        ECDH = 18,
//        ECDsa = 19,
//        ElGamalGeneral = 20,
//        DiffieHellman = 21,
//        Experimental_1 = 100,
//        Experimental_2 = 101,
//        Experimental_3 = 102,
//        Experimental_4 = 103,
//        Experimental_5 = 104,
//        Experimental_6 = 105,
//        Experimental_7 = 106,
//        Experimental_8 = 107,
//        Experimental_9 = 108,
//        Experimental_10 = 109,
//        Experimental_11 = 110
//    }

//    public class PGPEncryptDecrypt : IDisposable
//    {
//        public static readonly PGPEncryptDecrypt Instance = new PGPEncryptDecrypt();

//        private const int BufferSize = 0x10000;

//        public CompressionAlgorithm CompressionAlgorithm
//        {
//            get;
//            set;
//        }

//        public SymmetricKeyAlgorithm SymmetricKeyAlgorithm
//        {
//            get;
//            set;
//        }

//        public int PgpSignatureType
//        {
//            get;
//            set;
//        }

//        public PublicKeyAlgorithm PublicKeyAlgorithm
//        {
//            get;
//            set;
//        }
//        public PGPFileType FileType
//        {
//            get;
//            set;
//        }

//        #region Constructor

//        public PGPEncryptDecrypt()
//        {
//            CompressionAlgorithm = CompressionAlgorithm.Uncompressed;
//            SymmetricKeyAlgorithm = SymmetricKeyAlgorithm.TripleDes;
//            PgpSignatureType = PgpSignature.DefaultCertification;
//            PublicKeyAlgorithm = PublicKeyAlgorithm.RsaGeneral;
//            FileType = PGPFileType.Binary;
//        }

//        #endregion Constructor

//        #region Encrypt

//        public async Task EncryptFileAsync(string inputFilePath, string outputFilePath, string publicKeyFilePath,
//            bool armor = true, bool withIntegrityCheck = true)
//        {
//            await Task.Run(() => EncryptFile(inputFilePath, outputFilePath, publicKeyFilePath, armor, withIntegrityCheck));
//        }

//        public async Task EncryptFileAsync(string inputFilePath, string outputFilePath, Stream publicKeyStream,
//            bool armor = true, bool withIntegrityCheck = true)
//        {
//            await Task.Run(() => EncryptFile(inputFilePath, outputFilePath, publicKeyStream, armor, withIntegrityCheck));
//        }

//        public void EncryptFile(string inputFilePath, string outputFilePath, string publicKeyFilePath,
//            bool armor = true, bool withIntegrityCheck = true)
//        {
//            if (String.IsNullOrEmpty(publicKeyFilePath))
//                throw new ArgumentException("PublicKeyFilePath");
//            if (!File.Exists(publicKeyFilePath))
//                throw new FileNotFoundException(String.Format("Public Key file [{0}] does not exist.", publicKeyFilePath));

//            using (Stream pkStream = File.OpenRead(publicKeyFilePath))
//            {
//                this.EncryptFile(inputFilePath: inputFilePath, outputFilePath: outputFilePath, publicKeyStream: pkStream, armor: armor, withIntegrityCheck: withIntegrityCheck);
//            }
//        }
//        /// <summary>
//        /// PGP Encrypt the file.
//        /// </summary>
//        /// <param name="inputFilePath"></param>
//        /// <param name="outputFilePath"></param>
//        /// <param name="publicKeyFilePath"></param>
//        /// <param name="armor"></param>
//        /// <param name="withIntegrityCheck"></param>
//        public void EncryptFile(string inputFilePath, string outputFilePath, Stream publicKeyStream,
//        bool armor = true, bool withIntegrityCheck = true)
//        {
//            if (String.IsNullOrEmpty(inputFilePath))
//                throw new ArgumentException("InputFilePath");
//            if (String.IsNullOrEmpty(outputFilePath))
//                throw new ArgumentException("OutputFilePath");

//            if (!File.Exists(inputFilePath))
//                throw new FileNotFoundException(String.Format("Input file [{0}] does not exist.", inputFilePath));

//            using (Stream pkStream = publicKeyStream)
//            {
//                using (MemoryStream @out = new MemoryStream())
//                {
//                    if (CompressionAlgorithm != CompressionAlgorithm.Uncompressed)
//                    {
//                        PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator((CompressionAlgorithmTag)(int)CompressionAlgorithm);
//                        PgpUtilities.WriteFileToLiteralData(comData.Open(@out), FileTypeToChar(), new FileInfo(inputFilePath));
//                        comData.Close();
//                    }
//                    else
//                        PgpUtilities.WriteFileToLiteralData(@out, FileTypeToChar(), new FileInfo(inputFilePath));

//                    PgpEncryptedDataGenerator pk = new PgpEncryptedDataGenerator((SymmetricKeyAlgorithmTag)(int)SymmetricKeyAlgorithm, withIntegrityCheck, new SecureRandom());
//                    pk.AddMethod(ReadPublicKey(pkStream));

//                    byte[] bytes = @out.ToArray();

//                    using (Stream outStream = File.Create(outputFilePath))
//                    {
//                        if (armor)
//                        {
//                            using (ArmoredOutputStream armoredStream = new ArmoredOutputStream(outStream))
//                            {
//                                using (Stream armoredOutStream = pk.Open(armoredStream, bytes.Length))
//                                {
//                                    armoredOutStream.Write(bytes, 0, bytes.Length);
//                                }
//                            }
//                        }
//                        else
//                        {
//                            using (Stream plainStream = pk.Open(outStream, bytes.Length))
//                            {
//                                plainStream.Write(bytes, 0, bytes.Length);
//                            }
//                        }
//                    }
//                }
//            }
//        }

//        #endregion Encrypt

//        #region Encrypt and Sign

//        public async Task EncryptFileAndSignAsync(string inputFilePath, string outputFilePath, string publicKeyFilePath, string privateKeyFilePath,
//            string passPhrase, bool armor = true, bool withIntegrityCheck = true)
//        {
//            await Task.Run(() => EncryptFileAndSign(inputFilePath, outputFilePath, publicKeyFilePath, privateKeyFilePath, passPhrase, armor, withIntegrityCheck));
//        }

//        /// <summary>
//        /// Encrypt and sign the file pointed to by unencryptedFileInfo and
//        /// </summary>
//        /// <param name="inputFilePath"></param>
//        /// <param name="outputFilePath"></param>
//        /// <param name="publicKeyFilePath"></param>
//        /// <param name="privateKeyFilePath"></param>
//        /// <param name="passPhrase"></param>
//        /// <param name="armor"></param>
//        public void EncryptFileAndSign(string inputFilePath, string outputFilePath, string publicKeyFilePath,
//            string privateKeyFilePath, string passPhrase, bool armor = true, bool withIntegrityCheck = true)
//        {
//            if (String.IsNullOrEmpty(inputFilePath))
//                throw new ArgumentException("InputFilePath");
//            if (String.IsNullOrEmpty(outputFilePath))
//                throw new ArgumentException("OutputFilePath");
//            if (String.IsNullOrEmpty(publicKeyFilePath))
//                throw new ArgumentException("PublicKeyFilePath");
//            if (String.IsNullOrEmpty(privateKeyFilePath))
//                throw new ArgumentException("PrivateKeyFilePath");
//            if (passPhrase == null)
//                passPhrase = String.Empty;

//            if (!File.Exists(inputFilePath))
//                throw new FileNotFoundException(String.Format("Input file [{0}] does not exist.", inputFilePath));
//            if (!File.Exists(publicKeyFilePath))
//                throw new FileNotFoundException(String.Format("Public Key file [{0}] does not exist.", publicKeyFilePath));
//            if (!File.Exists(privateKeyFilePath))
//                throw new FileNotFoundException(String.Format("Private Key file [{0}] does not exist.", privateKeyFilePath));

//            PGPEncryptionKeys encryptionKeys = new PGPEncryptionKeys(publicKeyFilePath, privateKeyFilePath, passPhrase);

//            if (encryptionKeys == null)
//                throw new ArgumentNullException("Encryption Key not found.");

//            using (Stream outputStream = File.Create(outputFilePath))
//            {
//                if (armor)
//                {
//                    using (ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(outputStream))
//                    {
//                        OutputEncrypted(inputFilePath, armoredOutputStream, encryptionKeys, withIntegrityCheck);
//                    }
//                }
//                else
//                    OutputEncrypted(inputFilePath, outputStream, encryptionKeys, withIntegrityCheck);
//            }
//        }

//        private void OutputEncrypted(string inputFilePath, Stream outputStream, PGPEncryptionKeys encryptionKeys, bool withIntegrityCheck)
//        {
//            using (Stream encryptedOut = ChainEncryptedOut(outputStream, encryptionKeys, withIntegrityCheck))
//            {
//                FileInfo unencryptedFileInfo = new FileInfo(inputFilePath);
//                using (Stream compressedOut = ChainCompressedOut(encryptedOut))
//                {
//                    PgpSignatureGenerator signatureGenerator = InitSignatureGenerator(compressedOut, encryptionKeys);
//                    using (Stream literalOut = ChainLiteralOut(compressedOut, unencryptedFileInfo))
//                    {
//                        using (FileStream inputFileStream = unencryptedFileInfo.OpenRead())
//                        {
//                            WriteOutputAndSign(compressedOut, literalOut, inputFileStream, signatureGenerator);
//                            inputFileStream.Close();
//                        }
//                    }
//                }
//            }
//        }

//        private void WriteOutputAndSign(Stream compressedOut, Stream literalOut, FileStream inputFilePath, PgpSignatureGenerator signatureGenerator)
//        {
//            int length = 0;
//            byte[] buf = new byte[BufferSize];
//            while ((length = inputFilePath.Read(buf, 0, buf.Length)) > 0)
//            {
//                literalOut.Write(buf, 0, length);
//                signatureGenerator.Update(buf, 0, length);
//            }
//            signatureGenerator.Generate().Encode(compressedOut);
//        }

//        private Stream ChainEncryptedOut(Stream outputStream, PGPEncryptionKeys encryptionKeys, bool withIntegrityCheck)
//        {
//            PgpEncryptedDataGenerator encryptedDataGenerator;
//            encryptedDataGenerator = new PgpEncryptedDataGenerator((SymmetricKeyAlgorithmTag)(int)SymmetricKeyAlgorithm, withIntegrityCheck, new SecureRandom());
//            encryptedDataGenerator.AddMethod(encryptionKeys.PublicKey);
//            return encryptedDataGenerator.Open(outputStream, new byte[BufferSize]);
//        }

//        private Stream ChainCompressedOut(Stream encryptedOut)
//        {
//            if (CompressionAlgorithm != CompressionAlgorithm.Uncompressed)
//            {
//                PgpCompressedDataGenerator compressedDataGenerator = new PgpCompressedDataGenerator((CompressionAlgorithmTag)(int)CompressionAlgorithm);
//                return compressedDataGenerator.Open(encryptedOut);
//            }
//            else
//                return encryptedOut;
//        }

//        private Stream ChainLiteralOut(Stream compressedOut, FileInfo file)
//        {
//            PgpLiteralDataGenerator pgpLiteralDataGenerator = new PgpLiteralDataGenerator();
//            return pgpLiteralDataGenerator.Open(compressedOut, FileTypeToChar(), file);
//        }

//        private PgpSignatureGenerator InitSignatureGenerator(Stream compressedOut, PGPEncryptionKeys encryptionKeys)
//        {
//            PublicKeyAlgorithmTag tag = encryptionKeys.SecretKey.PublicKey.Algorithm;
//            PgpSignatureGenerator pgpSignatureGenerator = new PgpSignatureGenerator(tag, HashAlgorithmTag.Sha1);
//            pgpSignatureGenerator.InitSign(PgpSignature.BinaryDocument, encryptionKeys.PrivateKey);
//            foreach (string userId in encryptionKeys.SecretKey.PublicKey.GetUserIds())
//            {
//                PgpSignatureSubpacketGenerator subPacketGenerator = new PgpSignatureSubpacketGenerator();
//                subPacketGenerator.SetSignerUserId(false, userId);
//                pgpSignatureGenerator.SetHashedSubpackets(subPacketGenerator.Generate());
//                // Just the first one!
//                break;
//            }
//            pgpSignatureGenerator.GenerateOnePassVersion(false).Encode(compressedOut);
//            return pgpSignatureGenerator;
//        }

//        #endregion Encrypt and Sign

//        #region Decrypt

//        public async Task DecryptFileAsync(string inputFilePath, string outputFilePath, string privateKeyFilePath, string passPhrase)
//        {
//            await Task.Run(() => DecryptFile(inputFilePath, outputFilePath, privateKeyFilePath, passPhrase));
//        }
//        public async Task DecryptFileAsync(string inputFilePath, string outputFilePath, Stream privateKeyStream, string passPhrase)
//        {
//            await Task.Run(() => DecryptFile(inputFilePath, outputFilePath, privateKeyStream, passPhrase));
//        }

//        /// <summary>
//        /// PGP decrypt a given file.
//        /// </summary>
//        /// <param name="inputFilePath"></param>
//        /// <param name="outputFilePath"></param>
//        /// <param name="privateKeyFilePath"></param>
//        /// <param name="passPhrase"></param>
//        public void DecryptFile(string inputFilePath, string outputFilePath, string privateKeyFilePath, string passPhrase)
//        {
//            if (String.IsNullOrEmpty(privateKeyFilePath))
//                throw new ArgumentException("PrivateKeyFilePath");
//            if (!File.Exists(privateKeyFilePath))
//                throw new FileNotFoundException(String.Format("Private Key File [{0}] not found.", privateKeyFilePath));

//            using (Stream keyStream = File.OpenRead(privateKeyFilePath))
//            {
//                DecryptFile(inputFilePath: inputFilePath, outputFilePath: outputFilePath, privateKeyStream: keyStream, passPhrase: passPhrase);
//            }
//        }
//        public void DecryptFile(string inputFilePath, string outputFilePath, Stream privateKeyStream, string passPhrase)
//        {
//            if (String.IsNullOrEmpty(inputFilePath))
//                throw new ArgumentException("InputFilePath");
//            if (String.IsNullOrEmpty(outputFilePath))
//                throw new ArgumentException("OutputFilePath");
//            if (passPhrase == null)
//                passPhrase = String.Empty;

//            if (!File.Exists(inputFilePath))
//                throw new FileNotFoundException(String.Format("Encrypted File [{0}] not found.", inputFilePath));

//            using (Stream inputStream = File.OpenRead(inputFilePath))
//            {
//                using (Stream outStream = File.Create(outputFilePath))
//                    Decrypt(inputStream, outStream, privateKeyStream, passPhrase);
//            }
//        }

//        /*
//        * PGP decrypt a given stream.
//        */
//        private void Decrypt(Stream inputStream, Stream outputStream, Stream privateKeyStream, string passPhrase)
//        {
//            if (inputStream == null)
//                throw new ArgumentException("InputStream");
//            if (outputStream == null)
//                throw new ArgumentException("outputStream");
//            if (privateKeyStream == null)
//                throw new ArgumentException("privateKeyStream");
//            if (passPhrase == null)
//                passPhrase = String.Empty;

//            PgpObjectFactory objFactory = new PgpObjectFactory(PgpUtilities.GetDecoderStream(inputStream));
//            // find secret key
//            PgpSecretKeyRingBundle pgpSec = new PgpSecretKeyRingBundle(PgpUtilities.GetDecoderStream(privateKeyStream));

//            PgpObject obj = null;
//            if (objFactory != null)
//                obj = objFactory.NextPgpObject();

//            // the first object might be a PGP marker packet.
//            PgpEncryptedDataList enc = null;
//            if (obj is PgpEncryptedDataList)
//                enc = (PgpEncryptedDataList)obj;
//            else
//                enc = (PgpEncryptedDataList)objFactory.NextPgpObject();

//            // decrypt
//            PgpPrivateKey privateKey = null;
//            PgpPublicKeyEncryptedData pbe = null;
//            foreach (PgpPublicKeyEncryptedData pked in enc.GetEncryptedDataObjects())
//            {
//                privateKey = FindSecretKey(pgpSec, pked.KeyId, passPhrase.ToCharArray());

//                if (privateKey != null)
//                {
//                    pbe = pked;
//                    break;
//                }
//            }

//            if (privateKey == null)
//                throw new ArgumentException("Secret key for message not found.");

//            PgpObjectFactory plainFact = null;

//            using (Stream clear = pbe.GetDataStream(privateKey))
//            {
//                plainFact = new PgpObjectFactory(clear);
//            }

//            PgpObject message = plainFact.NextPgpObject();
//            if (message is PgpOnePassSignatureList)
//                message = plainFact.NextPgpObject();

//            if (message is PgpCompressedData)
//            {
//                PgpCompressedData cData = (PgpCompressedData)message;
//                PgpObjectFactory of = null;

//                using (Stream compDataIn = cData.GetDataStream())
//                {
//                    of = new PgpObjectFactory(compDataIn);
//                }

//                message = of.NextPgpObject();
//                if (message is PgpOnePassSignatureList)
//                {
//                    message = of.NextPgpObject();
//                    PgpLiteralData Ld = null;
//                    Ld = (PgpLiteralData)message;
//                    Stream unc = Ld.GetInputStream();
//                    Streams.PipeAll(unc, outputStream);
//                }
//                else
//                {
//                    PgpLiteralData Ld = null;
//                    Ld = (PgpLiteralData)message;
//                    Stream unc = Ld.GetInputStream();
//                    Streams.PipeAll(unc, outputStream);
//                }
//            }
//            else if (message is PgpLiteralData)
//            {
//                PgpLiteralData ld = (PgpLiteralData)message;
//                string outFileName = ld.FileName;

//                Stream unc = ld.GetInputStream();
//                Streams.PipeAll(unc, outputStream);
//            }
//            else if (message is PgpOnePassSignatureList)
//                throw new PgpException("Encrypted message contains a signed message - not literal data.");
//            else
//                throw new PgpException("Message is not a simple encrypted file.");
//        }

//        public async Task DecryptFileAndVerifyAsync(string inputFilePath, string outputFilePath, string publicKeyFilePath, string privateKeyFilePath, string passPhrase)
//        {
//            await Task.Run(() => DecryptFileAndVerify(inputFilePath, outputFilePath, publicKeyFilePath, privateKeyFilePath, passPhrase));
//        }

//        public void DecryptFileAndVerify(string inputFilePath, string outputFilePath, string publicKeyFilePath, string privateKeyFilePath, string passPhrase)
//        {
//            if (String.IsNullOrEmpty(inputFilePath))
//                throw new ArgumentException("InputFilePath");
//            if (String.IsNullOrEmpty(outputFilePath))
//                throw new ArgumentException("OutputFilePath");
//            if (String.IsNullOrEmpty(publicKeyFilePath))
//                throw new ArgumentException("PublicKeyFilePath");
//            if (String.IsNullOrEmpty(privateKeyFilePath))
//                throw new ArgumentException("PrivateKeyFilePath");
//            if (passPhrase == null)
//                passPhrase = String.Empty;

//            if (!File.Exists(inputFilePath))
//                throw new FileNotFoundException(String.Format("Encrypted File [{0}] not found.", inputFilePath));
//            if (!File.Exists(publicKeyFilePath))
//                throw new FileNotFoundException(String.Format("Public Key File [{0}] not found.", publicKeyFilePath));
//            if (!File.Exists(privateKeyFilePath))
//                throw new FileNotFoundException(String.Format("Private Key File [{0}] not found.", privateKeyFilePath));

//            PGPEncryptionKeys encryptionKeys = new PGPEncryptionKeys(publicKeyFilePath, privateKeyFilePath, passPhrase);

//            if (encryptionKeys == null)
//                throw new ArgumentNullException("Encryption Key not found.");

//            using (Stream inputStream = File.OpenRead(inputFilePath))
//            {
//                PgpPublicKeyEncryptedData publicKeyED = ExtractPublicKeyEncryptedData(inputStream);
//                if (publicKeyED.KeyId != encryptionKeys.PublicKey.KeyId)
//                    throw new PgpException(String.Format("Failed to verify file."));

//                PgpObject message = GetClearCompressedMessage(publicKeyED, encryptionKeys);

//                if (message is PgpCompressedData)
//                {
//                    message = ProcessCompressedMessage(message);
//                    PgpLiteralData literalData = (PgpLiteralData)message;
//                    using (Stream outputFile = File.Create(outputFilePath))
//                    {
//                        using (Stream literalDataStream = literalData.GetInputStream())
//                        {
//                            Streams.PipeAll(literalDataStream, outputFile);
//                        }
//                    }
//                }
//                else if (message is PgpLiteralData)
//                {
//                    PgpLiteralData literalData = (PgpLiteralData)message;
//                    using (Stream outputFile = File.Create(outputFilePath))
//                    {
//                        using (Stream literalDataStream = literalData.GetInputStream())
//                        {
//                            Streams.PipeAll(literalDataStream, outputFile);
//                        }
//                    }
//                }
//                else
//                    throw new PgpException("Message is not a simple encrypted file.");
//            }

//            return;
//        }

//        #endregion Decrypt

//        #region GenerateKey

//        public async Task GenerateKeyAsync(string publicKeyFilePath, string privateKeyFilePath, string identity = null, string password = null, int strength = 1024, int certainty = 8)
//        {
//            await Task.Run(() => GenerateKey(publicKeyFilePath, privateKeyFilePath, identity, password, strength, certainty));
//        }

//        public void GenerateKey(string publicKeyFilePath, string privateKeyFilePath, string identity = null, string password = null, int strength = 1024, int certainty = 8)
//        {
//            if (String.IsNullOrEmpty(publicKeyFilePath))
//                throw new ArgumentException("PublicKeyFilePath");
//            if (String.IsNullOrEmpty(privateKeyFilePath))
//                throw new ArgumentException("PrivateKeyFilePath");

//            using (Stream pubs = File.Open(publicKeyFilePath, FileMode.OpenOrCreate))
//            using (Stream pris = File.Open(privateKeyFilePath, FileMode.OpenOrCreate))
//                GenerateKey(publicKeyStream: pubs, privateKeyStream: pris, identity: identity, password: password, strength: strength, certainty: certainty);
//        }

//        public void GenerateKey(Stream publicKeyStream, Stream privateKeyStream, string identity = null, string password = null, int strength = 1024, int certainty = 8, bool armor = true)
//        {
//            identity = identity == null ? string.Empty : identity;
//            password = password == null ? string.Empty : password;

//            IAsymmetricCipherKeyPairGenerator kpg = new RsaKeyPairGenerator();
//            kpg.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x13), new SecureRandom(), strength, certainty));
//            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();

//            ExportKeyPair(privateKeyStream, publicKeyStream, kp.Public, kp.Private, identity: identity, passPhrase: password.ToCharArray(), armor: armor);
//        }

//        #endregion GenerateKey

//        #region Private helpers

//        private char FileTypeToChar()
//        {
//            if (FileType == PGPFileType.UTF8)
//                return PgpLiteralData.Utf8;
//            else if (FileType == PGPFileType.Text)
//                return PgpLiteralData.Text;
//            else
//                return PgpLiteralData.Binary;

//        }

//        private void ExportKeyPair(
//                    Stream secretOut,
//                    Stream publicOut,
//                    AsymmetricKeyParameter publicKey,
//                    AsymmetricKeyParameter privateKey,
//                    string identity,
//                    char[] passPhrase,
//                    bool armor)
//        {
//            if (secretOut == null)
//                throw new ArgumentException("secretOut");
//            if (publicOut == null)
//                throw new ArgumentException("publicOut");

//            if (armor)
//            {
//                secretOut = new ArmoredOutputStream(secretOut);
//            }

//            PgpSecretKey secretKey = new PgpSecretKey(
//                certificationLevel: PgpSignatureType,
//                algorithm: (PublicKeyAlgorithmTag)(int)PublicKeyAlgorithm,
//                pubKey: publicKey,
//                privKey: privateKey,
//                time: DateTime.Now,
//                id: identity,
//                encAlgorithm: (SymmetricKeyAlgorithmTag)(int)SymmetricKeyAlgorithm,
//                passPhrase: passPhrase,
//                hashedPackets: null,
//                unhashedPackets: null,
//                rand: new SecureRandom()
//                //                ,"BC"
//                );

//            secretKey.Encode(secretOut);

//            secretOut.Close();

//            if (armor)
//            {
//                publicOut = new ArmoredOutputStream(publicOut);
//            }

//            PgpPublicKey key = secretKey.PublicKey;

//            key.Encode(publicOut);

//            publicOut.Close();
//        }

//        /*
//        * A simple routine that opens a key ring file and loads the first available key suitable for encryption.
//        */
//        private PgpPublicKey ReadPublicKey(Stream inputStream)
//        {
//            inputStream = PgpUtilities.GetDecoderStream(inputStream);

//            PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(inputStream);

//            // we just loop through the collection till we find a key suitable for encryption, in the real
//            // world you would probably want to be a bit smarter about this.
//            // iterate through the key rings.
//            foreach (PgpPublicKeyRing kRing in pgpPub.GetKeyRings())
//            {
//                foreach (PgpPublicKey k in kRing.GetPublicKeys())
//                {
//                    if (k.IsEncryptionKey)
//                        return k;
//                }
//            }

//            throw new ArgumentException("Can't find encryption key in key ring.");
//        }

//        /*
//        * Search a secret key ring collection for a secret key corresponding to keyId if it exists.
//        */
//        private PgpPrivateKey FindSecretKey(PgpSecretKeyRingBundle pgpSec, long keyId, char[] pass)
//        {
//            PgpSecretKey pgpSecKey = pgpSec.GetSecretKey(keyId);

//            if (pgpSecKey == null)
//                return null;

//            return pgpSecKey.ExtractPrivateKey(pass);
//        }

//        private static PgpPublicKeyEncryptedData ExtractPublicKeyEncryptedData(Stream inputStream)
//        {
//            Stream encodedFile = PgpUtilities.GetDecoderStream(inputStream);
//            PgpEncryptedDataList encryptedDataList = GetEncryptedDataList(encodedFile);
//            PgpPublicKeyEncryptedData publicKeyED = ExtractPublicKey(encryptedDataList);
//            return publicKeyED;
//        }
//        private static PgpObject ProcessCompressedMessage(PgpObject message)
//        {
//            PgpCompressedData compressedData = (PgpCompressedData)message;
//            Stream compressedDataStream = compressedData.GetDataStream();
//            PgpObjectFactory compressedFactory = new PgpObjectFactory(compressedDataStream);
//            message = CheckforOnePassSignatureList(message, compressedFactory);
//            return message;
//        }
//        private static PgpObject CheckforOnePassSignatureList(PgpObject message, PgpObjectFactory compressedFactory)
//        {
//            message = compressedFactory.NextPgpObject();
//            if (message is PgpOnePassSignatureList)
//            {
//                message = compressedFactory.NextPgpObject();
//            }
//            return message;
//        }
//        private PgpObject GetClearCompressedMessage(PgpPublicKeyEncryptedData publicKeyED, PGPEncryptionKeys encryptionKeys)
//        {
//            PgpObjectFactory clearFactory = GetClearDataStream(encryptionKeys.PrivateKey, publicKeyED);
//            PgpObject message = clearFactory.NextPgpObject();
//            if (message is PgpOnePassSignatureList)
//                message = clearFactory.NextPgpObject();
//            return message;
//        }
//        private static PgpObjectFactory GetClearDataStream(PgpPrivateKey privateKey, PgpPublicKeyEncryptedData publicKeyED)
//        {
//            Stream clearStream = publicKeyED.GetDataStream(privateKey);
//            PgpObjectFactory clearFactory = new PgpObjectFactory(clearStream);
//            return clearFactory;
//        }
//        private static PgpPublicKeyEncryptedData ExtractPublicKey(PgpEncryptedDataList encryptedDataList)
//        {
//            PgpPublicKeyEncryptedData publicKeyED = null;
//            foreach (PgpPublicKeyEncryptedData privateKeyED in encryptedDataList.GetEncryptedDataObjects())
//            {
//                if (privateKeyED != null)
//                {
//                    publicKeyED = privateKeyED;
//                    break;
//                }
//            }
//            return publicKeyED;
//        }
//        private static PgpEncryptedDataList GetEncryptedDataList(Stream encodedFile)
//        {
//            PgpObjectFactory factory = new PgpObjectFactory(encodedFile);
//            PgpObject pgpObject = factory.NextPgpObject();

//            PgpEncryptedDataList encryptedDataList;

//            if (pgpObject is PgpEncryptedDataList)
//            {
//                encryptedDataList = (PgpEncryptedDataList)pgpObject;
//            }
//            else
//            {
//                encryptedDataList = (PgpEncryptedDataList)factory.NextPgpObject();
//            }
//            return encryptedDataList;
//        }
//        public void Dispose()
//        {
//        }

//        #endregion Private helpers
//    }

//}