using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Threading.Tasks;

namespace PGP.Tools.Standard.PGP
{
    public class GenerateKey : BaseEncryptDecrypt
    {
        public static readonly GenerateKey Instance = new GenerateKey();

        public GenerateKey() : base() { }

        #region GenerateKey

        public async Task GenerateKeyPathAsync(string publicKeyFilePath, string privateKeyFilePath, string identity = null, string password = null, int strength = 1024, int certainty = 8)
        {
            await Task.Run(() => GenerateKeyPath(publicKeyFilePath, privateKeyFilePath, identity, password, strength, certainty));
        }

        public void GenerateKeyPath(string publicKeyFilePath, string privateKeyFilePath, string identity = null, string password = null, int strength = 1024, int certainty = 8)
        {
            if (string.IsNullOrEmpty(publicKeyFilePath))
                throw new ArgumentException("PublicKeyFilePath");
            if (string.IsNullOrEmpty(privateKeyFilePath))
                throw new ArgumentException("PrivateKeyFilePath");

            using (Stream pubs = File.Open(publicKeyFilePath, FileMode.OpenOrCreate))
            using (Stream pris = File.Open(privateKeyFilePath, FileMode.OpenOrCreate))
                GenerateKeyStream(publicKeyStream: pubs, privateKeyStream: pris, identity: identity, password: password, strength: strength, certainty: certainty);
        }

        public void GenerateKeyStream(Stream publicKeyStream, Stream privateKeyStream, string identity = null, string password = null, int strength = 1024, int certainty = 8, bool armor = true)
        {
            identity = identity == null ? string.Empty : identity;
            password = password == null ? string.Empty : password;

            IAsymmetricCipherKeyPairGenerator kpg = new RsaKeyPairGenerator();
            kpg.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(0x13), new SecureRandom(), strength, certainty));
            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();

            ExportKeyPair(privateKeyStream, publicKeyStream, kp.Public, kp.Private, identity: identity, passPhrase: password.ToCharArray(), armor: armor);
        }

        #endregion GenerateKey

        protected void ExportKeyPair(
                   Stream secretOut,
                   Stream publicOut,
                   AsymmetricKeyParameter publicKey,
                   AsymmetricKeyParameter privateKey,
                   string identity,
                   char[] passPhrase,
                   bool armor)
        {
            if (secretOut == null)
                throw new ArgumentException("secretOut");
            if (publicOut == null)
                throw new ArgumentException("publicOut");

            if (armor)
            {
                secretOut = new ArmoredOutputStream(secretOut);
            }

            PgpSecretKey secretKey = new PgpSecretKey(
                certificationLevel: PgpSignatureType,
                algorithm: (PublicKeyAlgorithmTag)(int)PublicKeyAlgorithm,
                pubKey: publicKey,
                privKey: privateKey,
                time: DateTime.Now,
                id: identity,
                encAlgorithm: (SymmetricKeyAlgorithmTag)(int)SymmetricKeyAlgorithm,
                passPhrase: passPhrase,
                hashedPackets: null,
                unhashedPackets: null,
                rand: new SecureRandom()
                //                ,"BC"
                );

            secretKey.Encode(secretOut);

            secretOut.Close();

            if (armor)
            {
                publicOut = new ArmoredOutputStream(publicOut);
            }

            PgpPublicKey key = secretKey.PublicKey;

            key.Encode(publicOut);

            publicOut.Close();
        }
    }
}
