using System;
using System.IO;

namespace PGP.Tools.Standard.Test
{
    class Program
    {
        const string identityString = "test@email.com";
        const string passwordString = "password123";
        static void Main(string[] args)
        {
            Console.WriteLine(Directory.GetCurrentDirectory());
            //GenerateKeyPair("test");
            //EncryptFile();
            //DecryptFile();
            EncryptFileWithStream();
            DecryptFileWithStream();
            //EncryptFileNSign();
            //DecryptFileNVerify();
            Console.ReadLine();
        }

        private static void GenerateKeyPair(string keyName = null)
        {
            keyName = keyName ?? "Sample";
            using (PGPEncryptDecrypt pgp = new PGPEncryptDecrypt())
                pgp.GenerateKey(
                    publicKeyFilePath: $"{keyName}_public_key.asc",
                    privateKeyFilePath: $"{keyName}_private_key.asc",
                    identity: $"{identityString} <{keyName}>",
                    password: passwordString);

            Console.WriteLine("PGP KeyPair generated.");
        }
        private static void EncryptFile()
        {
            using (PGPEncryptDecrypt pgp = new PGPEncryptDecrypt())
            {
                //pgp.CompressionAlgorithm = CompressionAlgorithm.Zip;
                pgp.FileType = PGPFileType.UTF8;


                pgp.EncryptFile(
                    inputFilePath: "Sample_file.txt",
                    outputFilePath: "Sample_file.txt.pgp",
                    publicKeyFilePath: "Sample_public_key.asc",
                    armor: true,
                    withIntegrityCheck: false);
                Console.WriteLine("PGP Encryption done.");
            }
        }
        private static void DecryptFile()
        {
            using (PGPEncryptDecrypt pgp = new PGPEncryptDecrypt())
            {
                pgp.DecryptFile(
                    inputFilePath: "Sample_file.txt.pgp",
                    outputFilePath: "Sample_file.out.txt",
                    privateKeyFilePath: "Sample_private_key.asc",
                    passPhrase: "password123");
                Console.WriteLine("PGP Decryption done.");
            }
        }
        private static void EncryptFileWithStream()
        {
            using (PGPEncryptDecrypt pgp = new PGPEncryptDecrypt())
            {
                using (Stream publicKStream = ToStream(Constants.publicKey))
                {
                    pgp.EncryptFile(
                        inputFilePath: "Sample_file.txt",
                        outputFilePath: "Sample_file_stream.txt.pgp",
                        publicKeyStream: publicKStream,
                        armor: true,
                        withIntegrityCheck: false);
                    Console.WriteLine("PGP Steam public key Encryption done.");
                }
            }
        }
        private static void DecryptFileWithStream()
        {
            using (PGPEncryptDecrypt pgp = new PGPEncryptDecrypt())
            {
                using (Stream privateKStream = ToStream(Constants.privateKey))
                {
                    pgp.DecryptFile(
                    inputFilePath: "Sample_file_stream.txt.pgp",
                    outputFilePath: "Sample_file_stream.out.txt",
                    privateKeyStream: privateKStream,
                    passPhrase: "password123");
                    Console.WriteLine("PGP Stream private key Decryption done.");
                }
            }
        }
        private static void EncryptFileNSign()
        {
            using (PGPEncryptDecrypt pgp = new PGPEncryptDecrypt())
            {
                pgp.EncryptFileAndSign(
                    inputFilePath: "Sample_file.txt",
                    outputFilePath: "Sample_file.nisgn.txt.pgp",
                    publicKeyFilePath: "Sample_public_key.asc",
                    privateKeyFilePath: "Sample_private_key.asc",
                    passPhrase: "password123",
                    armor: true,
                    withIntegrityCheck: false);
                Console.WriteLine("PGP Encryption done.");
            }
        }
        private static void DecryptFileNVerify()
        {
            using (PGPEncryptDecrypt pgp = new PGPEncryptDecrypt())
            {
                pgp.DecryptFileAndVerify(
                   inputFilePath: "Sample_file.nisgn.txt.pgp",
                   outputFilePath: "Sample_file.nisgn.out.txt",
                   publicKeyFilePath: "Sample_public_key.asc",
                   privateKeyFilePath: "Sample_private_key.asc",
                   passPhrase: "password123");
                Console.WriteLine("PGP Decryption done.");
            }
        }

        public static Stream ToStream(string str, System.Text.Encoding enc = null)
        {
            enc = enc ?? System.Text.Encoding.UTF8;
            return new MemoryStream(enc.GetBytes(str ?? ""));
        }
    }
}
