using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;

namespace PGP.Tools.Tasks.Tasks
{
    /// <summary>
    /// Example: 
    ///     dotnet PGP.Tools.Tasks.dll EncryptFile --inputFile "C:\Temp\PGP Test\Sample_file.txt" --outputFile "C:\Temp\PGP Test\Sample_file1.txt.pgp" --publicKey "C:\Projects\github\PGP.Tools\src\PGP.Tools.Standard.Test\Sample_public_key.asc"
    /// </summary>
    internal class EncryptFile : AbstractTask
    {
        private readonly IConfiguration configuration;
        private readonly ILogger<EncryptFile> logger;

        public EncryptFile(ILogger<EncryptFile> logger, IConfiguration configuration)
        {
            this.configuration = configuration;
            this.logger = logger;
        }

        public override bool Execute(string[] parameters)
        {
            logger.LogInformation($"Executing {nameof(EncryptFile)} task.");

            bool result = false;

            try
            {
                SetProperties(parameters);

                using (Standard.PGP.Encrypt pgp = new Standard.PGP.Encrypt())
                {
                    logger.LogInformation($"'{inputFile}' is being encrypted to '{outputFile}' with key '{publicKey}'.");

                    pgp.FileType = Standard.Enums.PGPFileType.UTF8;

                    pgp.EncryptFileWithPathKey(
                        inputFilePath: inputFile,
                        outputFilePath: outputFile,
                        publicKeyFilePath: publicKey,
                        armor: true,
                        withIntegrityCheck: false);

                    logger.LogInformation($"Completed file encryption '{outputFile}'.");
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Could not complete {nameof(EncryptFile)} task.");
            }

            logger.LogInformation($"{nameof(EncryptFile)} task complete.");

            return result;
        }

        string inputFile { get; set; }
        string outputFile { get; set; }
        string publicKey { get; set; }
        private void SetProperties(string[] parameters)
        {
            //set provided settings
            for (int i = 0; i < parameters.Length; i++)
            {
                string param = parameters[i].Trim();
                if (param.StartsWith("--"))
                {
                    //change i to value of setting
                    ++i;
                    switch (param.Substring(2))
                    {
                        case nameof(inputFile):
                            inputFile = parameters[i];
                            break;
                        case nameof(outputFile):
                            outputFile = parameters[i];
                            break;
                        case nameof(publicKey):
                            publicKey = parameters[i];
                            break;
                        default:
                            logger.LogError($"Setting '{param}' is unknown.");
                            break;
                    }
                }
            }

            //default settings if not provided
            if (string.IsNullOrEmpty(publicKey))
                publicKey = configuration["PGP:publicKey"];
            if (string.IsNullOrEmpty(inputFile))
                throw new ArgumentNullException($"No {nameof(inputFile)} given to encrypt.");
            if (string.IsNullOrEmpty(outputFile))
                outputFile = $"{inputFile}.pgp";

            logger.LogTrace($"Settings: [{nameof(publicKey)}:{publicKey}] [{nameof(inputFile)}:{inputFile}] [{nameof(outputFile)}:{outputFile}]");
        }
    }
}
