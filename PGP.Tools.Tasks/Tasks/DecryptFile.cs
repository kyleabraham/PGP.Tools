using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;

namespace PGP.Tools.Tasks.Tasks
{
    /// <summary>
    /// Example: 
    ///     dotnet PGP.Tools.Tasks.dll DecryptFile --inputFile "C:\Temp\PGP Test\files\Sample_file_2.txt.pgp" --outputFile "C:\Temp\PGP Test\files\Sample_file_2.txt" --privateKey "C:\Projects\github\PGP.Tools\src\PGP.Tools.Standard.Test\Sample_private_key.asc" --passPhrase "password123"
    /// </summary>
    internal class DecryptFile : AbstractTask
    {
        private readonly IConfiguration configuration;
        private readonly ILogger<DecryptFile> logger;

        public DecryptFile(ILogger<DecryptFile> logger, IConfiguration configuration)
        {
            this.configuration = configuration;
            this.logger = logger;
        }

        public override bool Execute(string[] parameters)
        {
            logger.LogInformation($"Executing {nameof(DecryptFile)} task.");

            bool result = false;

            try
            {
                SetProperties(parameters);

                using (Standard.PGP.Decrypt pgp = new Standard.PGP.Decrypt())
                {
                    logger.LogInformation($"'{inputFile}' is being decrypted to '{outputFile}' with key '{privateKey}'.");

                    pgp.FileType = Standard.Enums.PGPFileType.UTF8;

                    pgp.DecryptFileWithPath(
                        inputFilePath: inputFile,
                        outputFilePath: outputFile,
                        privateKeyFilePath: privateKey,
                        passPhrase: passPhrase);

                    logger.LogInformation($"Completed file decryption '{outputFile}'.");
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Could not complete {nameof(DecryptFile)} task.");
            }

            logger.LogInformation($"{nameof(DecryptFile)} task complete.");

            return result;
        }

        string inputFile { get; set; }
        string outputFile { get; set; }
        string privateKey { get; set; }
        string passPhrase { get; set; }
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
                        case nameof(privateKey):
                            privateKey = parameters[i];
                            break;
                        case nameof(passPhrase):
                            passPhrase = parameters[i];
                            break;
                        default:
                            logger.LogError($"Setting '{param}' is unknown.");
                            break;
                    }
                }
            }

            //default settings if not provided
            if (string.IsNullOrEmpty(privateKey))
                privateKey = configuration["PGP:privateKey"];
            if (string.IsNullOrEmpty(passPhrase))
                passPhrase = configuration["PGP:passPhrase"];
            if (string.IsNullOrEmpty(inputFile))
                throw new ArgumentNullException($"No {nameof(inputFile)} given to decrypt.");
            if (string.IsNullOrEmpty(outputFile))
                outputFile = $"{System.IO.Path.GetDirectoryName(inputFile)}\\{System.IO.Path.GetFileNameWithoutExtension(inputFile)}";

            logger.LogTrace($"Settings: [{nameof(privateKey)}:{privateKey}] [{nameof(inputFile)}:{inputFile}] [{nameof(outputFile)}:{outputFile}] [{nameof(passPhrase)}:{passPhrase}]");
        }
    }
}
