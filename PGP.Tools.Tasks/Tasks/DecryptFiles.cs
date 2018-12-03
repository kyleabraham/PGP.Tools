using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;

namespace PGP.Tools.Tasks.Tasks
{
    /// <summary>
    /// Example: 
    ///     dotnet PGP.Tools.Tasks.dll DecryptFiles --inputDirectory "C:\Temp\PGP Test\files\out" --outputDirectory "C:\Temp\PGP Test\files\out" --privateKey "C:\Projects\github\PGP.Tools\src\PGP.Tools.Standard.Test\Sample_private_key.asc" --passPhrase "password123"
    /// </summary>
    internal class DecryptFiles : AbstractTask
    {
        private readonly IConfiguration configuration;
        private readonly ILogger<DecryptFiles> logger;

        public DecryptFiles(ILogger<DecryptFiles> logger, IConfiguration configuration)
        {
            this.configuration = configuration;
            this.logger = logger;
        }

        public override bool Execute(string[] parameters)
        {
            logger.LogInformation($"Executing {nameof(DecryptFiles)} task.");

            bool result = false;

            try
            {
                SetProperties(parameters);
                logger.LogInformation($"Files from '{inputDirectory}' are being decrypted to '{outputDirectory}' with key '{privateKey}'.");

                string[] files = System.IO.Directory.GetFiles(inputDirectory);

                foreach (var file in files)
                {
                    using (Standard.PGP.Decrypt pgp = new Standard.PGP.Decrypt())
                    {
                        string outputFile = $"{outputDirectory}\\{System.IO.Path.GetFileNameWithoutExtension(file)}";
                        pgp.FileType = Standard.Enums.PGPFileType.UTF8;

                        pgp.DecryptFileWithPath(
                           inputFilePath: file,
                           outputFilePath: outputFile,
                           privateKeyFilePath: privateKey,
                           passPhrase: passPhrase);

                        logger.LogInformation($"Completed file decryption '{outputFile}'.");
                    }
                }

                logger.LogInformation("Completed directory decryption.");
                result = true;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Could not complete {nameof(DecryptFiles)} task.");
            }

            logger.LogInformation($"{nameof(DecryptFiles)} task complete.");

            return result;
        }

        string inputDirectory { get; set; }
        string outputDirectory { get; set; }
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
                        case nameof(inputDirectory):
                            inputDirectory = parameters[i];
                            break;
                        case nameof(outputDirectory):
                            outputDirectory = parameters[i];
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
            if (string.IsNullOrEmpty(inputDirectory))
                throw new ArgumentNullException($"No {nameof(inputDirectory)} given to decrypt.");
            if (string.IsNullOrEmpty(outputDirectory))
                outputDirectory = inputDirectory;

            logger.LogTrace($"Settings: [{nameof(privateKey)}:{privateKey}] [{nameof(inputDirectory)}:{inputDirectory}] [{nameof(outputDirectory)}:{outputDirectory}] [{nameof(passPhrase)}:{passPhrase}]");
        }
    }
}
