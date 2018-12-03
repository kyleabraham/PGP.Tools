using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;

namespace PGP.Tools.Tasks.Tasks
{
    /// <summary>
    /// Example: 
    ///     dotnet PGP.Tools.Tasks.dll EncryptFiles --inputDirectory "C:\Temp\PGP Test\files" --outputDirectory "C:\Temp\PGP Test\files\out" --publicKey "C:\Projects\github\PGP.Tools\src\PGP.Tools.Standard.Test\Sample_public_key.asc"
    /// </summary>
    internal class EncryptFiles : AbstractTask
    {
        private readonly IConfiguration configuration;
        private readonly ILogger<EncryptFiles> logger;

        public EncryptFiles(ILogger<EncryptFiles> logger, IConfiguration configuration)
        {
            this.configuration = configuration;
            this.logger = logger;
        }

        public override bool Execute(string[] parameters)
        {
            logger.LogInformation($"Executing {nameof(EncryptFiles)} task.");

            bool result = false;

            try
            {
                SetProperties(parameters);
                logger.LogInformation($"Files from '{inputDirectory}' are being encrypted to '{outputDirectory}' with key '{publicKey}'.");

                string[] files = System.IO.Directory.GetFiles(inputDirectory);

                foreach (var file in files)
                {
                    using (Standard.PGP.Encrypt pgp = new Standard.PGP.Encrypt())
                    {
                        string outputFile = $"{outputDirectory}\\{System.IO.Path.GetFileName(file)}.pgp";
                        pgp.FileType = Standard.Enums.PGPFileType.UTF8;

                        pgp.EncryptFileWithPathKey(
                            inputFilePath: file,
                            outputFilePath: outputFile,
                            publicKeyFilePath: publicKey,
                            armor: true,
                            withIntegrityCheck: false);

                        logger.LogInformation($"Completed file encryption '{outputFile}'.");
                    }
                }

                logger.LogInformation("Completed directory encryption.");
                result = true;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Could not complete {nameof(EncryptFiles)} task.");
            }

            logger.LogInformation($"{nameof(EncryptFiles)} task complete.");

            return result;
        }

        string inputDirectory { get; set; }
        string outputDirectory { get; set; }
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
                        case nameof(inputDirectory):
                            inputDirectory = parameters[i];
                            break;
                        case nameof(outputDirectory):
                            outputDirectory = parameters[i];
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
            if (string.IsNullOrEmpty(inputDirectory))
                throw new ArgumentNullException($"No {nameof(inputDirectory)} given to encrypt.");
            if (string.IsNullOrEmpty(outputDirectory))
                outputDirectory = inputDirectory;

            logger.LogTrace($"Settings: [{nameof(publicKey)}:{publicKey}] [{nameof(inputDirectory)}:{inputDirectory}] [{nameof(outputDirectory)}:{outputDirectory}]");
        }
    }
}
