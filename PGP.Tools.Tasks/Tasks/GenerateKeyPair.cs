using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;

namespace PGP.Tools.Tasks.Tasks
{
    /// <summary>
    /// Example: 
    ///     dotnet PGP.Tools.Tasks.dll GenerateKeyPair --publicKey "C:\Temp\PGP Test\keys\public.asc" --privateKey "C:\Temp\PGP Test\keys\private.asc" --identity "john.doe@email.com <John Doe>" --passPhrase "password123"
    /// </summary>
    internal class GenerateKeyPair : AbstractTask
    {
        private readonly IConfiguration configuration;
        private readonly ILogger<GenerateKeyPair> logger;

        public GenerateKeyPair(ILogger<GenerateKeyPair> logger, IConfiguration configuration)
        {
            this.configuration = configuration;
            this.logger = logger;
        }

        public override bool Execute(string[] parameters)
        {
            logger.LogInformation($"Executing {nameof(GenerateKeyPair)} task.");

            bool result = false;

            try
            {
                SetProperties(parameters);

                using (Standard.PGP.KeyGenerator pgp = new Standard.PGP.KeyGenerator())
                {
                    logger.LogInformation($"'{publicKey}' and '{privateKey}' is being generated for identity '{identity}' with passPhrase '{passPhrase}'.");

                    pgp.FileType = Standard.Enums.PGPFileType.UTF8;

                    pgp.GenerateKeyPath(
                        publicKeyFilePath: publicKey,
                        privateKeyFilePath: privateKey,
                        identity: identity,
                        password: passPhrase);

                    logger.LogInformation($"Completed key pair generation.");
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Could not complete {nameof(GenerateKeyPair)} task.");
            }

            logger.LogInformation($"{nameof(GenerateKeyPair)} task complete.");

            return result;
        }

        string publicKey { get; set; }
        string privateKey { get; set; }
        string identity { get; set; }
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
                        case nameof(publicKey):
                            publicKey = parameters[i];
                            break;
                        case nameof(privateKey):
                            privateKey = parameters[i];
                            break;
                        case nameof(identity):
                            identity = parameters[i];
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

            logger.LogTrace($"Settings: [{nameof(publicKey)}:{publicKey}] [{nameof(privateKey)}:{privateKey}] [{nameof(identity)}:{identity}] [{nameof(passPhrase)}:{passPhrase}]");
        }
    }
}
