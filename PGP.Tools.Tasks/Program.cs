using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NLog.Extensions.Logging;
using PGP.Tools.Tasks.Tasks;
using System;
using System.Collections.Generic;
using System.Linq;

namespace PGP.Tools.Tasks
{
    class Program
    {
        static int Main(string[] args)
        {
            BuildDependencyInjection();

            logger.LogInformation("Starting task runner.");
            BuildTasks();

            int result = -1;
            try
            {
                if (args.Length == 0)
                    logger.LogError("No parameters supplied, must supply at least task name.");
                else
                {
                    string taskName = args[0].ToLower();
                    if (InvokeTask(taskName, args))
                        result = 0;
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Error executing task.");
            }

            logger.LogInformation("Task runner complete.");

            return result;
        }


        private static Dictionary<string, Type> Tasks { get; set; }
        static IConfiguration Configuration { get; set; }
        static IServiceProvider ServiceProvider { get; set; }
        static ILogger<Program> logger { get; set; }

        static void BuildDependencyInjection()
        {
            var environmentName = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
            var serviceCollection = new ServiceCollection();
            var builder = new ConfigurationBuilder()
                .SetBasePath(System.IO.Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json")
                .AddJsonFile($"appsettings.{environmentName}.json", true, true)
                .AddEnvironmentVariables();

            Configuration = builder.Build();

            ConfigureServices(serviceCollection);

            ServiceProvider = serviceCollection.BuildServiceProvider();

            var loggerFactory = ServiceProvider.GetRequiredService<ILoggerFactory>();
            //configure NLog
            loggerFactory.AddNLog(new NLogProviderOptions { CaptureMessageTemplates = true, CaptureMessageProperties = true });
            NLog.LogManager.LoadConfiguration("nlog.config");

            logger = ServiceProvider.GetService<ILogger<Program>>();
        }

        private static void ConfigureServices(IServiceCollection services)
        {
            services.AddLogging(configure => configure.AddConsole())
                .AddSingleton<IConfiguration>(Configuration)
                //Add all tasks
                .AddTransient<DecryptFile>()
                .AddTransient<DecryptFiles>()
                .AddTransient<EncryptFile>()
                .AddTransient<EncryptFiles>()
                .AddTransient<GenerateKeyPair>();
        }

        private static void BuildTasks()
        {
            logger.LogDebug("Building task list.");

            Tasks = new Dictionary<string, Type>();
            foreach (Type type in System.Reflection.Assembly.GetExecutingAssembly().GetTypes())
            {
                if (type.IsSubclassOf(typeof(AbstractTask)))
                {
                    string taskName = type.Name.ToLower();

                    logger.LogDebug("Adding task {0} to list of tasks.", taskName);
                    Tasks.Add(taskName, type);
                }
            }
        }

        private static bool InvokeTask(string taskName, string[] args)
        {
            if (!Tasks.ContainsKey(taskName))
            {
                logger.LogError("Could not find task named {0}.", taskName);
                return false;
            }

            logger.LogInformation("Executing task {0}.", taskName);
            Type type = Tasks[taskName];
            AbstractTask task = (AbstractTask)ServiceProvider.GetService(type);//(AbstractTask)Activator.CreateInstance(type);
            string[] argsParsed = args.Skip(1).Take(args.Length - 1).ToArray();
            return task.Execute(argsParsed);
        }
    }
}
