using System.CommandLine;
using System.Text.Json.Serialization;
using System.Text.Json;
using System.Text;

using Serilog;
using Serilog.Extensions.Logging;
using SAPTeam.EasySign.CommandLine;

namespace SAPTeam.EasySign.Cli
{
    internal class Program
    {
        public static string AppDirectory => AppDomain.CurrentDomain.BaseDirectory;

        public static string ConfigPath => Path.Combine(AppDirectory, "config.json");

        private static int Main(string[] args)
        {
            Log.Logger = new LoggerConfiguration()
                .Enrich.WithThreadId()
                .WriteTo.File(
                    Path.Combine(AppDirectory, "logs/log-.txt"),
                    rollingInterval: RollingInterval.Day,
                    outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff} [{Level:u3}] {Context}({ThreadId}) - {Message} {NewLine}{Exception}"
                )
                .MinimumLevel.Debug() // Minimum log level
                .CreateLogger();

            Serilog.ILogger appLogger = Log.Logger.ForContext("Context", "Main");
            appLogger.Information("Starting EasySign CLI at {DateTime}", DateTime.Now);

            Microsoft.Extensions.Logging.ILogger bundleLogger = new SerilogLoggerFactory(Log.Logger.ForContext("Context", "Bundle"))
                .CreateLogger("CommandProvider");

            Microsoft.Extensions.Logging.ILogger commandProviderLogger = new SerilogLoggerFactory(Log.Logger.ForContext("Context", "CommandProvider"))
                .CreateLogger("CommandProvider");

            CommandProviderConfiguration config;
            if (File.Exists(ConfigPath))
            {
                using FileStream fs = File.OpenRead(ConfigPath);
                config = JsonSerializer.Deserialize(fs, typeof(CommandProviderConfiguration), SourceGenerationConfigurationContext.Default) as CommandProviderConfiguration ?? new CommandProviderConfiguration();
            }
            else
            {
                config = new CommandProviderConfiguration();
            }

            config.AddSAPTeamCertificates();
            var cp = new BundleCommandProvider(config, commandProviderLogger, bundleLogger);

            RootCommand root = cp.GetRootCommand();
            int exitCode = root.Invoke(args);

            appLogger.Information("Shutting down EasySign CLI at {DateTime} with exit code {ExitCode}", DateTime.Now, exitCode);

            string data = JsonSerializer.Serialize(config, config.GetType(), SourceGenerationConfigurationContext.Default);

            if(File.Exists(ConfigPath))
            {
                File.Delete(ConfigPath);
            }

            using (FileStream fs = File.Create(ConfigPath))
            {
                fs.Write(Encoding.UTF8.GetBytes(data));
            }

            Log.CloseAndFlush();
            return exitCode;
        }
    }
}
