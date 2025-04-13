using System.CommandLine;
using System.Text.Json.Serialization;
using System.Text.Json;
using System.Text;

using Serilog;
using Serilog.Extensions.Logging;
using SAPTeam.EasySign.CommandLine;
using SAPTeam.CommonTK;
using Spectre.Console;

namespace SAPTeam.EasySign.Cli
{
    internal class Program
    {
        public static string AppDirectory => Context.GetApplicationDataDirectory("EasySign");

        public static string ConfigPath => Path.Combine(AppDirectory, "config.json");

        private static int Main(string[] args)
        {
            Log.Logger = new LoggerConfiguration()
                .Enrich.WithThreadId()
                .WriteTo.File(
                    Path.Combine(AppDirectory, "logs/log-.txt"),
                    rollingInterval: RollingInterval.Day,
                    outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff} [{Level:u3}] {Context}({ThreadId}): {Message} {NewLine}{Exception}"
                )
                .MinimumLevel.Debug() // Minimum log level
                .CreateLogger();

            Serilog.ILogger appLogger = Log.Logger.ForContext("Context", "Main");
            appLogger.Information("Starting EasySign CLI");

            Microsoft.Extensions.Logging.ILogger bundleLogger = new SerilogLoggerFactory(Log.Logger.ForContext("Context", "Bundle"))
                .CreateLogger("CommandProvider");

            Microsoft.Extensions.Logging.ILogger commandProviderLogger = new SerilogLoggerFactory(Log.Logger.ForContext("Context", "CommandProvider"))
                .CreateLogger("CommandProvider");

            if (!Directory.Exists(AppDirectory))
            {
                appLogger.Debug("Creating application data directory at {AppDirectory}", AppDirectory);
                Directory.CreateDirectory(AppDirectory);
            }

            CommandProviderConfiguration? config = null;
            if (File.Exists(ConfigPath))
            {
                appLogger.Information("Loading configuration from {ConfigPath}", ConfigPath);
                FileStream fs = File.OpenRead(ConfigPath);

                try
                {
                    config = JsonSerializer.Deserialize(fs, typeof(CommandProviderConfiguration), SourceGenerationConfigurationContext.Default) as CommandProviderConfiguration ?? new CommandProviderConfiguration();
                    fs.Dispose();
                }
                catch
                {
                    fs.Dispose();

                    appLogger.Warning("Failed to load configuration from {ConfigPath}", ConfigPath);
                    config = null;

                    appLogger.Information("Creating backup of the old configuration file at {ConfigPath}.old", ConfigPath + ".old");
                    File.Copy(ConfigPath, ConfigPath + ".old", true);

                    appLogger.Information("Deleting the broken configuration file at {ConfigPath}", ConfigPath);
                    File.Delete(ConfigPath);

                    AnsiConsole.MarkupLine($"[yellow]Failed to load configuration file. A backup has been created at {ConfigPath + ".old"}[/]");
                    AnsiConsole.MarkupLine("[yellow]A new configuration file will be created with default values.[/]");
                }
            }

            if (config == null)
            {
                appLogger.Information("Loading default configuration");
                config = new CommandProviderConfiguration();
            }

            appLogger.Debug("Loading SAP Team trusted certificates");
            config.AddSAPTeamCertificates();

            appLogger.Debug("Initializing command provider");
            var cp = new BundleCommandProvider(config, commandProviderLogger, bundleLogger);

            appLogger.Debug("Loading command line interface");
            RootCommand root = cp.GetRootCommand();

            appLogger.Information("Running command: {command}", args);
            int exitCode = root.Invoke(args);
            appLogger.Information("Command completed with exit code {exitCode}", exitCode);

            appLogger.Information("Shutting down EasySign CLI");

            appLogger.Debug("Saving configuration to {ConfigPath}", ConfigPath);
            string data = JsonSerializer.Serialize(config, config.GetType(), SourceGenerationConfigurationContext.Default);

            if(File.Exists(ConfigPath))
            {
                File.Delete(ConfigPath);
            }

            using (FileStream fs = File.Create(ConfigPath))
            {
                fs.Write(Encoding.UTF8.GetBytes(data));
            }
            appLogger.Debug("Configuration saved to {ConfigPath}", ConfigPath);

            appLogger.Debug("Application shutdown successfully completed");
            Log.CloseAndFlush();
            return exitCode;
        }
    }
}
