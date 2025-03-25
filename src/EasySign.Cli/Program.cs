using System.Collections.Concurrent;
using System.CommandLine;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

using Serilog;

using Spectre.Console;

namespace SAPTeam.EasySign.Cli
{
    internal class Program
    {
        public static Serilog.ILogger Logger { get; private set; }

        static int Main(string[] args)
        {
            Log.Logger = new LoggerConfiguration()
                .Enrich.WithThreadId()
                .WriteTo.File(
                    Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs/log-.txt"),
                    rollingInterval: RollingInterval.Day,
                    outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff} [{Level:u3}] {Context}({ThreadId}) - {Message} {NewLine}{Exception}"
                )
                .MinimumLevel.Debug() // Minimum log level
                .CreateLogger();

            var serviceCollection = new ServiceCollection();
            serviceCollection.AddLogging(configure =>
            {
                configure.ClearProviders(); // Clear default providers
                configure.AddSerilog(Log.Logger.ForContext("Context", "Bundle"));
            });

            var serviceProvider = serviceCollection.BuildServiceProvider();

            // Resolve an ILogger instance
            var bundleLogger = serviceProvider.GetRequiredService<ILogger<Bundle>>();

            Logger = Log.Logger.ForContext("Context", "Main");
            Logger.Information("Starting EasySign CLI at {DateTime}", DateTime.Now);

            var root = new BundleCommandProvider(bundleLogger).GetRootCommand();
            var exitCode = root.Invoke(args);

            Logger.Information("Shutting down EasySign CLI at {DateTime} with exit code {ExitCode}", DateTime.Now, exitCode);

            Log.CloseAndFlush();
            return exitCode;
        }

    }
}
