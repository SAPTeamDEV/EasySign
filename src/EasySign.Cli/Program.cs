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
        static int Main(string[] args)
        {
            Log.Logger = new LoggerConfiguration()
                .WriteTo.File(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs/log-.txt"), rollingInterval: RollingInterval.Day, shared: true)
                .MinimumLevel.Debug() // Minimum log level
                .CreateLogger();

            var serviceCollection = new ServiceCollection();
            serviceCollection.AddLogging(configure =>
            {
                configure.ClearProviders(); // Clear default providers
                configure.AddSerilog();
            });

            var serviceProvider = serviceCollection.BuildServiceProvider();

            // Resolve an ILogger instance
            var logger = serviceProvider.GetRequiredService<ILogger<Program>>();
            logger.BeginScope("EasySign.Cli started at " + DateTime.Now);

            var root = new BundleCommandProvider(logger).GetRootCommand();
            var exitCode = root.Invoke(args);

            return exitCode;
        }

    }
}
