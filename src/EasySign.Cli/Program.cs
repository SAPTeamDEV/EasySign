﻿using System.CommandLine;

using Serilog;
using Serilog.Extensions.Logging;

namespace SAPTeam.EasySign.Cli
{
    internal class Program
    {
        private static int Main(string[] args)
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

            Serilog.ILogger appLogger = Log.Logger.ForContext("Context", "Main");
            appLogger.Information("Starting EasySign CLI at {DateTime}", DateTime.Now);

            Microsoft.Extensions.Logging.ILogger bundleLogger = new SerilogLoggerFactory(Log.Logger.ForContext("Context", "Bundle"))
                .CreateLogger("CommandProvider");

            Microsoft.Extensions.Logging.ILogger commandProviderLogger = new SerilogLoggerFactory(Log.Logger.ForContext("Context", "CommandProvider"))
                .CreateLogger("CommandProvider");

            RootCommand root = new BundleCommandProvider(commandProviderLogger, bundleLogger).GetRootCommand();
            int exitCode = root.Invoke(args);

            appLogger.Information("Shutting down EasySign CLI at {DateTime} with exit code {ExitCode}", DateTime.Now, exitCode);

            Log.CloseAndFlush();
            return exitCode;
        }
    }
}
