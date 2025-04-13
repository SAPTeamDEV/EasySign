using System.CommandLine;
using System.Text.Json.Serialization;

using Microsoft.Extensions.Logging;

using SAPTeam.EasySign.CommandLine;

namespace SAPTeam.EasySign.Cli
{
    internal class BundleCommandProvider : CommandProvider<Bundle, CommandProviderConfiguration>
    {
        private readonly ILogger _bundleLogger;

        public BundleCommandProvider(CommandProviderConfiguration configuration, ILogger logger, ILogger bundleLogger) : base(configuration, logger)
        {
            _bundleLogger = bundleLogger;
        }

        protected override void InitializeBundle(string bundlePath)
        {
            Logger.LogInformation("Initializing bundle at {bundlePath}", bundlePath);
            Bundle = new Bundle(bundlePath, _bundleLogger);
        }

        public override RootCommand GetRootCommand()
        {
            RootCommand root = new RootCommand("Easy Digital Signing Tool")
            {
                Add,
                Info,
                Sign,
                Verify,
                Config,
            };

            if (Configuration.Settings["selfsign.enable"])
            {
                root.Add(SelfSign);
            }

            if (Configuration.Settings["trust.enable"])
            {
                root.Add(Trust);
            }

            return root;
        }
    }

    [JsonSourceGenerationOptions(GenerationMode = JsonSourceGenerationMode.Metadata, WriteIndented = true, DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingDefault)]
    [JsonSerializable(typeof(CommandProviderConfiguration))]
    internal partial class SourceGenerationConfigurationContext : JsonSerializerContext
    {

    }
}
