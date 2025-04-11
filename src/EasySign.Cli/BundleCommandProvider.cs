using System.CommandLine;

using Microsoft.Extensions.Logging;

using SAPTeam.EasySign.CommandLine;

namespace SAPTeam.EasySign.Cli
{
    internal class BundleCommandProvider : CommandProvider<Bundle>
    {
        private readonly ILogger _bundleLogger;

        public BundleCommandProvider(string appDirectory, ILogger logger, ILogger bundleLogger) : base(appDirectory, logger)
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
                SelfSign,
            };

            return root;
        }
    }
}
