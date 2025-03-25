using System;
using System.Collections.Generic;
using System.CommandLine;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Microsoft.Extensions.Logging;

using SAPTeam.EasySign.CommandLine;

namespace SAPTeam.EasySign.Cli
{
    internal class BundleCommandProvider : CommandProvider<Bundle>
    {
        ILogger _bundleLogger;

        public BundleCommandProvider(ILogger logger, ILogger bundleLogger)
        {
            Logger = logger;
            _bundleLogger = bundleLogger;
        }

        public override void InitializeBundle(string bundlePath)
        {
            Logger.LogInformation("Initializing bundle at {bundlePath}", bundlePath);
            Bundle = new Bundle(bundlePath, _bundleLogger);
        }

        public override RootCommand GetRootCommand()
        {
            var root = new RootCommand("Easy Digital Signing Tool")
            {
                Add,
                Sign,
                Verify
            };

            return root;
        }
    }
}
