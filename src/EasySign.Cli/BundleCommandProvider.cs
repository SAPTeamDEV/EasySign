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
        ILogger _logger;

        public BundleCommandProvider(ILogger logger)
        {
            _logger = logger;
        }

        public override void InitializeBundle(string bundlePath)
        {
            Bundle = new Bundle(bundlePath, _logger);
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
