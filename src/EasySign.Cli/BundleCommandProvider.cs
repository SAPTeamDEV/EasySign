using System;
using System.Collections.Generic;
using System.CommandLine;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using SAPTeam.EasySign.CommandLine;

namespace SAPTeam.EasySign.Cli
{
    internal class BundleCommandProvider : CommandProvider<Bundle>
    {
        public override void InitializeBundle(string bundlePath)
        {
            Bundle = new Bundle(bundlePath);
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
