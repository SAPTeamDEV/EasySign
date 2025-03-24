using System.Collections.Concurrent;
using System.CommandLine;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Spectre.Console;

namespace SAPTeam.EasySign.Cli
{
    internal class Program
    {
        static int Main(string[] args)
        {
            var root = new BundleCommandProvider().GetRootCommand();
            return root.Invoke(args);
        }

    }
}
