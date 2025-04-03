using System.CommandLine;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace SAPTeam.EasySign.CommandLine
{
    /// <summary>
    /// Provides command definitions and handlers for the EasySign command line interface.
    /// </summary>
    /// <typeparam name="T">The type of the bundle.</typeparam>
    public abstract partial class CommandProvider<T>
    {
        /// <summary>
        /// Gets or sets the logger to use for logging.
        /// </summary>
        protected ILogger Logger { get; set; } = NullLogger.Instance;

        /// <summary>
        /// Gets the common argument for the bundle path.
        /// </summary>
        protected Argument<string> BundlePath { get; } = new Argument<string>("bundle", "Bundle path or directory containing the bundle\n" +
            "if the bundle name is not specified, a default name will be used");

        /// <summary>
        /// Gets the root command for the command line interface.
        /// </summary>
        /// <returns>The root command.</returns>
        public abstract RootCommand GetRootCommand();

        /// <summary>
        /// Gets the command for creating a new bundle or updating an existing one.
        /// </summary>
        public Command Add
        {
            get
            {
                Option<bool> replaceOpt = new Option<bool>("--replace", "Replace existing entries");
                replaceOpt.AddAlias("-r");

                Option<bool> continueOpt = new Option<bool>("--continue", "Continue adding files if an error occurs");
                continueOpt.AddAlias("-c");

                Command command = new Command("add", "Create new bundle or update an existing one")
                    {
                        BundlePath,
                        replaceOpt,
                        continueOpt,
                    };

                command.SetHandler((bundlePath, replace, continueOnError) =>
                {
                    InitializeBundle(bundlePath);
                    Utilities.RunInStatusContext("[yellow]Preparing[/]", ctx => RunAdd(ctx, replace, continueOnError));
                }, BundlePath, replaceOpt, continueOpt);

                return command;
            }
        }

        /// <summary>
        /// Gets the command for signing bundle with one or more certificate.
        /// </summary>
        public Command Sign
        {
            get
            {
                Option<string> pfxOpt = new Option<string>("--pfx", "PFX File contains certificate and private key");
                Option<string> pfxPassOpt = new Option<string>("--pfx-password", "PFX File password");
                Option<bool> pfxNoPassOpt = new Option<bool>("--no-password", "Ignore PFX File password prompt");

                Command command = new Command("sign", "Sign bundle with certificate")
                    {
                        BundlePath,
                        pfxOpt,
                        pfxPassOpt,
                        pfxNoPassOpt,
                    };

                command.SetHandler((bundlePath, pfxFilePath, pfxFilePassword, pfxNoPasswordPrompt) =>
                {
                    InitializeBundle(bundlePath);
                    X509Certificate2Collection collection = Utilities.GetCertificates(pfxFilePath, pfxFilePassword, pfxNoPasswordPrompt);

                    Utilities.RunInStatusContext("[yellow]Preparing[/]", ctx => RunSign(ctx, collection));
                }, BundlePath, pfxOpt, pfxPassOpt, pfxNoPassOpt);

                return command;
            }
        }

        /// <summary>
        /// Gets the command for verifying bundle.
        /// </summary>
        public Command Verify
        {
            get
            {
                Command command = new Command("verify", "Verify bundle")
                    {
                        BundlePath,
                    };

                command.SetHandler((bundlePath) =>
                {
                    InitializeBundle(bundlePath);
                    Utilities.RunInStatusContext("[yellow]Preparing[/]", ctx => RunVerify(ctx));
                }, BundlePath);

                return command;
            }
        }
    }
}
