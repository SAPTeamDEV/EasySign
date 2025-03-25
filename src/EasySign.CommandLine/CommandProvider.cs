using System;
using System.Collections.Generic;
using System.CommandLine;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Spectre.Console;

namespace SAPTeam.EasySign.CommandLine
{
    /// <summary>
    /// Provides command definitions and handlers for the EasySign command line interface.
    /// </summary>
    /// <typeparam name="T">The type of the bundle.</typeparam>
    public abstract partial class CommandProvider<T>
    {
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
                var replaceOpt = new Option<bool>("--replace", "Replace existing entries");
                replaceOpt.AddAlias("-r");

                var command = new Command("add", "Create new bundle or update an existing one")
                    {
                        BundlePath,
                        replaceOpt,
                    };

                command.SetHandler((bundlePath, replace) =>
                {
                    InitializeBundle(bundlePath);
                    Utilities.RunInStatusContext("[yellow]Preparing[/]", ctx => RunAdd(ctx, replace));
                }, BundlePath, replaceOpt);

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
                var pfxOpt = new Option<string>("--pfx", "PFX File contains certificate and private key");
                var pfxPassOpt = new Option<string>("--pfx-password", "PFX File password");
                var pfxNoPassOpt = new Option<bool>("--no-password", "Ignore PFX File password prompt");

                var command = new Command("sign", "Sign bundle with certificate")
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
                var command = new Command("verify", "Verify bundle")
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
