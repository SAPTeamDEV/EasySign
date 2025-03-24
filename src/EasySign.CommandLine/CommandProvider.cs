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
        /// Gets the common argument for the working directory.
        /// </summary>
        protected Argument<string> WorkingDirectory { get; } = new Argument<string>("directory", "Working directory");

        /// <summary>
        /// Gets the common option for the bundle file name.
        /// </summary>
        protected Option<string> BundleName { get; } = new Option<string>("-f", () => ".eSign", "Bundle file name");

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
                var command = new Command("add", "Create new bundle or update an existing one")
                    {
                        WorkingDirectory,
                        BundleName,
                    };

                command.SetHandler((workingDir, bundleName) =>
                {
                    InitializeBundle(workingDir, bundleName);
                    Utilities.RunInStatusContext(ctx => RunAdd(ctx));
                }, WorkingDirectory, BundleName);

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
                        WorkingDirectory,
                        BundleName,
                        pfxOpt,
                        pfxPassOpt,
                        pfxNoPassOpt,
                    };

                command.SetHandler((workingDir, bundleName, pfxFilePath, pfxFilePassword, pfxNoPasswordPrompt) =>
                {
                    InitializeBundle(workingDir, bundleName);
                    X509Certificate2Collection collection = Utilities.GetCertificates(pfxFilePath, pfxFilePassword, pfxNoPasswordPrompt);

                    Utilities.RunInStatusContext(ctx => RunSign(ctx, collection));
                }, WorkingDirectory, BundleName, pfxOpt, pfxPassOpt, pfxNoPassOpt);

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
                        WorkingDirectory,
                        BundleName,
                    };

                command.SetHandler((workingDir, bundleName) =>
                {
                    InitializeBundle(workingDir, bundleName);
                    Utilities.RunInStatusContext(ctx => RunVerify(ctx));
                }, WorkingDirectory, BundleName);

                return command;
            }
        }
    }
}
