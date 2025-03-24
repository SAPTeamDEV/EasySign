using System;
using System.Collections.Generic;
using System.CommandLine;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Spectre.Console;

namespace SAPTeam.EasySign.CommandLine
{
    public abstract partial class CommandProvider<T>
    {
        protected Argument<string> WorkingDirectory { get; } = new Argument<string>("directory", "Working directory");

        protected Option<string> BundleName { get; } = new Option<string>("-f", () => ".eSign", "Bundle file name");

        public abstract RootCommand GetRootCommand();

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
                    Utils.RunInStatusContext(ctx => RunAdd(ctx));
                }, WorkingDirectory, BundleName);

                return command;
            }
        }

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
                    X509Certificate2Collection collection = Utils.GetCertificates(pfxFilePath, pfxFilePassword, pfxNoPasswordPrompt);

                    Utils.RunInStatusContext(ctx => RunSign(ctx, collection));
                }, WorkingDirectory, BundleName, pfxOpt, pfxPassOpt, pfxNoPassOpt);

                return command;
            }
        }

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
                    Utils.RunInStatusContext(ctx => RunVerify(ctx));
                }, WorkingDirectory, BundleName);

                return command;
            }
        }
    }
}
