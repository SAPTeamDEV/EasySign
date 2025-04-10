using System.CommandLine;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

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
        /// Gets or sets the logger to use for logging.
        /// </summary>
        protected ILogger Logger { get; set; }

        /// <summary>
        /// Gets or sets the application directory.
        /// </summary>
        public string AppDirectory { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="CommandProvider{T}"/> class with the specified application directory and logger.
        /// </summary>
        /// <param name="appDirectory">
        /// The application directory where configuration files are stored.
        /// </param>
        /// <param name="logger">
        /// The logger to use for logging. If null, a default null logger will be used.
        /// </param>
        /// <exception cref="ArgumentNullException"></exception>
        protected CommandProvider(string appDirectory, ILogger? logger)
        {
            AppDirectory = appDirectory ?? throw new ArgumentNullException(nameof(appDirectory));
            Logger = logger ?? NullLogger.Instance;
        }

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
                
                Option<bool> selfSignOpt = new Option<bool>("--self-sign", "Sign with self-signed certificate");
                selfSignOpt.AddAlias("-s");

                Command command = new Command("sign", "Sign bundle with certificate")
                    {
                        BundlePath,
                        pfxOpt,
                        pfxPassOpt,
                        pfxNoPassOpt,
                        selfSignOpt,
                    };

                command.SetHandler((bundlePath, pfxFilePath, pfxFilePassword, pfxNoPasswordPrompt, selfSign) =>
                {
                    InitializeBundle(bundlePath);

                    X509Certificate2Collection collection;
                    X509Certificate2Collection certs;

                    if (selfSign)
                    {
                        X509Certificate2? rootCA = GetSelfSigningRootCA();
                        if (rootCA == null)
                        {
                            AnsiConsole.MarkupLine("[red]Self-Signing Root CA not found![/]");
                            return;
                        }

                        var subject = CertificateUtilities.GetSubjectNameFromUser();
                        var issuedCert = CertificateUtilities.IssueCertificate(subject, rootCA);

                        certs = new X509Certificate2Collection(issuedCert);
                    }
                    else
                    {
                        certs = CertificateUtilities.GetCertificates(pfxFilePath, pfxFilePassword, pfxNoPasswordPrompt);
                    }

                    if (certs.Count == 0)
                    {
                        AnsiConsole.MarkupLine("[red]No certificates found![/]");
                        return;
                    }
                    else if (certs.Count == 1)
                    {
                        collection = certs;
                    }
                    else
                    {
                        Dictionary<string, X509Certificate2> mapping = [];
                        foreach (X509Certificate2 cert in certs)
                        {
                            mapping[$"{cert.GetNameInfo(X509NameType.SimpleName, false)},{cert.GetNameInfo(X509NameType.SimpleName, true)},{cert.Thumbprint}"] = cert;
                        }

                        List<string> selection = AnsiConsole.Prompt(
                            new MultiSelectionPrompt<string>()
                                .PageSize(10)
                                .Title("Select Signing Certificates")
                                .MoreChoicesText("[grey](Move up and down to see more certificates)[/]")
                                .InstructionsText("[grey](Press [blue]<space>[/] to toggle a certificate, [green]<enter>[/] to accept)[/]")
                                .AddChoices(mapping.Keys));

                        collection = new(selection.Select(x => mapping[x]).ToArray());
                    }

                    Utilities.RunInStatusContext("[yellow]Preparing[/]", ctx => RunSign(ctx, collection));
                }, BundlePath, pfxOpt, pfxPassOpt, pfxNoPassOpt, selfSignOpt);

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

        /// <summary>
        /// Gets the command for generating a self-signed root CA certificate.
        /// </summary>
        public Command SelfSign
        {
            get
            {
                var cnOption = new Option<string>(
                    aliases: ["--commonName", "-cn"],
                    description: "Common Name for the certificate (e.g., example.com)");

                var orgOption = new Option<string>(
                    aliases: ["--organization", "-o"],
                    description: "Organization name (e.g., Example Inc.)");

                var ouOption = new Option<string>(
                    aliases: ["--organizationalUnit", "-ou"],
                    description: "Organizational Unit (e.g., IT Department)");

                var locOption = new Option<string>(
                    aliases: ["--locality", "-l"],
                    description: "Locality (e.g., New York)");

                var stateOption = new Option<string>(
                    aliases: ["--state", "-s"],
                    description: "State or Province (e.g., NY)");

                var countryOption = new Option<string>(
                    aliases: ["--country", "-c"],
                    description: "Country (e.g., US)");

                var command = new Command("self-sign", "Generate self-signed root CA")
                {
                    cnOption,
                    orgOption,
                    ouOption,
                    locOption,
                    stateOption,
                    countryOption,
                };

                command.SetHandler((string commonName, string organization, string organizationalUnit, string locality, string state, string country) =>
                {
                    if (GetSelfSigningRootCA() != null)
                    {
                        AnsiConsole.MarkupLine("[red]Root CA already exists![/]");
                        return;
                    }

                    string subject;

                    if (string.IsNullOrEmpty(commonName))
                    {
                        subject = CertificateUtilities.GetSubjectNameFromUser();
                    }
                    else
                    {
                        subject = CertificateUtilities.GenerateSubjectName(commonName, organization, organizationalUnit, locality, state, country);
                    }

                    var rootCA = CertificateUtilities.CreateSelfSignedCACertificate(subject);

                    using (FileStream fs = File.Create(Path.Combine(AppDirectory, $"rootCA.pfx")))
                    {
                        fs.Write(rootCA.Export(X509ContentType.Pfx));
                    }

                    AnsiConsole.MarkupLine($"[green]Root CA created successfully![/]");
                }, cnOption, orgOption, ouOption, locOption, stateOption, countryOption);

                return command;
            }
        }

        /// <summary>
        /// Gets the self-signed root CA.
        /// </summary>
        /// <returns>
        /// The self-signed root CA certificate, or null if it does not exist.
        /// </returns>
        protected X509Certificate2? GetSelfSigningRootCA()
        {
            string rootCAPath = Path.Combine(AppDirectory, "rootCA.pfx");

            if (File.Exists(rootCAPath))
            {
#if NET9_0_OR_GREATER
                X509Certificate2Collection collection = X509CertificateLoader.LoadPkcs12CollectionFromFile(rootCAPath, null, X509KeyStorageFlags.EphemeralKeySet);
#else
                X509Certificate2Collection collection = new();
                collection.Import(rootCAPath, null, X509KeyStorageFlags.EphemeralKeySet);
#endif

                return collection.First();
            }

            return null;
        }
    }
}
