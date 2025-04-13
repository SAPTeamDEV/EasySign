using System.CommandLine;
using System.Diagnostics.Metrics;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

using Spectre.Console;

namespace SAPTeam.EasySign.CommandLine
{
    /// <summary>
    /// Provides command definitions and handlers for the EasySign command line interface.
    /// </summary>
    /// <typeparam name="TBundle">The type of the bundle.</typeparam>
    /// <typeparam name="TConfiguration">The type of the command provider configuration.</typeparam>
    public abstract partial class CommandProvider<TBundle, TConfiguration>
        where TBundle : Bundle
        where TConfiguration : CommandProviderConfiguration, new()
    {
        /// <summary>
        /// Gets or sets the logger to use for logging.
        /// </summary>
        protected ILogger Logger { get; set; }

        /// <summary>
        /// Gets the application configurations.
        /// </summary>
        public TConfiguration Configuration { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="CommandProvider{TBundle, TConfiguration}"/> class.
        /// </summary>
        /// <param name="configuration">
        /// The configuration for the command provider. If null, a default configuration will be used.
        /// </param>
        /// <param name="logger">
        /// The logger to use for logging. If null, a default null logger will be used.
        /// </param>
        /// <exception cref="ArgumentNullException"></exception>
        protected CommandProvider(TConfiguration? configuration, ILogger? logger)
        {
            Configuration = configuration ?? new();
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
                Argument<string[]> filesArg = new Argument<string[]>("files", description: "Files to add to the bundle, Must be inside the bundle root path\n" +
                    "if not specified, all files in the bundle root path will be added", parse: x =>
                    {
                        List<string> result = [];
                        foreach (var file in x.Tokens.Select(t => t.Value))
                        {
                            if (string.IsNullOrEmpty(file)) continue;

                            result.Add(Path.GetFullPath(file));
                        }

                        return result.ToArray();
                    })
                {
                    Arity = ArgumentArity.ZeroOrMore,
                };

                Option<bool> replaceOpt = new Option<bool>("--replace", "Replace existing entries");
                replaceOpt.AddAlias("-r");

                Option<bool> recursiveOpt = new Option<bool>("--recursive", "Add all files within the bundle root path recursively");
                recursiveOpt.AddAlias("-R");

                Option<bool> continueOpt = new Option<bool>("--continue", "Continue adding files if an error occurs");
                continueOpt.AddAlias("-c");

                Option<bool> forceOpt = new Option<bool>("--force", "Add files even if the bundle is signed");

                Command command = new Command("add", "Create new bundle or update an existing one")
                {
                    BundlePath,
                    filesArg,
                    replaceOpt,
                    recursiveOpt,
                    continueOpt,
                };

                command.SetHandler((bundlePath, files, replace, recursive, continueOnError, force) =>
                {
                    InitializeBundle(bundlePath);
                    Utilities.RunInStatusContext("[yellow]Preparing[/]", ctx => RunAdd(ctx, files, replace, recursive, continueOnError, force));
                }, BundlePath, filesArg, replaceOpt, recursiveOpt, continueOpt, forceOpt);

                return command;
            }
        }

        /// <summary>
        /// Gets the command for Showing bundle information
        /// </summary>
        public Command Info
        {
            get
            {
                Command command = new Command("info", "Show bundle information")
                {
                    BundlePath,
                };

                command.SetHandler((bundlePath) =>
                {
                    InitializeBundle(bundlePath);
                    Utilities.RunInStatusContext("[yellow]Preparing[/]", ctx => RunInfo(ctx));
                }, BundlePath);

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

                Option<bool> skipVerifyOpt = new Option<bool>("--skip-verification", "Skip verification of the certificate");

                Command command = new Command("sign", "Sign bundle with certificate")
                    {
                        BundlePath,
                        pfxOpt,
                        pfxPassOpt,
                        pfxNoPassOpt,
                        selfSignOpt,
                        skipVerifyOpt,
                    };

                command.SetHandler((bundlePath, pfxFilePath, pfxFilePassword, pfxNoPasswordPrompt, selfSign, skipVerify) =>
                {
                    InitializeBundle(bundlePath);

                    X509Certificate2Collection collection;
                    X509Certificate2Collection certs;

                    if (selfSign)
                    {
                        if (!Configuration.Settings["selfsign.enable"])
                        {
                            AnsiConsole.MarkupLine("[red]Self-Signing feature is disabled[/]");
                            return;
                        }

                        X509Certificate2? rootCA = GetSelfSigningRootCA();
                        if (rootCA == null)
                        {
                            AnsiConsole.MarkupLine("[red]Self-Signing Root CA not found[/]");
                            return;
                        }

                        string? selectedCert = null;
                        if (Configuration.IssuedCertificates.Count > 0)
                        {
                            selectedCert = AnsiConsole.Prompt<string>(
                            new SelectionPrompt<string>()
                                .PageSize(10)
                                .Title("Select Self-Signing Certificate")
                                .MoreChoicesText("[grey](Move up and down to see more certificates)[/]")
                                .AddChoices(Configuration.IssuedCertificates.Keys)
                                .AddChoices("Issue New Certificate"));
                        }

                        if (string.IsNullOrEmpty(selectedCert) || selectedCert == "Issue New Certificate")
                        {
                            var subject = CertificateUtilities.GetSubjectFromUser();
                            var issuedCert = CertificateUtilities.IssueCertificate(subject.ToString(), rootCA);

                            Configuration.AddCertificate(CertificateStore.IssuedCertificates, issuedCert, subject.CommonName);

                            certs = new X509Certificate2Collection(issuedCert);
                        }
                        else
                        {
                            certs = [Configuration.LoadCertificate(CertificateStore.IssuedCertificates, selectedCert)];
                        }
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

                    Utilities.RunInStatusContext("[yellow]Preparing[/]", ctx => RunSign(ctx, collection, skipVerify));
                }, BundlePath, pfxOpt, pfxPassOpt, pfxNoPassOpt, selfSignOpt, skipVerifyOpt);

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
                var ignoreTimeOpt = new Option<bool>("--ignore-time", "Ignore time validation");
                ignoreTimeOpt.AddAlias("-i");

                Command command = new Command("verify", "Verify bundle")
                {
                    BundlePath,
                    ignoreTimeOpt,
                };

                command.SetHandler((bundlePath, ignoreTime) =>
                {
                    InitializeBundle(bundlePath);
                    Utilities.RunInStatusContext("[yellow]Preparing[/]", ctx => RunVerify(ctx, ignoreTime));
                }, BundlePath, ignoreTimeOpt);

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
                var forceOpt = new Option<bool>("--force", "Generate new self-signed root CA even if one already exists");
                forceOpt.AddAlias("-f");

                var cnOption = new Option<string>(
                    aliases: ["--commonName", "-cn"],
                    description: "Common Name for the certificate (e.g., example.com)\n" +
                                 "If not specified, the user will be prompted for input.");

                var emailOption = new Option<string>(
                    aliases: ["--email", "-e"],
                    description: "Email address (e.g., support@example.com)");

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
                    aliases: ["--state", "-st"],
                    description: "State or Province (e.g., NY)");

                var countryOption = new Option<string>(
                    aliases: ["--country", "-c"],
                    description: "Country (e.g., US)");

                var command = new Command("self-sign", "Generate self-signed root CA")
                {
                    forceOpt,
                    cnOption,
                    emailOption,
                    orgOption,
                    ouOption,
                    locOption,
                    stateOption,
                    countryOption,
                };

                command.SetHandler(RunSelfSign, forceOpt, cnOption, emailOption, orgOption, ouOption, locOption, stateOption, countryOption);

                return command;
            }
        }

        /// <summary>
        /// Gets the command for managing trusted root CAs and intermediate CAs.
        /// </summary>
        public Command Trust
        {
            get
            {
                var caPathArg = new Argument<string>("path", "Path to the certificate file in PEM or DER format")
                {
                    Arity = ArgumentArity.ExactlyOne,
                };

                var interOpt = new Option<bool>("--intermediate", "Run command for Intermediate CA");
                interOpt.AddAlias("-i");

                Command addCmd = new Command("add", "Add trusted root CA or intermediate CA certificate")
                {
                    caPathArg,
                    interOpt,
                };

                addCmd.SetHandler((path, intermediate) =>
                {
                    if (!File.Exists(path))
                    {
                        AnsiConsole.MarkupLine($"[red]Certificate file not found: {path}[/]");
                        return;
                    }

                    var certificate = CertificateUtilities.Import(path);
                    CertificateUtilities.DisplayCertificate(certificate);

                    var modifier = intermediate ? "Intermediate" : "Trusted Root";
                    var store = intermediate ? CertificateStore.IntermediateCA : CertificateStore.TrustedRootCA;

                    var id = Configuration.AddCertificate(store, certificate);
                    AnsiConsole.MarkupLine($"[green] {modifier} CA certificate added with ID: {id}[/]");
                }, caPathArg, interOpt);

                var verboseOpt = new Option<bool>("--verbose", "Show detailed information about the certificate");
                verboseOpt.AddAlias("-v");

                var listCmd = new Command("list", "List trusted root CA and intermediate CA certificates")
                {
                    interOpt,
                    verboseOpt,
                };

                listCmd.SetHandler((intermediate, verbose) =>
                {
                    string modifier = intermediate ? "Intermediate" : "Trusted Root";
                    var store = intermediate ? CertificateStore.IntermediateCA : CertificateStore.TrustedRootCA;
                    var target = intermediate ? Configuration.IntermediateCA : Configuration.TrustedRootCA;

                    X509Certificate2Collection certificates = [];
                    AnsiConsole.WriteLine($"{modifier} CA certificates:");
                    foreach (var cert in target)
                    {
                        var certificate = Configuration.LoadCertificate(store, cert.Key);
                        var subject = new CertificateSubject(certificate);
                        var isProtected = Configuration.IsProtected(cert.Key);

                        AnsiConsole.MarkupLine($"[{(isProtected ? Color.Green : Color.White)}]   {cert.Key}{(isProtected ? " (Protected)" : "")}[/]");

                        certificates.Add(certificate);
                    }

                    if (verbose)
                    {
                        AnsiConsole.WriteLine();
                        CertificateUtilities.DisplayCertificate(certificates.ToArray());
                    }

                }, interOpt, verboseOpt);

                var idArg = new Argument<string>("ID", "ID of the certificate")
                {
                    Arity = ArgumentArity.ExactlyOne,
                };

                var removeCmd = new Command("remove", "Remove trusted root CA or intermediate CA certificate")
                {
                    idArg,
                    interOpt,
                };

                removeCmd.SetHandler((id, intermediate) =>
                {
                    var modifier = intermediate ? "Intermediate" : "Trusted Root";
                    var store = intermediate ? CertificateStore.IntermediateCA : CertificateStore.TrustedRootCA;

                    if (Configuration.IsProtected(id))
                    {
                        AnsiConsole.MarkupLine($"[red]This ID is protected and cannot be modified[/]");
                        return;
                    }

                    if (Configuration.RemoveCertificate(store, id))
                    {
                        AnsiConsole.MarkupLine($"[green]{modifier} CA certificate removed with ID: {id}[/]");
                    }
                    else
                    {
                        AnsiConsole.MarkupLine($"[red]{modifier} CA certificate with ID: {id} not found![/]");
                    }
                }, idArg, interOpt);

                Command command = new Command("trust", "Manage trusted root CAs and intermediate CAs");

                if (Configuration.Settings["trust.enable"])
                {
                    command.AddCommand(addCmd);
                    command.AddCommand(listCmd);
                    command.AddCommand(removeCmd);
                }
                else
                {
                    command.SetHandler(() =>
                    {
                        AnsiConsole.MarkupLine("[red]Custom trust store feature is disabled[/]");
                        return;
                    });
                }

                return command;
            }
        }

        /// <summary>
        /// Gets the command for managing configuration settings.
        /// </summary>
        public Command Config
        {
            get
            {
                var keyArg = new Argument<string>("key", "Key to set or get\n" +
                    "if not specified, will list all keys")
                {
                    Arity = ArgumentArity.ZeroOrOne,
                };

                var valueArg = new Argument<string>("value", "Value to set\n" +
                    "if not specified, will get the value of the key")
                {
                    Arity = ArgumentArity.ZeroOrOne,
                };

                var forceOpt = new Option<bool>("--force", "Set value even if it is not existing");
                forceOpt.AddAlias("-f");

                var command = new Command("config", "Get or set configuration values")
                {
                    keyArg,
                    valueArg,
                    forceOpt,
                };

                command.SetHandler((key, value, force) =>
                {
                    if (string.IsNullOrEmpty(value))
                    {
                        var items = string.IsNullOrEmpty(key) ? Configuration.Settings : Configuration.Settings.Where(x => x.Key.StartsWith(key));

                        foreach (var item in items)
                        {
                            AnsiConsole.WriteLine($"{item.Key} = {item.Value}");
                        }
                    }
                    else
                    {
                        if (!force && !Configuration.Settings.ContainsKey(key))
                        {
                            AnsiConsole.MarkupLine($"[red]Invalid key: {key}[/]");
                            return;
                        }

                        bool bValue;
                        try
                        {
                            bValue = Utilities.ParseToBool(value);
                        }
                        catch
                        {
                            AnsiConsole.MarkupLine($"[red]Invalid value: {value}[/]");
                            return;
                        }

                        Configuration.Settings[key] = bValue;
                        AnsiConsole.MarkupLine($"[green]{key} set to {Configuration.Settings[key]}[/]");
                    }
                }, keyArg, valueArg, forceOpt);

                return command;
            }
        }

        /// <summary>
        /// Runs the self-sign command to create a self-signed root CA certificate.
        /// </summary>
        /// <param name="force">A value indicating whether to force the creation of a new self-signed root CA certificate even if one already exists.</param>
        /// <param name="commonName">Common Name (CN) - required. if not specified, will prompt for user input.</param>
        /// <param name="email">Email (E) - optional.</param>
        /// <param name="organization">Organization (O) - optional.</param>
        /// <param name="organizationalUnit">Organizational Unit (OU) - optional.</param>
        /// <param name="locality">Locality (L) - optional.</param>
        /// <param name="state">State or Province (ST) - optional.</param>
        /// <param name="country">Country (C) - optional.</param>
        public virtual void RunSelfSign(bool force, string? commonName, string? email, string? organization, string? organizationalUnit, string? locality, string? state, string? country)
        {
            if (!Configuration.Settings["selfsign.enable"])
            {
                AnsiConsole.MarkupLine("[red]Self-Signing feature is disabled[/]");
                return;
            }

            Logger.LogInformation("Running self-sign command");

            if (force || Configuration.SelfSignedRootCA != null)
            {
                Logger.LogWarning("Root CA already exists");
                AnsiConsole.MarkupLine("[red]Root CA already exists![/]");
                return;
            }

            string subject;

            if (string.IsNullOrEmpty(commonName))
            {
                Logger.LogDebug("Getting subject name from user");
                subject = CertificateUtilities.GetSubjectFromUser().ToString();
            }
            else
            {
                subject = new CertificateSubject(commonName: commonName,
                                                 email: email,
                                                 organization: organization,
                                                 organizationalUnit: organizationalUnit,
                                                 locality: locality,
                                                 state: state,
                                                 country: country).ToString();
            }

            Logger.LogInformation("Creating self-signed root CA certificate with subject: {subject}", subject);
            var rootCA = CertificateUtilities.CreateSelfSignedCACertificate(subject);
            Logger.LogDebug("Root CA certificate issued with subject: {subject}", rootCA.Subject);

            Logger.LogDebug("Exporting root CA certificate to configuration");
            Configuration.SelfSignedRootCA = rootCA.Export(X509ContentType.Pfx);

            Logger.LogDebug("Clearing issued certificates");
            Configuration.IssuedCertificates.Clear();
            
            CertificateUtilities.DisplayCertificate(rootCA);

            Logger.LogInformation("Root CA created successfully");
            AnsiConsole.MarkupLine($"[green]Root CA created successfully![/]");
        }

        /// <summary>
        /// Gets the self-signed root CA.
        /// </summary>
        /// <returns>
        /// The self-signed root CA certificate, or null if it does not exist.
        /// </returns>
        protected X509Certificate2? GetSelfSigningRootCA()
        {
            if (Configuration.SelfSignedRootCA != null)
            {
                return CertificateUtilities.ImportPFX(Configuration.SelfSignedRootCA).Single();
            }

            return null;
        }
    }
}
