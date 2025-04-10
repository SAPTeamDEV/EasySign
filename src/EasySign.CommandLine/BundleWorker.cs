using System.Security.Cryptography.X509Certificates;

using Microsoft.Extensions.Logging;

using Spectre.Console;

namespace SAPTeam.EasySign.CommandLine
{
    public abstract partial class CommandProvider<T>
        where T : Bundle
    {
        /// <summary>
        /// Gets or sets the bundle.
        /// </summary>
        public T? Bundle { get; protected set; }

        /// <summary>
        /// Initializes the bundle.
        /// </summary>
        /// <param name="bundlePath">Path of the bundle.</param>
        public abstract void InitializeBundle(string bundlePath);

        /// <summary>
        /// Runs the add command.
        /// </summary>
        /// <param name="statusContext">
        /// The status context for interacting with <see cref="AnsiConsole.Status"/>.
        /// </param>
        /// <param name="replace">
        /// A value indicating whether to replace existing entries.
        /// </param>
        /// <param name="continueOnError">
        /// A value indicating whether to continue adding files if an error occurs.
        /// </param>
        protected virtual void RunAdd(StatusContext statusContext, bool replace, bool continueOnError)
        {
            Logger.LogInformation("Running add command");

            if (Bundle == null)
            {
                throw new ApplicationException("Bundle is not initialized");
            }

            if (!Bundle.Loaded && File.Exists(Bundle.BundlePath))
            {
                Logger.LogDebug("A bundle file exists, loading bundle");
                statusContext.Status("[yellow]Loading Bundle[/]");
                Bundle.LoadFromFile(false);
            }

            statusContext.Status("[yellow]Adding Files[/]");

            Logger.LogDebug("Discovering files in the directory: {RootPath}", Bundle.RootPath);
            string[] foundFiles = Utilities.SafeEnumerateFiles(Bundle.RootPath, "*").ToArray();
            Logger.LogInformation("Discovered {FileCount} files", foundFiles.Count());

            Logger.LogInformation("Starting file adder multi-thread task");
            bool errorOccurred = false;
            _ = Parallel.ForEach(foundFiles, (file, state) =>
            {
                if (file == Bundle.BundlePath) return;
                string entryName = Manifest.GetNormalizedEntryName(Path.GetRelativePath(Bundle.RootPath, file));

                Logger.LogInformation("Processing file: {EntryName}", entryName);

                try
                {
                    if (Bundle.Manifest.Entries.ContainsKey(entryName))
                    {
                        if (!replace)
                        {
                            Logger.LogWarning("Entry already exists: {EntryName}", entryName);
                            AnsiConsole.MarkupLine($"[{Color.Orange1}]Exists:[/] {entryName}");
                            return;
                        }

                        Logger.LogDebug("Replacing entry: {EntryName}", entryName);

                        Bundle.DeleteEntry(entryName);
                        Bundle.AddEntry(file);

                        Logger.LogInformation("Entry: {EntryName} Replaced", entryName);
                        AnsiConsole.MarkupLine($"[{Color.Cyan2}]Replaced:[/] {entryName}");
                    }
                    else
                    {
                        Logger.LogDebug("Adding entry: {EntryName}", entryName);

                        Bundle.AddEntry(file);

                        Logger.LogInformation("Entry: {EntryName} Added", entryName);
                        AnsiConsole.MarkupLine($"[blue]Added:[/] {entryName}");
                    }
                }
                catch (Exception ex)
                {
                    errorOccurred = true;

                    Logger.LogError(ex, "Error occurred while adding entry: {EntryName}", entryName);
                    AnsiConsole.MarkupLine($"[{Color.Red}]Error:[/] {entryName} ({ex.GetType().Name}: {ex.Message})");

                    if (!continueOnError)
                    {
                        Logger.LogWarning("Stopping add operation due to error");
                        state.Stop();
                    }
                }
            });

            if (errorOccurred)
            {
                AnsiConsole.WriteLine();
                AnsiConsole.MarkupLine("[red]One or more errors occurred, check the console output or logs for more information[/]");

                if (!continueOnError)
                {
                    Logger.LogWarning("Add operation aborted");
                    AnsiConsole.MarkupLine("[red]No changes were made to the bundle[/]");
                    return;
                }
            }

            Logger.LogInformation("Saving bundle");
            statusContext.Status("[yellow]Saving Bundle[/]");
            Bundle.Update();

            Logger.LogInformation("Bundle saved successfully");
            AnsiConsole.MarkupLine($"[green]Bundle file: {Bundle.BundlePath} Saved successfully[/]");
        }

        /// <summary>
        /// Runs the sign command.
        /// </summary>
        /// <param name="statusContext">The status context for interacting with <see cref="AnsiConsole.Status"/>.</param>
        /// <param name="certificates">The certificates.</param>
        protected virtual void RunSign(StatusContext statusContext, X509Certificate2Collection certificates)
        {
            Logger.LogInformation("Running sign command");

            if (Bundle == null)
            {
                throw new ApplicationException("Bundle is not initialized");
            }

            if (certificates.Count == 0)
            {
                Logger.LogWarning("No certificates provided for signing");
                AnsiConsole.MarkupLine("[red]No certificates provided for signing[/]");
                return;
            }

            Logger.LogDebug("Loading bundle");
            statusContext.Status("[yellow]Loading Bundle[/]");
            Bundle.LoadFromFile(false);

            int divider = 0;
            int signs = 0;

            foreach (X509Certificate2 cert in certificates)
            {
                if (divider++ > 0) AnsiConsole.WriteLine();

                Logger.LogDebug("Loading certificate information for {Cert}", cert);
                statusContext.Status("[yellow]Loading certificate informations[/]");

                Grid grid = new Grid();
                grid.AddColumn(new GridColumn().NoWrap());
                grid.AddColumn(new GridColumn().PadLeft(2));
                grid.AddRow("Certificate Info:");
                grid.AddRow("  Common Name", cert.GetNameInfo(X509NameType.SimpleName, false));
                grid.AddRow("  Issuer Name", cert.GetNameInfo(X509NameType.SimpleName, true));
                grid.AddRow("  Holder Email", cert.GetNameInfo(X509NameType.EmailName, false));
                grid.AddRow("  Valid From", cert.GetEffectiveDateString());
                grid.AddRow("  Valid To", cert.GetExpirationDateString());
                grid.AddRow("  Thumbprint", cert.Thumbprint);

                AnsiConsole.Write(grid);
                AnsiConsole.WriteLine();

                Logger.LogDebug("Verifying certificate {cert}", cert);
                statusContext.Status("[yellow]Verifying Certificate[/]");

                bool verifyCert = VerifyCertificate(cert);
                if (!verifyCert)
                {
                    Logger.LogWarning("Skipping signing with {cert}", cert);
                    continue;
                }

                Logger.LogDebug("Acquiring RSA private key for {cert}", cert);
                statusContext.Status("[yellow]Preparing for signing[/]");

                System.Security.Cryptography.RSA? prvKey = cert.GetRSAPrivateKey();
                if (prvKey == null)
                {
                    Logger.LogError("Failed to acquire RSA private key for {cert}", cert);
                    AnsiConsole.MarkupLine($"[{Color.Green}] Failed to Acquire RSA Private Key[/]");
                    continue;
                }

                Logger.LogDebug("Signing bundle with {cert}", cert);
                statusContext.Status("[yellow]Signing Bundle[/]");

                Bundle.Sign(cert, prvKey);

                signs++;
                Logger.LogInformation("Bundle signed with {cert}", cert);
                AnsiConsole.MarkupLine($"[green] Signing Completed Successfully[/]");
            }

            if (signs == 0)
            {
                Logger.LogWarning("No certificates were suitable for signing");
                AnsiConsole.MarkupLine("[red]No certificates were suitable for signing[/]");
                return;
            }

            Logger.LogInformation("Saving bundle");
            statusContext.Status("[yellow]Updating Bundle[/]");
            Bundle.Update();

            Logger.LogInformation("Bundle saved successfully");
            AnsiConsole.MarkupLine($"[green]Bundle file: {Bundle.BundlePath} Saved successfully[/]");
        }

        /// <summary>
        /// Runs the verify command.
        /// </summary>
        /// <param name="statusContext">The status context for interacting with <see cref="AnsiConsole.Status"/>.</param>
        protected virtual void RunVerify(StatusContext statusContext)
        {
            Logger.LogInformation("Running verify command");

            if (Bundle == null)
            {
                throw new ApplicationException("Bundle is not initialized");
            }

            Dictionary<string, Color> colorDict = new Dictionary<string, Color>()
            {
                ["file_verified"] = Color.MediumSpringGreen,
                ["file_failed"] = Color.OrangeRed1,
                ["file_missing"] = Color.Grey70,
                ["file_error"] = Color.Red3_1,
            };

            Logger.LogDebug("Loading bundle");
            statusContext.Status("[yellow]Loading Bundle[/]");
            Bundle.LoadFromFile();

            Logger.LogInformation("Starting certificate and signature verification");
            statusContext.Status("[yellow]Verification Phase 1: Certificates and signatures[/]");

            int verifiedCerts = 0;
            int divider = 0;

            foreach (string certificateHash in Bundle.Signatures.Entries.Keys)
            {
                if (divider++ > 0) AnsiConsole.WriteLine();

                X509Certificate2 certificate = Bundle.GetCertificate(certificateHash);

                Logger.LogDebug("Verifying certificate {cert}", certificate);
                AnsiConsole.MarkupLine($"Verifying Certificate [{Color.Teal}]{certificate.GetNameInfo(X509NameType.SimpleName, false)}[/] Issued by [{Color.Aqua}]{certificate.GetNameInfo(X509NameType.SimpleName, true)}[/]");

                bool verifyCert = VerifyCertificate(certificate);
                if (!verifyCert)
                {
                    Logger.LogWarning("Skipping signature verification for {cert}", certificate);
                    continue;
                }

                Logger.LogDebug("Verifying signature for certificate {cert}", certificate);
                bool verifySign = Bundle.VerifySignature(certificateHash);
                AnsiConsole.MarkupLine($"[{(verifySign ? Color.Green : Color.Red)}] Signature Verification {(verifySign ? "Successful" : "Failed")}[/]");
                if (!verifySign)
                {
                    Logger.LogWarning("Signature verification failed for {cert}", certificate);
                    continue;
                }

                Logger.LogInformation("Certificate and signature verification successful for {cert}", certificate);
                verifiedCerts++;
            }

            AnsiConsole.WriteLine();

            if (verifiedCerts == 0)
            {
                if (Bundle.Signatures.Entries.Count == 0)
                {
                    Logger.LogWarning("Bundle is not signed");
                    AnsiConsole.MarkupLine($"[red]This bundle is not signed[/]");
                }

                Logger.LogWarning("No certificates were verified");
                AnsiConsole.MarkupLine($"[red]Verification failed[/]");
                return;
            }

            if (verifiedCerts == Bundle.Signatures.Entries.Count)
            {
                Logger.LogInformation("All certificates were verified");
                AnsiConsole.MarkupLine($"[{Color.Green3}]All Certificates were verified[/]");
            }
            else
            {
                Logger.LogWarning("{verifiedCerts} out of {totalCerts} certificates were verified", verifiedCerts, Bundle.Signatures.Entries.Count);
                AnsiConsole.MarkupLine($"[{Color.Yellow}]{verifiedCerts} out of {Bundle.Signatures.Entries.Count} Certificates were verified[/]");
            }

            AnsiConsole.WriteLine();

            Logger.LogInformation("Starting file verification for {fileCount} files in multi-thread mode", Bundle.Manifest.Entries.Count);
            statusContext.Status("[yellow]Verification Phase 2: Files[/]");

            bool p2Verified = true;

            int fv = 0;
            int ff = 0;
            int fm = 0;
            int fe = 0;

            _ = Parallel.ForEach(Bundle.Manifest.Entries, (entry) =>
            {
                bool verifyFile = false;

                Logger.LogDebug("Verifying file {file}", entry.Key);

                try
                {
                    verifyFile = Bundle.VerifyFile(entry.Key);

                    if (verifyFile)
                    {
                        Logger.LogInformation("File {file} verified", entry.Key);
                        Interlocked.Increment(ref fv);
                    }
                    else
                    {
                        Logger.LogWarning("File {file} failed verification", entry.Key);
                        Interlocked.Increment(ref ff);
                    }

                    AnsiConsole.MarkupLine($"[{(verifyFile ? colorDict["file_verified"] : colorDict["file_failed"])}]{entry.Key}[/]");
                }
                catch (FileNotFoundException)
                {
                    Logger.LogWarning("File {file} not found", entry.Key);
                    Interlocked.Increment(ref fm);
                    AnsiConsole.MarkupLine($"[{colorDict["file_missing"]}]{entry.Key}[/]");
                }
                catch (Exception ex)
                {
                    Logger.LogError(ex, "Error occurred while verifying file {file}", entry.Key);
                    Interlocked.Increment(ref fe);
                    AnsiConsole.MarkupLine($"[{colorDict["file_error"]}]{entry.Key} - {ex.GetType().Name}: {ex.Message}[/]");
                }

                if (!verifyFile) p2Verified = false;
            });

            AnsiConsole.WriteLine();

            if (Bundle.Manifest.Entries.Count != fv)
            {
                AnsiConsole.MarkupLine("File Verification Summary");
                AnsiConsole.MarkupLine($"[{colorDict["file_verified"]}] {fv} Files verified[/]");
                if (ff > 0) AnsiConsole.MarkupLine($"[{colorDict["file_failed"]}] {ff} Files tampered with[/]");
                if (fm > 0) AnsiConsole.MarkupLine($"[{colorDict["file_missing"]}] {fm} Files not found[/]");
                if (fe > 0) AnsiConsole.MarkupLine($"[{colorDict["file_error"]}] {fe} Files encountered with errors[/]");

                AnsiConsole.WriteLine();
            }

            if (!p2Verified)
            {
                Logger.LogWarning("File verification failed");
                AnsiConsole.MarkupLine($"[red]File Verification Failed[/]");
                return;
            }

            Logger.LogInformation("Bundle verification completed successfully");
            AnsiConsole.MarkupLine("[green]Bundle Verification Completed Successfully[/]");
        }

        /// <summary>
        /// Verifies the validity of a certificate.
        /// </summary>
        /// <param name="certificate">The certificate to verify.</param>
        /// <returns>True if the certificate is valid; otherwise, false.</returns>
        protected bool VerifyCertificate(X509Certificate2 certificate)
        {
            if (Bundle == null)
            {
                throw new ApplicationException("Bundle is not initialized");
            }

            List<bool> verifyResults = [];

            X509Certificate2? rootCA;
            if ((rootCA = GetSelfSigningRootCA()) != null)
            {
                Logger.LogDebug("Verifying certificate {cert} with self-signing root CA", certificate);

                X509ChainPolicy policy = new X509ChainPolicy();
                policy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                policy.CustomTrustStore.Add(rootCA);
                policy.VerificationFlags |= X509VerificationFlags.IgnoreNotTimeValid;
                policy.RevocationMode = X509RevocationMode.NoCheck;

                bool selfSignVerification = Bundle.VerifyCertificate(certificate, out X509ChainStatus[] selfSignStatuses, policy: policy);
                verifyResults.Add(selfSignVerification);

                Logger.LogInformation("Certificate verification with self-signing root CA for {cert}: {result}", certificate, selfSignVerification);
                
                if (!selfSignVerification)
                {
                    AnsiConsole.MarkupLine($"[{Color.Green}] Certificate Verification with Self-Signing Root CA Successful[/]");
                    return true;
                }
            }

            Logger.LogDebug("Verifying certificate {cert} with default verification policy", certificate);
            bool defaultVerification = Bundle.VerifyCertificate(certificate, out X509ChainStatus[] statuses);
            verifyResults.Add(defaultVerification);

            Logger.LogInformation("Certificate verification with default policy for {cert}: {result}", certificate, defaultVerification);
            AnsiConsole.MarkupLine($"[{(defaultVerification ? Color.Green : Color.Red)}] Certificate Verification {(defaultVerification ? "Successful" : "Failed")}[/]");

            if (!defaultVerification)
            {
                bool timeIssue = statuses.Any(x => x.Status.HasFlag(X509ChainStatusFlags.NotTimeValid));

                Utilities.EnumerateStatuses(statuses);

                if (timeIssue)
                {
                    Logger.LogWarning("Certificate has time validity issues, retrying verification with time check disabled");

                    X509ChainPolicy policy = new X509ChainPolicy();
                    policy.VerificationFlags |= X509VerificationFlags.IgnoreNotTimeValid;

                    bool noTimeVerification = Bundle.VerifyCertificate(certificate, out X509ChainStatus[] noTimeStatuses, policy: policy);
                    verifyResults.Add(noTimeVerification);

                    Logger.LogInformation("Certificate verification without time checking for {cert}: {result}", certificate, noTimeVerification);
                    AnsiConsole.MarkupLine($"[{(noTimeVerification ? Color.Green : Color.Red)}] Certificate Verification without time checking {(noTimeVerification ? "Successful" : "Failed")}[/]");
                    Utilities.EnumerateStatuses(noTimeStatuses);
                }
            }

            return verifyResults.Any(x => x);
        }
    }
}
