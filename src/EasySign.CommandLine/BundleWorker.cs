﻿using System.Security.Cryptography.X509Certificates;

using Microsoft.Extensions.Logging;

using Spectre.Console;

namespace SAPTeam.EasySign.CommandLine
{
    public abstract partial class CommandProvider<TBundle, TConfiguration>
    {
        /// <summary>
        /// Gets or sets the bundle.
        /// </summary>
        public TBundle? Bundle { get; protected set; }

        /// <summary>
        /// Initializes the bundle.
        /// </summary>
        /// <param name="bundlePath">Path of the bundle.</param>
        protected abstract void InitializeBundle(string bundlePath);

        /// <summary>
        /// Loads the bundle from file and handles load errors.
        /// </summary>
        /// <param name="readOnly">
        /// A value indicating whether to load the bundle in read-only mode.
        /// </param>
        protected bool LoadBundle(bool readOnly = true)
        {
            if (Bundle == null)
            {
                throw new ApplicationException("Bundle is not initialized");
            }

            try
            {
                Bundle.LoadFromFile(readOnly);

                if (!string.IsNullOrEmpty(Bundle.Manifest.UpdatedBy) && Bundle.Manifest.UpdatedBy != Bundle.GetType().FullName)
                {
                    Logger.LogWarning("Bundle was created by a different application");
                    AnsiConsole.MarkupLine($"[{Color.Orange1}]Warning:[/] Bundle was created by a different application");
                }

                return true;
            }
            catch (FileNotFoundException fnfex)
            {
                Logger.LogError(fnfex, "Bundle file not found: {BundlePath}", Bundle.BundlePath);
                AnsiConsole.MarkupLine($"[red]File not found: {Bundle.BundlePath}[/]");
            }
            catch (Exception ex)
            {
                Logger.LogError(ex, "Failed to load bundle from file: {BundlePath}", Bundle.BundlePath);
                AnsiConsole.MarkupLine($"[{Color.Red}]Failed to load file: {Bundle.BundlePath}[/]");
                AnsiConsole.MarkupLine($"[{Color.Red}]Error:[/] {ex.GetType().Name}: {ex.Message}");
            }

            return false;
        }

        /// <summary>
        /// Runs the add command.
        /// </summary>
        /// <param name="statusContext">
        /// The status context for interacting with <see cref="AnsiConsole.Status"/>.
        /// </param>
        /// <param name="files">
        /// The files to add to the bundle.
        /// </param>
        /// <param name="replace">
        /// A value indicating whether to replace existing entries.
        /// </param>
        /// <param name="recursive">
        /// A value indicating whether to add files recursively.
        /// </param>
        /// <param name="continueOnError">
        /// A value indicating whether to continue adding files if an error occurs.
        /// </param>
        /// <param name="force">
        /// A value indicating whether to force the addition of files to a signed bundle.
        /// </param>
        protected virtual void RunAdd(StatusContext statusContext, string[] files, bool replace, bool recursive, bool continueOnError, bool force)
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
                
                if (!LoadBundle(false)) return;

                if (!force && Bundle.Signatures.Entries.Count > 0)
                {
                    Logger.LogError("Bundle is already signed, cannot add files");
                    AnsiConsole.MarkupLine($"[{Color.Red}]Cannot add files to a signed bundle[/]");
                    return;
                }
            }

            statusContext.Status("[yellow]Adding Files[/]");

            if (files.Length == 0)
            {
                Logger.LogDebug("Discovering files in the directory: {RootPath}", Bundle.RootPath);

                if ((files = Utilities.SafeEnumerateFiles(Bundle.RootPath, "*", recursive).ToArray()).Length == 0)
                {
                    Logger.LogWarning("No files found in the directory: {RootPath}", Bundle.RootPath);
                    AnsiConsole.MarkupLine($"[{Color.Red}]No files found in the directory: {Bundle.RootPath}[/]");
                    return;
                }
                else
                {
                    Logger.LogInformation("Discovered {FileCount} files in the directory: {RootPath}", files.Length, Bundle.RootPath);
                    AnsiConsole.MarkupLine($"[{Color.Green}]Discovered {files.Length} files in the directory: {Bundle.RootPath}[/]");
                }
            }

            Logger.LogInformation("Starting file adder multi-thread task");
            bool errorOccurred = false;
            bool bundleUpdated = false;

            _ = Parallel.ForEach(files, (file, state) =>
            {
                if (file == Bundle.BundlePath)
                {
                    Logger.LogWarning("File {file} is the bundle file itself", file);
                    AnsiConsole.MarkupLine($"[{Color.Yellow}]Ignored:[/] File {file} is the bundle file itself");
                    return;
                }

                string entryName = Manifest.GetNormalizedEntryName(Path.GetRelativePath(Bundle.RootPath, file));

                Logger.LogInformation("Processing file: {EntryName}", entryName);

                try
                {
                    if (!Utilities.IsFileWithinRoot(file, Bundle.RootPath))
                    {
                        Logger.LogWarning("File {file} is outside the bundle root path", file);
                        AnsiConsole.MarkupLine($"[{Color.Yellow}]Ignored:[/] File {file} is outside the bundle root path");
                        return;
                    }

                    if (Bundle.Manifest.Entries.ContainsKey(entryName))
                    {
                        if (!replace)
                        {
                            Logger.LogWarning("Entry already exists: {EntryName}", entryName);
                            AnsiConsole.MarkupLine($"[{Color.Yellow}]Exists:[/] {entryName}");
                            return;
                        }

                        Logger.LogDebug("Replacing entry: {EntryName}", entryName);

                        Bundle.DeleteEntry(entryName);
                        Bundle.AddEntry(file);
                        bundleUpdated = true;

                        Logger.LogInformation("Entry: {EntryName} Replaced", entryName);
                        AnsiConsole.MarkupLine($"[{Color.Cyan2}]Replaced:[/] {entryName}");
                    }
                    else
                    {
                        Logger.LogDebug("Adding entry: {EntryName}", entryName);

                        Bundle.AddEntry(file);
                        bundleUpdated = true;

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

            AnsiConsole.WriteLine();

            if (errorOccurred)
            {
                AnsiConsole.MarkupLine("[orange]One or more errors occurred, check the console output or logs for more information[/]");
            }

            if (bundleUpdated && (continueOnError || !errorOccurred))
            {
                Logger.LogInformation("Saving bundle");
                statusContext.Status("[yellow]Saving Bundle[/]");

                Bundle.Update();

                Logger.LogInformation("Bundle saved successfully");
                AnsiConsole.MarkupLine($"[green]File: {Bundle.BundlePath} Saved successfully[/]");
            }
            else
            {
                Logger.LogInformation("No changes were made to the bundle");
                AnsiConsole.MarkupLine("[yellow]No changes were made to the file[/]");
            }
        }

        /// <summary>
        /// Runs the info command.
        /// </summary>
        /// <param name="statusContext">
        /// The status context for interacting with <see cref="AnsiConsole.Status"/>.
        /// </param>
        protected virtual void RunInfo(StatusContext statusContext)
        {
            Logger.LogInformation("Running info command");

            if (Bundle == null)
            {
                throw new ApplicationException("Bundle is not initialized");
            }

            Logger.LogDebug("Loading bundle");
            statusContext.Status("[yellow]Loading Bundle[/]");
            if (!LoadBundle()) return;

            Grid bundleGrid = new Grid();
            bundleGrid.AddColumn(new GridColumn().NoWrap());
            bundleGrid.AddColumn(new GridColumn().PadLeft(2));

            bundleGrid.AddRow("Bundle Info:");
            bundleGrid.AddRow("   Full Path:", Bundle.BundlePath);
            bundleGrid.AddRow("   Updated By:", Bundle.Manifest.UpdatedBy ?? "N/A");
            bundleGrid.AddRow("   Protected Entry Names:", Bundle.Manifest.ProtectedEntryNames.Count.ToString());
            bundleGrid.AddRow("   Store Files In Bundle:", Bundle.Manifest.StoreOriginalFiles ? "Yes" : "No");
            bundleGrid.AddRow("   Manifest Entries:", Bundle.Manifest.Entries.Count.ToString());
            bundleGrid.AddRow("   Manifest Is Signed:", Bundle.Signatures.Entries.Count > 0 ? "Yes" : "No");
            bundleGrid.AddRow("   Signature Count:", Bundle.Signatures.Entries.Count.ToString());

            AnsiConsole.Write(bundleGrid);
            AnsiConsole.WriteLine();

            Grid protectedEntries = new Grid();
            protectedEntries.AddColumn(new GridColumn().NoWrap());

            protectedEntries.AddRow("Protected Entry Names:");

            foreach (var entryName in Bundle.Manifest.ProtectedEntryNames)
            {
                protectedEntries.AddRow($"   {entryName}");
            }

            AnsiConsole.Write(protectedEntries);
            AnsiConsole.WriteLine();

            Grid manifestEntries = new Grid();
            manifestEntries.AddColumn(new GridColumn());
            manifestEntries.AddColumn(new GridColumn().PadLeft(2).Width(18));

            manifestEntries.AddRow("Manifest Entries:");
            manifestEntries.AddRow("   Entry Name", "Hash");

            foreach (var entry in Bundle.Manifest.Entries)
            {
                var entryHash = BitConverter.ToString(entry.Value).Replace("-", "");
                manifestEntries.AddRow($"   {entry.Key}", $"{entryHash[0..8]}..{entryHash.Substring(entryHash.Length - 8)}");
            }

            AnsiConsole.Write(manifestEntries);
            AnsiConsole.WriteLine();

            CertificateUtilities.DisplayCertificate(Bundle.Signatures.Entries.Keys.Select(Bundle.GetCertificate).ToArray());
        }

        /// <summary>
        /// Runs the sign command.
        /// </summary>
        /// <param name="statusContext">The status context for interacting with <see cref="AnsiConsole.Status"/>.</param>
        /// <param name="certificates">The certificates.</param>
        /// <param name="skipVerify">A value indicating whether to skip certificate verification.</param>
        protected virtual void RunSign(StatusContext statusContext, X509Certificate2Collection certificates, bool skipVerify)
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
            if (!LoadBundle(false)) return;

            int divider = 0;
            int signs = 0;

            foreach (X509Certificate2 cert in certificates)
            {
                if (divider++ > 0) AnsiConsole.WriteLine();

                Logger.LogDebug("Loading certificate information for {Cert}", cert);
                statusContext.Status("[yellow]Loading certificate informations[/]");

                CertificateUtilities.DisplayCertificate(cert);

                if (!skipVerify)
                {
                    Logger.LogDebug("Verifying certificate {cert}", cert);
                    statusContext.Status("[yellow]Verifying Certificate[/]");

                    bool verifyCert = VerifyCertificate(cert, false);
                    if (!verifyCert)
                    {
                        Logger.LogWarning("Skipping signing with {cert}", cert);
                        continue;
                    }
                }

                Logger.LogDebug("Acquiring RSA private key for {cert}", cert);
                statusContext.Status("[yellow]Preparing for signing[/]");

                System.Security.Cryptography.RSA? prvKey = cert.GetRSAPrivateKey();
                if (prvKey == null)
                {
                    Logger.LogError("Failed to acquire RSA private key for {cert}", cert);
                    AnsiConsole.MarkupLine($"[{Color.Red}] Failed to Acquire RSA Private Key[/]");
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
            AnsiConsole.MarkupLine($"[green]File: {Bundle.BundlePath} Saved successfully[/]");
        }

        /// <summary>
        /// Runs the verify command.
        /// </summary>
        /// <param name="statusContext">The status context for interacting with <see cref="AnsiConsole.Status"/>.</param>
        /// <param name="ignoreTime">A value indicating whether to ignore time validity checks for certificate verification.</param>
        /// <returns><see langword="true"></see> if the verification was successful; otherwise, <see langword="false"></see></returns>
        protected virtual bool RunVerify(StatusContext statusContext, bool ignoreTime)
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
            if (!LoadBundle()) return false;

            if (Bundle.Signatures.Entries.Count == 0)
            {
                Logger.LogError("Bundle is not signed");
                AnsiConsole.MarkupLine($"[red]The file is not signed[/]");
                return false;
            }

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

                bool verifyCert = VerifyCertificate(certificate, ignoreTime);
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
                Logger.LogWarning("No certificates were verified");
                AnsiConsole.MarkupLine($"[red]Verification failed[/]");
                return false;
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
                return false;
            }

            Logger.LogInformation("File verification completed successfully");
            AnsiConsole.MarkupLine("[green]All Files Verified Successfully[/]");

            return true;
        }

        /// <summary>
        /// Verifies the validity of a certificate.
        /// </summary>
        /// <remarks>
        /// This method has console output. For internal usages, call <see cref="VerifyCertificateImpl(X509Certificate2, bool, out X509ChainStatus[])"/> instead.
        /// </remarks>
        /// <param name="certificate">
        /// The certificate to verify.
        /// </param>
        /// <param name="ignoreTime">
        /// A value indicating whether to ignore time validity checks.
        /// </param>
        /// <returns>
        /// <see langword="true"/> if the certificate is valid; otherwise, <see langword="false"/>.
        /// </returns>
        protected bool VerifyCertificate(X509Certificate2 certificate, bool ignoreTime)
        {
            bool result = VerifyCertificateImpl(certificate, ignoreTime, out X509ChainStatus[] verificationStatuses);

            if (!result)
            {
                Utilities.EnumerateStatuses(verificationStatuses);
            }

            AnsiConsole.MarkupLine($"[{(result ? Color.Green3 : Color.Red)}] Certificate Verification {(result ? "Successful" : "Failed")}[/]");
            return result;
        }

        /// <summary>
        /// Verifies the certificate using the configured trust stores.
        /// </summary>
        /// <param name="certificate">
        /// The certificate to verify.
        /// </param>
        /// <param name="ignoreTime">
        /// A value indicating whether to ignore time validity checks.
        /// </param>
        /// <param name="chainStatuses">
        /// The chain statuses of the verification.
        /// </param>
        /// <returns>
        /// <see langword="true"/> if the certificate is valid; otherwise, <see langword="false"/>.
        /// </returns>
        /// <exception cref="ApplicationException"></exception>
        protected bool VerifyCertificateImpl(X509Certificate2 certificate, bool ignoreTime, out X509ChainStatus[] chainStatuses)
        {
            if (Bundle == null)
            {
                throw new ApplicationException("Bundle is not initialized");
            }

            List<bool> verificationResults = [];
            List<X509ChainStatus[]> verificationStatuses = [];

            if (Configuration.Settings["selfsign.enable"] && Configuration.SelfSignedRootCA != null)
            {
                verificationResults.Add(SelfSignVerify(certificate, out X509ChainStatus[] selfSigningStatuses));
                verificationStatuses.Add(selfSigningStatuses);
            }

            X509ChainPolicy policy = new();
            policy.ExtraStore.AddRange(Configuration.LoadCertificates(CertificateStore.IntermediateCA));

            if (ignoreTime)
            {
                policy.VerificationFlags |= X509VerificationFlags.IgnoreCtlNotTimeValid;
            }

            if (!verificationResults.Any(x => x))
            {
                Logger.LogDebug("Verifying certificate {cert} with system trust store", certificate);

                bool defaultVerification = Bundle.VerifyCertificate(certificate, out X509ChainStatus[] defaultChainStatuses, policy);

                Logger.LogInformation("Certificate verification with system trust store for {cert}: {result}", certificate, defaultVerification);

                verificationResults.Add(defaultVerification);
                verificationStatuses.Add(defaultChainStatuses);
            }

            if (Configuration.Settings["trust.enable"] && !verificationResults.Any(x => x) && Configuration.TrustedRootCA.Count > 0)
            {
                policy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                policy.CustomTrustStore.AddRange(Configuration.LoadCertificates(CertificateStore.TrustedRootCA));

                Logger.LogDebug("Verifying certificate {cert} with custom trust store", certificate);
                bool customVerification = Bundle.VerifyCertificate(certificate, out X509ChainStatus[] customChainStatuses, policy);
                Logger.LogInformation("Certificate verification with custom trust store for {cert}: {result}", certificate, customVerification);

                verificationResults.Add(customVerification);
                verificationStatuses.Add(customChainStatuses);
            }

            chainStatuses = verificationStatuses.Aggregate((prev, next) =>
            {
                return prev.Intersect(next).ToArray();
            });

            return verificationResults.Any(x => x);
        }

        private bool SelfSignVerify(X509Certificate2 certificate, out X509ChainStatus[] chainStatuses)
        {
            if (Bundle == null)
            {
                throw new ApplicationException("Bundle is not initialized");
            }

            chainStatuses = [];
            X509Certificate2? rootCA;

            if ((rootCA = GetSelfSigningRootCA()) != null)
            {
                Logger.LogDebug("Verifying certificate {cert} with self-signing root CA", certificate);

                X509ChainPolicy selfSignPolicy = new X509ChainPolicy();
                selfSignPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                selfSignPolicy.CustomTrustStore.Add(rootCA);
                selfSignPolicy.VerificationFlags |= X509VerificationFlags.IgnoreNotTimeValid;
                selfSignPolicy.RevocationMode = X509RevocationMode.NoCheck;

                bool selfSignVerification = Bundle.VerifyCertificate(certificate, out chainStatuses, policy: selfSignPolicy);
                Logger.LogInformation("Certificate verification with self-signing root CA for {cert}: {result}", certificate, selfSignVerification);

                return selfSignVerification;
            }

            Logger.LogDebug("Self-signing root CA not found");
            return false;
        }
    }
}
