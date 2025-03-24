using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Spectre.Console;

namespace SAPTeam.EasySign.CommandLine
{
    public abstract partial class CommandProvider<T>
        where T : Bundle
    {
        public T Bundle { get; protected set; }

        public abstract void InitializeBundle(string workingDirectory, string bundleName);

        protected virtual void RunAdd(StatusContext statusContext)
        {
            if (Bundle == null)
            {
                throw new ApplicationException("Bundle is not initialized");
            }

            if (!Bundle.IsLoaded && File.Exists(Bundle.BundlePath))
                Bundle.LoadFromFile(false);

            Parallel.ForEach(Utils.SafeEnumerateFiles(Bundle.RootPath, "*"), file =>
            {
                if (file == Bundle.BundlePath) return;
                Bundle.AddEntry(file);
                AnsiConsole.MarkupLine($"[blue]Added:[/] {Path.GetRelativePath(Bundle.RootPath, file)}");
            });

            statusContext.Status("[yellow]Saving Bundle[/]");
            Bundle.Update();
        }

        protected virtual void RunSign(StatusContext statusContext, X509Certificate2Collection certificates)
        {
            if (Bundle == null)
            {
                throw new ApplicationException("Bundle is not initialized");
            }

            Bundle.LoadFromFile(false);

            int divider = 0;
            foreach (var cert in certificates)
            {
                if (divider++ > 0) AnsiConsole.WriteLine();

                var grid = new Grid();
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
                bool verifyCert = VerifyCertificate(cert);
                if (!verifyCert) continue;

                var prvKey = cert.GetRSAPrivateKey();
                if (prvKey == null)
                {
                    AnsiConsole.MarkupLine($"[{Color.Green}] Failed to Acquire RSA Private Key[/]");
                    continue;
                }

                Bundle.Sign(cert, prvKey);
                AnsiConsole.MarkupLine($"[green] Signing Completed Successfully[/]");
            }

            statusContext.Status("[yellow]Updating Bundle[/]");
            Bundle.Update();
        }

        protected virtual void RunVerify(StatusContext statusContext)
        {
            if (Bundle == null)
            {
                throw new ApplicationException("Bundle is not initialized");
            }

            var colorDict = new Dictionary<string, Color>()
            {
                ["file_verified"] = Color.MediumSpringGreen,
                ["file_failed"] = Color.OrangeRed1,
                ["file_missing"] = Color.Grey70,
                ["file_error"] = Color.Red3_1,
            };

            Bundle.LoadFromFile();

            int verifiedCerts = 0;
            int divider = 0;

            foreach (var cert in Bundle.Signatures.Entries.Keys)
            {
                if (divider++ > 0) AnsiConsole.WriteLine();

                var certificate = Bundle.GetCertificate(cert);
                AnsiConsole.MarkupLine($"Verifying Certificate [{Color.Teal}]{certificate.GetNameInfo(X509NameType.SimpleName, false)}[/] Issued by [{Color.Aqua}]{certificate.GetNameInfo(X509NameType.SimpleName, true)}[/]");

                var verifyCert = VerifyCertificate(certificate);
                if (!verifyCert) continue;

                var verifySign = Bundle.VerifySignature(cert);
                AnsiConsole.MarkupLine($"[{(verifySign ? Color.Green : Color.Red)}] Signature Verification {(verifySign ? "Successful" : "Failed")}[/]");
                if (!verifySign) continue;

                verifiedCerts++;
            }

            AnsiConsole.WriteLine();

            if (verifiedCerts == 0)
            {
                if (Bundle.Signatures.Entries.Count == 0)
                    AnsiConsole.MarkupLine($"[red]This bundle is not signed[/]");

                AnsiConsole.MarkupLine($"[red]Verification failed[/]");
                return;
            }

            if (verifiedCerts == Bundle.Signatures.Entries.Count)
                AnsiConsole.MarkupLine($"[{Color.Green3}]All Certificates were verified[/]");
            else
            {
                AnsiConsole.MarkupLine($"[{Color.Yellow}]{verifiedCerts} out of {Bundle.Signatures.Entries.Count} Certificates were verified[/]");
            }

            AnsiConsole.WriteLine();

            statusContext.Status("[yellow]Verifying Files[/]");

            bool p2Verified = true;

            int fv = 0;
            int ff = 0;
            int fm = 0;
            int fe = 0;

            Parallel.ForEach(Bundle.Manifest.Entries, (entry) =>
            {
                var verifyFile = false;

                try
                {
                    verifyFile = Bundle.VerifyFileIntegrity(entry.Key);

                    if (verifyFile)
                        Interlocked.Increment(ref fv);
                    else
                    {
                        Interlocked.Increment(ref ff);
                    }

                    AnsiConsole.MarkupLine($"[{(verifyFile ? colorDict["file_verified"] : colorDict["file_failed"])}]{entry.Key}[/]");
                }
                catch (FileNotFoundException)
                {
                    Interlocked.Increment(ref fm);
                    AnsiConsole.MarkupLine($"[{colorDict["file_missing"]}]{entry.Key}[/]");
                }
                catch (Exception ex)
                {
                    Interlocked.Increment(ref fe);
                    AnsiConsole.MarkupLine($"[{colorDict["file_error"]}]{entry.Key} - {ex.GetType().Name}: {ex.Message}[/]");
                }

                if (!verifyFile)
                    p2Verified = false;
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
                AnsiConsole.MarkupLine($"[red]File Verification Failed[/]");
                return;
            }

            AnsiConsole.MarkupLine("[green]Bundle Verification Completed Successfully[/]");
        }

        protected bool VerifyCertificate(X509Certificate2 certificate)
        {
            if (Bundle == null)
            {
                throw new ApplicationException("Bundle is not initialized");
            }

            List<bool> verifyResults = new();

            var defaultVerification = Bundle.VerifyCertificate(certificate, out X509ChainStatus[] statuses);
            verifyResults.Add(defaultVerification);

            AnsiConsole.MarkupLine($"[{(defaultVerification ? Color.Green : Color.Red)}] Certificate Verification {(defaultVerification ? "Successful" : "Failed")}[/]");

            if (!defaultVerification)
            {
                bool timeIssue = statuses.Any(x => x.Status.HasFlag(X509ChainStatusFlags.NotTimeValid));

                Utils.EnumerateStatuses(statuses);

                if (timeIssue)
                {
                    var policy = new X509ChainPolicy();
                    policy.VerificationFlags |= X509VerificationFlags.IgnoreNotTimeValid;

                    var noTimeVerification = Bundle.VerifyCertificate(certificate, out X509ChainStatus[] noTimeStatuses, policy: policy);
                    verifyResults.Add(noTimeVerification);

                    AnsiConsole.MarkupLine($"[{(noTimeVerification ? Color.Green : Color.Red)}] Certificate Verification without time checking {(noTimeVerification ? "Successful" : "Failed")}[/]");
                    Utils.EnumerateStatuses(noTimeStatuses);
                }
            }

            return verifyResults.Any(x => x);
        }
    }
}
