using System.Collections.Concurrent;
using System.CommandLine;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Spectre.Console;

namespace EasySign.Cli
{
    internal class Program
    {
        public static Bundle Bundle { get; set; }

        static RootCommand GetCommands()
        {
            var root = new RootCommand("Easy Digital Signing Tool");

            #region Shared Options
            var directoryArg = new Argument<string>("directory", "Working directory");

            var fileOpt = new Option<string>("-f", () => Bundle.DefaultBundleName, "Bundle file name");
            #endregion

            var addCmd = new Command("add", "Create new bundle or update an existing one")
            {
                directoryArg,
                fileOpt,
            };

            addCmd.SetHandler((workingDir, bundleName) =>
            {
                InitBundle(workingDir, bundleName);
                Add();
            }, directoryArg, fileOpt);

            root.AddCommand(addCmd);

            var signCmd = new Command("sign", "Sign bundle with certificate")
            {
                directoryArg,
                fileOpt,
            };

            signCmd.SetHandler((workingDir, bundleName) =>
            {
                InitBundle(workingDir, bundleName);
                Sign();
            }, directoryArg, fileOpt);

            root.AddCommand(signCmd);

            var verifyCmd = new Command("verify", "Verify bundle")
            {
                directoryArg,
                fileOpt,
            };

            verifyCmd.SetHandler((workingDir, bundleName) =>
            {
                InitBundle(workingDir, bundleName);
                Verify();
            }, directoryArg, fileOpt);

            root.AddCommand(verifyCmd);

            return root;
        }

        static int Main(string[] args)
        {
            var root = GetCommands();
            return root.Invoke(args);
        }

        static void InitBundle(string workingDirectory, string bundleName)
        {
            Bundle = new(workingDirectory, bundleName);
        }

        static void Add()
        {
            AnsiConsole.Status()
                .AutoRefresh(true)
                .Spinner(Spinner.Known.Default)
                .Start("[yellow]Indexing Files[/]", ctx =>
                {
                    if (File.Exists(Bundle.BundlePath))
                    {
                        Bundle.Load(false);
                    }

                    Parallel.ForEach(SafeEnumerateFiles(Bundle.RootPath, "*"), file =>
                    {
                        if (file == Bundle.BundlePath) return;
                        Bundle.AddEntry(file);
                        AnsiConsole.MarkupLine($"[blue]Added:[/] {Path.GetRelativePath(Bundle.RootPath, file)}");
                    });

                    ctx.Status("[yellow]Saving Bundle[/]");
                    Bundle.Update();
                });
        }

        static void Sign()
        {
            AnsiConsole.Status()
                .AutoRefresh(true)
                .Spinner(Spinner.Known.Default)
                .Start("[yellow]Signing[/]", ctx =>
                {
                    Bundle.Load(false);

                    X509Store store = new X509Store("MY", StoreLocation.CurrentUser);
                    store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                    X509Certificate2Collection collection = store.Certificates;

                    int divider = 0;
                    foreach (var cert in collection.Where(x => x.HasPrivateKey))
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

                        var verifyCert = cert.Verify();
                        AnsiConsole.MarkupLine($"[{(verifyCert ? Color.Green : Color.Red)}] Certificate Verification {(verifyCert ? "Successful" : "Failed")}[/]");
                        if (!verifyCert) continue;

                        var prvKey = cert.GetRSAPrivateKey();
                        if (prvKey == null)
                        {
                            AnsiConsole.MarkupLine($"[{Color.Green}] Failed to Acquire RSA Private Key[/]");
                            continue;
                        }

                        Bundle.SignBundle(cert, prvKey);
                        AnsiConsole.MarkupLine($"[green] Signing Completed Successfully[/]");
                    }

                    ctx.Status("[yellow]Updating Bundle[/]");
                    Bundle.Update();
                });
        }

        static void Verify()
        {
            var colorDict = new Dictionary<string, Color>()
            {
                ["cert_verified"] = Color.Green,
                ["cert_failed"] = Color.Red,
                ["file_verified"] = Color.MediumSpringGreen,
                ["file_failed"] = Color.OrangeRed1,
                ["file_missing"] = Color.Grey70,
                ["file_error"] = Color.Red3_1,
            };

            AnsiConsole.Status()
                .AutoRefresh(true)
                .Spinner(Spinner.Known.Default)
                .Start("[yellow]Verifying Signature[/]", ctx =>
                {
                    Bundle.Load();

                    int verifiedCerts = 0;
                    int divider = 0;

                    foreach (var cert in Bundle.Signatures.Entries.Keys)
                    {
                        if (divider++ > 0) AnsiConsole.WriteLine();

                        var certificate = Bundle.GetCertificate(cert);
                        AnsiConsole.MarkupLine($"Verifying Certificate [{Color.Teal}]{certificate.GetNameInfo(X509NameType.SimpleName, false)}[/] Issued by [{Color.Aqua}]{certificate.GetNameInfo(X509NameType.SimpleName, true)}[/]");

                        var verifyCert = Bundle.VerifyCertificate(cert);
                        AnsiConsole.MarkupLine($"[{(verifyCert ? colorDict["cert_verified"] : colorDict["cert_failed"])}] Certificate Verification {(verifyCert ? "Successful" : "Failed")}[/]");
                        if (!verifyCert) continue;

                        var verifySign = Bundle.VerifySignature(cert);
                        AnsiConsole.MarkupLine($"[{(verifySign ? colorDict["cert_verified"] : colorDict["cert_failed"])}] Signature Verification {(verifySign ? "Successful" : "Failed")}[/]");
                        if (!verifySign) continue;

                        verifiedCerts++;
                    }

                    AnsiConsole.WriteLine();

                    if (verifiedCerts == 0)
                    {
                        if (Bundle.Signatures.Entries.Count == 0)
                        {
                            AnsiConsole.MarkupLine($"[red]This bundle is not signed[/]");
                        }

                        AnsiConsole.MarkupLine($"[red]Verification failed[/]");
                        return;
                    }

                    if (verifiedCerts == Bundle.Signatures.Entries.Count)
                    {
                        AnsiConsole.MarkupLine($"[{Color.Green3}]All Certificates were verified[/]");
                    }
                    else
                    {
                        AnsiConsole.MarkupLine($"[{Color.Yellow}]{verifiedCerts} out of {Bundle.Signatures.Entries.Count} Certificates were verified[/]");
                    }
                    
                    AnsiConsole.WriteLine();

                    ctx.Status("[yellow]Verifying Files[/]");

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
                            verifyFile = Bundle.VerifyFile(entry.Key);

                            if (verifyFile)
                            {
                                Interlocked.Increment(ref fv);
                            }
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
                        {
                            p2Verified = false;
                        }
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
                });
        }

        public static IEnumerable<string> SafeEnumerateFiles(string path, string searchPattern)
        {
            ConcurrentQueue<string> folders = new();
            folders.Enqueue(path);

            while (!folders.IsEmpty)
            {
                folders.TryDequeue(out string currentDir);
                string[] subDirs;
                string[] files = null;

                try
                {
                    files = Directory.GetFiles(currentDir, searchPattern);
                }
                catch (UnauthorizedAccessException) { }
                catch (DirectoryNotFoundException) { }

                if (files != null)
                {
                    foreach (string file in files)
                    {
                        yield return file;
                    }
                }

                try
                {
                    subDirs = Directory.GetDirectories(currentDir);
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (DirectoryNotFoundException) { continue; }

                foreach (string str in subDirs)
                {
                    folders.Enqueue(str);
                }
            }
        }
    }
}
