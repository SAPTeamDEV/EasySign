using System.Collections.Concurrent;
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

        static void Main(string[] args)
        {
            Bundle = new(args[1]);

            if (args[0] == "add") Add();
            else if (args[0] == "verify") Verify();
            else AnsiConsole.MarkupLine("[red]No valid command is supplied[/]");
        }

        static void Add()
        {
            AnsiConsole.Status()
                .AutoRefresh(true)
                .Spinner(Spinner.Known.Default)
                .Start("[yellow]Indexing Files[/]", ctx =>
                {
                    Parallel.ForEach(SafeEnumerateFiles(Bundle.RootPath, "*"), file =>
                    {
                        if (file == Bundle.BundlePath) return;
                        Bundle.AddEntry(file);
                        AnsiConsole.MarkupLine($"[blue]Added:[/] {Path.GetRelativePath(Bundle.RootPath, file)}");
                    });

                    ctx.Status("[yellow]Signing[/]");

                    X509Store store = new X509Store("MY", StoreLocation.CurrentUser);
                    store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                    X509Certificate2Collection collection = store.Certificates;
                    foreach (var cert in collection.Where(x => x.HasPrivateKey))
                    {
                        var prvKey = cert.GetRSAPrivateKey();
                        if (prvKey == null) continue;
                        Bundle.SignBundle(cert, prvKey);
                        AnsiConsole.MarkupLine($"[green]Signed by:[/] {cert.GetNameInfo(X509NameType.SimpleName, false)}");
                    }

                    ctx.Status("[yellow]Creating Bundle[/]");
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

                    if (verifiedCerts == 0)
                    {
                        if (Bundle.Signatures.Entries.Count == 0)
                        {
                            AnsiConsole.MarkupLine($"[red]This bundle is not signed[/]");
                        }

                        AnsiConsole.MarkupLine($"[red]Verification failed[/]");
                        return;
                    }

                    AnsiConsole.WriteLine();

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

                    AnsiConsole.MarkupLine("File Verification Summary");
                    AnsiConsole.MarkupLine($"[{colorDict["file_verified"]}] {fv} Files verified[/]");
                    AnsiConsole.MarkupLine($"[{colorDict["file_failed"]}] {ff} Files tampered with[/]");
                    AnsiConsole.MarkupLine($"[{colorDict["file_missing"]}] {fm} Files not found[/]");
                    AnsiConsole.MarkupLine($"[{colorDict["file_error"]}] {fe} Files encountered with errors[/]");

                    AnsiConsole.WriteLine();

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
