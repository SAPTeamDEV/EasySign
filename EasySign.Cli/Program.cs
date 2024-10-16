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
        /*
        static void Main(string[] args)
        {
            bool doAdd = args[0] == "add";

            string path = Path.GetFullPath(args[1]);

            var signInfra = new Bundle(path);

            Console.WriteLine(path);

            if (doAdd)
            {
                Parallel.ForEach(Directory.GetFiles(path, "*", SearchOption.AllDirectories), (file) =>
                {
                    signInfra.AddEntry(file);
                    Console.WriteLine($"Added: {file}");
                });

                X509Store store = new X509Store("MY", StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                X509Certificate2Collection collection = store.Certificates;
                foreach (var cert in collection.Where(x => x.HasPrivateKey))
                {
                    if (cert.GetRSAPrivateKey() == null) continue;
                    Console.WriteLine($"Signing with: {cert.GetNameInfo(X509NameType.SimpleName, false)}");
                    signInfra.SignBundle(cert);
                    Console.WriteLine($"Signed by: {cert.GetNameInfo(X509NameType.SimpleName, false)}");
                }

                signInfra.Update();
            }
            else
            {
                signInfra.Load();

                foreach (var cert in signInfra.Signatures.Entries.Keys)
                {
                    var certificate = signInfra.GetCertificate(cert);
                    Console.WriteLine(certificate.Subject);
                    Console.WriteLine($"Is Verified: {certificate.Verify()}");
                    Console.WriteLine($"Is Valid Sign: {signInfra.VerifySignature(cert)}");
                    Console.WriteLine();
                }

                Parallel.ForEach(signInfra.Manifest.Entries, (entry) =>
                {
                    Console.WriteLine($"{entry.Key}: {signInfra.VerifyFile(entry.Key)}");
                });

                Console.WriteLine($"Verified {signInfra.Manifest.Entries.Count()} files");
            }
        }
        */

        public static Bundle Bundle { get; set; }

        static void Main(string[] args)
        {
            Bundle = new(args[1]);

            if (args[0] == "add") Add();
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
                        Bundle.AddEntry(file);
                        AnsiConsole.MarkupLine($"[blue]Added:[/] {file}");
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
