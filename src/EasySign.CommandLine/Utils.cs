using System;
using System.Linq;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Spectre.Console;

namespace SAPTeam.EasySign.CommandLine
{
    public static class Utils
    {
        public static void RunInStatusContext(Action<StatusContext> action)
        {
            AnsiConsole.Status()
                .AutoRefresh(true)
                .Spinner(Spinner.Known.Default)
                .Start("", action);
        }

        public static IEnumerable<string> SafeEnumerateFiles(string path, string searchPattern)
        {
            ConcurrentQueue<string> folders = new();
            folders.Enqueue(path);

            while (!folders.IsEmpty)
            {
                if (!folders.TryDequeue(out string? currentDir)) continue;

                string[] subDirs = Array.Empty<string>();
                string[] files = Array.Empty<string>();

                try
                {
                    files = Directory.GetFiles(currentDir, searchPattern);
                }
                catch (UnauthorizedAccessException) { }
                catch (DirectoryNotFoundException) { }

                foreach (string file in files)
                {
                    yield return file;
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

        public static X509Certificate2Collection GetCertificates(string pfxFilePath, string pfxFilePassword, bool pfxNoPasswordPrompt)
        {
            X509Certificate2Collection collection = new();

            if (!string.IsNullOrEmpty(pfxFilePath))
            {
                string pfpass = !string.IsNullOrEmpty(pfxFilePassword) ? pfxFilePassword : !pfxNoPasswordPrompt ? SecurePrompt("Enter PFX File password (if needed): ") : "";

#if NET9_0_OR_GREATER
                var tempCollection = X509CertificateLoader.LoadPkcs12CollectionFromFile(pfxFilePath, pfpass, X509KeyStorageFlags.EphemeralKeySet);
#else
                var tempCollection = new X509Certificate2Collection();
                tempCollection.Import(pfxFilePath, pfpass, X509KeyStorageFlags.EphemeralKeySet);
#endif

                var cond = tempCollection.Where(x => x.HasPrivateKey);
                if (cond.Any())
                    collection.AddRange(cond.ToArray());
                else
                {
                    collection.AddRange(tempCollection);
                }
            }
            else
            {
                X509Store store = new X509Store("MY", StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                var mapping = new Dictionary<string, X509Certificate2>();
                foreach (var cert in store.Certificates)
                {
                    mapping[$"{cert.GetNameInfo(X509NameType.SimpleName, false)},{cert.GetNameInfo(X509NameType.SimpleName, true)},{cert.Thumbprint}"] = cert;
                }

                var selection = AnsiConsole.Prompt(
                    new MultiSelectionPrompt<string>()
                        .PageSize(10)
                        .Title("Select Signing Certificates")
                        .MoreChoicesText("[grey](Move up and down to see more certificates)[/]")
                        .InstructionsText("[grey](Press [blue]<space>[/] to toggle a certificate, [green]<enter>[/] to accept)[/]")
                        .AddChoices(mapping.Keys));

                collection.AddRange(selection.Select(x => mapping[x]).ToArray());
            }

            return collection;
        }

        public static string SecurePrompt(string prompt)
        {
            return AnsiConsole.Prompt(
                new TextPrompt<string>(prompt)
                    .PromptStyle("red")
                    .AllowEmpty()
                    .Secret(null));
        }

        public static void EnumerateStatuses(X509ChainStatus[] statuses)
        {
            foreach (var status in statuses)
            {
                AnsiConsole.MarkupLine($"[{Color.IndianRed}]   {status.StatusInformation}[/]");
            }
        }
    }
}
