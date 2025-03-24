using System;
using System.Linq;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Spectre.Console;

namespace SAPTeam.EasySign.CommandLine
{
    /// <summary>
    /// Provides utility methods for various operations.
    /// </summary>
    public static class Utilities
    {
        /// <summary>
        /// Runs the specified action within a status context, provides fancy progress showing.
        /// </summary>
        /// <param name="action">The action to run within the status context.</param>
        public static void RunInStatusContext(Action<StatusContext> action)
        {
            AnsiConsole.Status()
                .AutoRefresh(true)
                .Spinner(Spinner.Known.Default)
                .Start("", action);
        }

        /// <summary>
        /// Safely enumerates files in the specified path that match the search pattern.
        /// </summary>
        /// <param name="path">The path to search for files.</param>
        /// <param name="searchPattern">The search pattern to match files.</param>
        /// <returns>An enumerable collection of file paths.</returns>
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

        /// <summary>
        /// Retrieves a collection of certificates from a PFX file or the current user's certificate store.
        /// </summary>
        /// <param name="pfxFilePath">The path to the PFX file.</param>
        /// <param name="pfxFilePassword">The password for the PFX file.</param>
        /// <param name="pfxNoPasswordPrompt">Indicates whether to prompt for a password if not provided.</param>
        /// <returns>A collection of certificates.</returns>
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

        /// <summary>
        /// Prompts the user for input securely, hiding the input as it is typed.
        /// </summary>
        /// <param name="prompt">The prompt message to display.</param>
        /// <returns>The user input.</returns>
        public static string SecurePrompt(string prompt)
        {
            return AnsiConsole.Prompt(
                new TextPrompt<string>(prompt)
                    .PromptStyle("red")
                    .AllowEmpty()
                    .Secret(null));
        }

        /// <summary>
        /// Enumerates and displays the statuses of an X509 certificate chain.
        /// </summary>
        /// <param name="statuses">The array of X509 chain statuses.</param>
        public static void EnumerateStatuses(X509ChainStatus[] statuses)
        {
            foreach (var status in statuses)
            {
                AnsiConsole.MarkupLine($"[{Color.IndianRed}]   {status.StatusInformation}[/]");
            }
        }
    }
}
