using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;

using Spectre.Console;

namespace SAPTeam.EasySign.CommandLine
{
    /// <summary>
    /// Provides utility methods for various operations.
    /// </summary>
    internal static class Utilities
    {
        /// <summary>
        /// Runs the specified action within a status context, provides fancy progress showing.
        /// </summary>
        /// <param name="initialStatus">The initial status being shown at the start of status context. Spectre.Console coloring is supported.</param>
        /// <param name="action">The action to run within the status context.</param>
        public static void RunInStatusContext(string initialStatus, Action<StatusContext> action)
        {
            AnsiConsole.Status()
                .AutoRefresh(true)
                .Spinner(Spinner.Known.Default)
                .Start(initialStatus, action);
        }

        /// <summary>
        /// Checks if a file is within a specified root path.
        /// </summary>
        /// <param name="filePath">
        /// The file path to check.
        /// </param>
        /// <param name="rootPath">
        /// The root path to check against.
        /// </param>
        /// <returns>
        /// True if the file is within the root path; otherwise, false.
        /// </returns>
        public static bool IsFileWithinRoot(string filePath, string rootPath)
        {
            // Get the full absolute paths
            string absoluteFilePath = Path.GetFullPath(filePath);
            string absoluteRootPath = Path.GetFullPath(rootPath);

            // Ensure the root path ends with a directory separator
            if (!absoluteRootPath.EndsWith(Path.DirectorySeparatorChar.ToString()))
            {
                absoluteRootPath += Path.DirectorySeparatorChar;
            }

            // Check if the file path starts with the root path (using OrdinalIgnoreCase for case-insensitive comparison on Windows)
            return absoluteFilePath.StartsWith(absoluteRootPath, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Safely enumerates files in the specified path that match the search pattern.
        /// </summary>
        /// <param name="path">The path to search for files.</param>
        /// <param name="searchPattern">The search pattern to match files.</param>
        /// <param name="recursive">Whether to search recursively in subdirectories.</param>
        /// <returns>An enumerable collection of file paths.</returns>
        public static IEnumerable<string> SafeEnumerateFiles(string path, string searchPattern, bool recursive = true)
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
                    if (recursive)
                    {
                        subDirs = Directory.GetDirectories(currentDir);
                    }
                }
                catch (UnauthorizedAccessException) { continue; }
                catch (DirectoryNotFoundException) { continue; }

                foreach (string dir in subDirs)
                {
                    folders.Enqueue(dir);
                }
            }
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
            foreach (X509ChainStatus status in statuses)
            {
                AnsiConsole.MarkupLine($"[{Color.IndianRed}]   {status.StatusInformation}[/]");
            }
        }
    }
}
