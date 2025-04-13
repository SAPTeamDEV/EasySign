using System.Collections.Concurrent;
using System.Data;
using System.Text.Json.Serialization;

namespace SAPTeam.EasySign
{
    /// <summary>
    /// Represents a manifest that holds entries of file names and their corresponding hashes.
    /// </summary>
    public class Manifest
    {
        private ConcurrentDictionary<string, byte[]> entries = new ConcurrentDictionary<string, byte[]>();

        /// <summary>
        /// Gets or sets the full name of the class that updated the manifest.
        /// </summary>
        public string? UpdatedBy { get; set; }

        /// <summary>
        /// Gets or sets the entries in the manifest as a sorted dictionary.
        /// </summary>
        /// <remarks>
        /// Note that this property is only for serialization purposes. Use <see cref="GetEntries"/> to get the entries as a concurrent dictionary.
        /// you can use this property to get a copy of the entries as a sorted dictionary but any changes made to it will be ignored.
        /// </remarks>
        public SortedDictionary<string, byte[]> Entries
        {
            get => new(entries); set => entries = new(value);
        }

        /// <summary>
        /// Gets or sets a value indicating whether the files should be stored in the bundle.
        /// </summary>
        public bool StoreOriginalFiles { get; set; }

        /// <summary>
        /// Gets or sets the list of entry names that should be protected by the bundle from accidental modifications.
        /// </summary>
        public HashSet<string> ProtectedEntryNames { get; set; } = [];

        /// <summary>
        /// Gets the entries as a thread-safe concurrent dictionary.
        /// </summary>
        /// <returns>A concurrent dictionary containing the entries.</returns>
        public ConcurrentDictionary<string, byte[]> GetEntries() => entries;

        /// <summary>
        /// Adds an entry to the manifest.
        /// An exception will be thrown if the entry already exists.
        /// </summary>
        /// <param name="entryName">
        /// The name of the entry to add.
        /// </param>
        /// <param name="hash">
        /// The hash of the entry to add.
        /// </param>
        /// <exception cref="DuplicateNameException"></exception>
        public void AddEntry(string entryName, byte[] hash)
        {
            if (!entries.TryAdd(entryName, hash))
            {
                throw new DuplicateNameException($"The entry '{entryName}' is already in the manifest.");
            }
        }

        /// <summary>
        /// Deletes an entry from the manifest.
        /// An exception will be thrown if the entry does not exist.
        /// </summary>
        /// <param name="entryName">The name of the entry to delete. </param>
        /// <exception cref="KeyNotFoundException"></exception>
        public void DeleteEntry(string entryName)
        {
            if (!entries.Remove(entryName, out _))
            {
                throw new KeyNotFoundException(entryName);
            }
        }

        /// <summary>
        /// Converts the path to an standard zip entry name
        /// </summary>
        /// <param name="path">
        /// The path to convert.
        /// </param>
        /// <returns>
        /// The normalized entry name.
        /// </returns>
        public static string GetNormalizedEntryName(string path) => new UnifiedPath.OSPath(path).Unix;
    }

    [JsonSourceGenerationOptions(GenerationMode = JsonSourceGenerationMode.Metadata, WriteIndented = false, DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingDefault)]
    [JsonSerializable(typeof(Manifest))]
    internal partial class SourceGenerationManifestContext : JsonSerializerContext
    {

    }
}
