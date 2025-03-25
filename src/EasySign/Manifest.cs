using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace SAPTeam.EasySign
{
    /// <summary>
    /// Represents a manifest that holds entries of file names and their corresponding hashes.
    /// </summary>
    public class Manifest
    {
        private ConcurrentDictionary<string, byte[]> entries = new ConcurrentDictionary<string, byte[]>();

        /// <summary>
        /// Gets or sets the entries in the manifest as a sorted dictionary.
        /// </summary>
        /// <remarks>
        /// Note this property is only for serialization purposes. Use <see cref="GetConcurrentDictionary"/> to get the entries as a concurrent dictionary.
        /// you can use this property to get a copy of the entries as a sorted dictionary but any changes made to it will be ignored.
        /// </remarks>
        public SortedDictionary<string, byte[]> Entries
        {
            get
            {
                return new(entries);
            }
            set
            {
                entries = new(value);
            }
        }

        /// <summary>
        /// Gets or sets a value indicating whether the files should be stored in the bundle.
        /// </summary>
        public bool StoreOriginalFiles { get; set; }

        /// <summary>
        /// Gets the entries as a thread-safe concurrent dictionary.
        /// </summary>
        /// <returns>A concurrent dictionary containing the entries.</returns>
        public ConcurrentDictionary<string, byte[]> GetConcurrentDictionary() => entries;

        /// <summary>
        /// Adds an entry to the manifest.
        /// if it already exists, an exception will be thrown.
        /// </summary>
        /// <param name="entryName">
        /// The name of the entry to add.
        /// </param>
        /// <param name="hash">
        /// The hash of the entry to add.
        /// </param>
        /// <exception cref="InvalidOperationException"></exception>
        public void AddEntry(string entryName, byte[] hash)
        {
            if (!entries.TryAdd(entryName, hash))
            {
                throw new InvalidOperationException($"The entry '{entryName}' is already in the manifest.");
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
        public static string GetNormalizedEntryName(string path)
        {
            return new UnifiedPath.OSPath(path).Unix;
        }
    }

    [JsonSourceGenerationOptions(GenerationMode = JsonSourceGenerationMode.Metadata, WriteIndented = false, DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingDefault)]
    [JsonSerializable(typeof(Manifest))]
    internal partial class SourceGenerationManifestContext : JsonSerializerContext
    {

    }
}
