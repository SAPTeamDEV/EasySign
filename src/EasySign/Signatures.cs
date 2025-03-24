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
    /// Represents a collection of manifest signatures.
    /// </summary>
    public class Signatures
    {
        /// <summary>
        /// Gets or sets the signature entries.
        /// </summary>
        public Dictionary<string, byte[]> Entries { get; set; } = new();
    }

    [JsonSourceGenerationOptions(GenerationMode = JsonSourceGenerationMode.Metadata, WriteIndented = false, DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingDefault)]
    [JsonSerializable(typeof(Signatures))]
    internal partial class SourceGenerationSignaturesContext : JsonSerializerContext
    {

    }
}
