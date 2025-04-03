using System.Text.Json.Serialization;

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
        public Dictionary<string, byte[]> Entries { get; set; } = [];
    }

    [JsonSourceGenerationOptions(GenerationMode = JsonSourceGenerationMode.Metadata, WriteIndented = false, DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingDefault)]
    [JsonSerializable(typeof(Signatures))]
    internal partial class SourceGenerationSignaturesContext : JsonSerializerContext
    {

    }
}
