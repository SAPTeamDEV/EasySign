using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace SAPTeam.EasySign.CommandLine
{
    /// <summary>
    /// Represents the configuration for the easysign command line tool.
    /// </summary>
    public class Configuration
    {
        /// <summary>
        /// Gets or sets the list of issued certificates by the self signing root CA.
        /// </summary>
        public Dictionary<string, string> IssuedCertificates { get; set; } = [];
    }

    [JsonSourceGenerationOptions(GenerationMode = JsonSourceGenerationMode.Metadata, WriteIndented = true, DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingDefault)]
    [JsonSerializable(typeof(Configuration))]
    internal partial class SourceGenerationConfigurationContext : JsonSerializerContext
    {

    }
}
