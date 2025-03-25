using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using EnsureThat;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace SAPTeam.EasySign
{
    /// <summary>
    /// Represents a bundle that holds file hashes and signatures.
    /// </summary>
    public class Bundle
    {
        private readonly string _bundleName;
        private byte[] _rawZipContents = [];

        private readonly ConcurrentDictionary<string, byte[]> _cache = new();
        private readonly int _maxCacheSize;
        private int _currentCacheSize;

        private readonly ConcurrentDictionary<string, byte[]> _pendingForAdd = new();
        private readonly List<string> _pendingForRemove = new();

        /// <summary>
        /// Gets the JSON serializer options.
        /// </summary>
        protected readonly JsonSerializerOptions SerializerOptions = new JsonSerializerOptions()
        {
            WriteIndented = false,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault,
        };

        /// <summary>
        /// Gets the logger to use for logging.
        /// </summary>
        protected ILogger Logger { get; }

        /// <summary>
        /// Gets the list of sensitive names. Regex patterns are supported.
        /// </summary>
        /// <remarks>
        /// These names are not allowed for add or delete.
        /// The entries with these names are only resolved with <see cref="ReadSource.Bundle"/>.
        /// </remarks>
        protected List<string> ProtectedNames { get; } = new()
        {
            ".manifest.ec",
            ".signatures.ec",
        };

        /// <summary>
        /// Gets the default name of the bundle.
        /// </summary>
        /// <remarks>
        /// Only used when the bundle path does not specify a file name.
        /// </remarks>
        protected virtual string DefaultBundleName => ".eSign";

        /// <summary>
        /// Gets the root path of the bundle. This path used for relative path resolution.
        /// </summary>
        public string RootPath { get; }

        /// <summary>
        /// Gets the name of the bundle file.
        /// </summary>
        public string BundleName => LoadedFromMemory ? throw new InvalidOperationException("Bundle is loaded from memory") : _bundleName;

        /// <summary>
        /// Gets the full path of the bundle file.
        /// </summary>
        public string BundlePath => Path.Combine(RootPath, BundleName);

        /// <summary>
        /// Gets the manifest of the bundle. The manifest contains all files hashes and bundle configurations.
        /// </summary>
        public Manifest Manifest { get; private set; } = new();

        /// <summary>
        /// Gets the signatures of the bundle.
        /// </summary>
        public Signatures Signatures { get; private set; } = new();

        /// <summary>
        /// Gets a value indicating whether the bundle is read-only.
        /// </summary>
        public bool ReadOnly { get; private set; }

        /// <summary>
        /// Gets a value indicating whether the bundle is loaded from memory.
        /// </summary>
        public bool LoadedFromMemory => _rawZipContents != null && _rawZipContents.Length > 0;

        /// <summary>
        /// Gets a value indicating whether the bundle is loaded.
        /// </summary>
        public bool Loaded { get; private set; }

        /// <summary>
        /// Occurs when the bundle file is being updated.
        /// </summary>
        public event Action<ZipArchive>? OnUpdating;

        /// <summary>
        /// Initializes a new instance of the <see cref="Bundle"/> class.
        /// </summary>
        /// <param name="bundlePath">The path of the bundle.</param>
        /// <param name="logger">The logger to use for logging.</param>
        /// <param name="maxCacheSize">The maximum size of the cache in bytes.</param>
        public Bundle(string bundlePath, ILogger? logger = null, int maxCacheSize = 0x8000000)
        {
            Ensure.String.IsNotNullOrEmpty(bundlePath.Trim(), nameof(bundlePath));

            var fullPath = Path.GetFullPath(bundlePath);

            if (Directory.Exists(fullPath))
            {
                _bundleName = DefaultBundleName;
                RootPath = fullPath;
            }
            else
            {
                _bundleName = Path.GetFileName(fullPath);
                RootPath = Path.GetDirectoryName(fullPath) ?? throw new ArgumentException("Cannot resolve root path of the bundle: " + fullPath);
            }

            Logger = logger ?? NullLogger.Instance;

            _maxCacheSize = maxCacheSize;
        }

        /// <summary>
        /// Throws an exception if the bundle is read-only.
        /// </summary>
        protected void EnsureWritable()
        {
            if (ReadOnly)
            {
                throw new InvalidOperationException("Bundle is read-only"); ;
            }
        }

        /// <summary>
        /// Checks whether the entry name is protected and throws an exception if it is.
        /// </summary>
        /// <param name="entryName">The name of the entry to check.</param>
        /// <param name="throwException">Whether to throw an exception if the entry name is protected.</param>
        /// <exception cref="UnauthorizedAccessException"></exception>
        /// <returns>True if the entry name is not protected; otherwise, false.</returns>
        protected bool CheckEntryNameSecurity(string entryName, bool throwException = true)
        {
            foreach (var pattern in ProtectedNames)
            {
                if (Regex.IsMatch(entryName, pattern))
                {
                    return throwException ? throw new UnauthorizedAccessException("Entry name is protected: " + entryName) : false;
                }
            }

            return true;
        }

        private void EvictIfNecessary(long incomingFileSize)
        {
            while (_currentCacheSize + incomingFileSize > _maxCacheSize && !_cache.IsEmpty)
            {
                var leastUsedKey = _cache.Keys.First();
                if (_cache.TryRemove(leastUsedKey, out var removed))
                {
                    _currentCacheSize -= removed.Length;
                }

                Logger.LogDebug("Evicted entry: {name} from the cache", leastUsedKey);
            }
        }

        /// <summary>
        /// Caches an entry in memory.
        /// </summary>
        /// <param name="entryName">The name of the entry to cache.</param>
        /// <param name="data">The data of the entry to cache.</param>
        /// <returns><see langword="true"/> if the entry was cached; otherwise, <see langword="false"/>.</returns>
        protected bool CacheEntry(string entryName, byte[] data)
        {
            Ensure.String.IsNotNullOrEmpty(entryName.Trim(), nameof(entryName));
            Ensure.Collection.HasItems(data, nameof(data));

            if (!ReadOnly || _maxCacheSize < data.Length)
            {
                return false;
            }

            if (_cache.TryGetValue(entryName, out var existing))
            {
                if (existing.SequenceEqual(data))
                {
                    return false;
                }
            }

            EvictIfNecessary(data.Length);
                        
            _cache[entryName] = data;
            _currentCacheSize += data.Length;

            Logger.LogDebug("Cached entry: {name} with {size} bytes", entryName, data.Length);

            return true;
        }

        /// <summary>
        /// Gets a <see cref="ZipArchive"/> for the bundle.
        /// </summary>
        /// <param name="mode">The mode in which to open the archive.</param>
        /// <returns>A <see cref="ZipArchive"/> for the bundle.</returns>
        public ZipArchive OpenZipArchive(ZipArchiveMode mode = ZipArchiveMode.Read)
        {
            if (mode != ZipArchiveMode.Read) EnsureWritable();

            Logger.LogDebug("Opening bundle archive in {Mode} mode", mode);

            if (LoadedFromMemory)
            {
                Logger.LogDebug("Loading bundle from memory with {Size} bytes", _rawZipContents.Length);

                var ms = new MemoryStream(_rawZipContents);
                return new ZipArchive(ms, mode);
            }
            else
            {
                Logger.LogDebug("Loading bundle from file: {file}", BundlePath);

                return ZipFile.Open(BundlePath, mode);
            }
        }

        /// <summary>
        /// Loads the bundle from the file system.
        /// </summary>
        /// <param name="readOnly">Whether to load the bundle in read-only mode.</param>
        public void LoadFromFile(bool readOnly = true)
        {
            if (Loaded)
            {
                throw new InvalidOperationException("The bundle is already loaded");
            }

            ReadOnly = readOnly;
            using var zip = OpenZipArchive();
            Parse(zip);

            Loaded = true;

            Logger.LogInformation("Bundle loaded from file: {file}", BundlePath);
        }

        /// <summary>
        /// Loads the bundle from a byte array. This method is more secure than loading from the file as it stores the bundle in memory.
        /// </summary>
        /// <param name="bundleContent">The byte array containing the bundle content.</param>
        public void LoadFromBytes(byte[] bundleContent)
        {
            if (Loaded)
            {
                throw new InvalidOperationException("The bundle is already loaded");
            }

            Ensure.Collection.HasItems(bundleContent, nameof(bundleContent));

            ReadOnly = true;
            _rawZipContents = bundleContent;

            using var zip = OpenZipArchive();
            Parse(zip);

            Loaded = true;

            Logger.LogInformation("Bundle loaded from memory with {Size} bytes", bundleContent.Length);
        }

        /// <summary>
        /// Parses the bundle contents from a <see cref="ZipArchive"/>.
        /// </summary>
        /// <param name="zip">The <see cref="ZipArchive"/> to read from.</param>
        protected virtual void Parse(ZipArchive zip)
        {
            Logger.LogInformation("Parsing bundle contents");

            ZipArchiveEntry? entry;
            if ((entry = zip.GetEntry(".manifest.ec")) != null)
            {
                Logger.LogDebug("Parsing manifest");
                Manifest = JsonSerializer.Deserialize(entry.Open(), typeof(Manifest), SourceGenerationManifestContext.Default) as Manifest ?? new Manifest();
            }
            else
            {
                Logger.LogWarning("Manifest not found in the bundle");
            }

            if ((entry = zip.GetEntry(".signatures.ec")) != null)
            {
                Logger.LogDebug("Parsing signatures");
                Signatures = JsonSerializer.Deserialize(entry.Open(), typeof(Signatures), SourceGenerationSignaturesContext.Default) as Signatures ?? new Signatures();
            }
            else
            {
                Logger.LogWarning("Signatures not found in the bundle");
            }
        }

        /// <summary>
        /// Adds a file entry to the bundle.
        /// if the <see cref="Manifest.StoreOriginalFiles"/> is <see langword="true"/>, the file will be embedded in the bundle and it's hash added to manifest.
        /// Otherwise just the file hash added to the bundle.
        /// </summary>
        /// <param name="path">The path of the file to add.</param>
        /// <param name="destinationPath">The destination path within the bundle. Ignore when <see cref="Manifest.StoreOriginalFiles"/> is <see langword="false"/></param>
        /// <param name="rootPath">The root path for relative paths.</param>
        public void AddEntry(string path, string destinationPath = "./", string? rootPath = null)
        {
            EnsureWritable();

            Ensure.String.IsNotNullOrEmpty(path.Trim(), nameof(path));

            if (!File.Exists(path))
            {
                throw new FileNotFoundException("File not found", path);
            }

            Logger.LogInformation("Adding file: {path}", path);

            if (!destinationPath.EndsWith('/'))
                destinationPath += "/";

            if (string.IsNullOrEmpty(rootPath))
                rootPath = RootPath;

            using var file = File.OpenRead(path);
            string name = Manifest.GetNormalizedEntryName(Path.GetRelativePath(rootPath, path));

            CheckEntryNameSecurity(name);

            var hash = ComputeSHA512Hash(file);

            if (Manifest.StoreOriginalFiles && !string.IsNullOrEmpty(destinationPath) && destinationPath != "./")
            {
                name = destinationPath + name;
            }

            Logger.LogDebug("Adding entry: {name} with hash {hash} to manifest", name, BitConverter.ToString(hash).Replace("-", string.Empty));
            Manifest.AddEntry(name, hash);

            if (Manifest.StoreOriginalFiles)
            {
                Logger.LogDebug("Pending file: {name} for embedding in the bundle", name);
                _pendingForAdd[name] = File.ReadAllBytes(path);
            }
        }

        /// <summary>
        /// Deletes an entry from the bundle.
        /// </summary>
        /// <param name="entryName">The name of the entry to delete.</param>
        public void DeleteEntry(string entryName)
        {
            EnsureWritable();

            Ensure.String.IsNotNullOrEmpty(entryName.Trim(), nameof(entryName));

            Logger.LogInformation("Deleting entry: {name}", entryName);

            CheckEntryNameSecurity(entryName);

            Logger.LogDebug("Deleting entry: {name} from manifest", entryName);
            Manifest.DeleteEntry(entryName);

            if (Manifest.StoreOriginalFiles)
            {
                Logger.LogDebug("Pending entry: {name} for deletion from the bundle", entryName);
                _pendingForRemove.Add(entryName);

                if (_pendingForAdd.ContainsKey(entryName))
                {
                    Logger.LogDebug("Removing pending entry: {name} from the bundle", entryName);
                    _pendingForAdd.Remove(entryName, out _);
                }
            }
        }

        /// <summary>
        /// Signs the bundle with the specified certificate and private key.
        /// </summary>
        /// <param name="certificate">The certificate to use for signing.</param>
        /// <param name="privateKey">The private key to use for signing.</param>
        public void Sign(X509Certificate2 certificate, RSA privateKey)
        {
            EnsureWritable();

            Ensure.Any.IsNotNull(certificate, nameof(certificate));
            Ensure.Any.IsNotNull(privateKey, nameof(privateKey));

            Logger.LogInformation("Signing bundle with certificate: {name}", certificate.Subject);

            Logger.LogDebug("Exporting certificate");
            var cert = Convert.ToBase64String(certificate.Export(X509ContentType.Cert));
            var name = certificate.GetCertHashString();

            StringBuilder pemBuilder = new StringBuilder();
            pemBuilder.AppendLine("-----BEGIN CERTIFICATE-----");
            pemBuilder.AppendLine(cert);
            pemBuilder.AppendLine("-----END CERTIFICATE-----");
            string pemContents = pemBuilder.ToString();

            Logger.LogDebug("Signing manifest");
            var manifestData = Export(Manifest, SourceGenerationManifestContext.Default);
            var signature = privateKey.SignData(manifestData, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);

            Logger.LogDebug("Pending file: {name} for embedding in the bundle", name);
            _pendingForAdd[name] = Encoding.UTF8.GetBytes(pemContents);

            Logger.LogDebug("Adding signature for certificate: {name} to signatures", name);
            Signatures.Entries[name] = signature;
        }

        /// <summary>
        /// Verifies the integrity of a file in the bundle.
        /// </summary>
        /// <param name="entryName">The name of the entry to verify.</param>
        /// <returns>True if the file is valid; otherwise, false.</returns>
        public bool VerifyFileIntegrity(string entryName)
        {
            Ensure.String.IsNotNullOrEmpty(entryName.Trim(), nameof(entryName));

            Logger.LogInformation("Verifying file integrity: {name}", entryName);

            byte[] hash = ComputeSHA512Hash(GetStream(entryName));
            bool result = Manifest.GetConcurrentDictionary()[entryName].SequenceEqual(hash);

            Logger.LogInformation("File integrity verification result for {name}: {result}", entryName, result);

            return result;
        }

        /// <summary>
        /// Verifies the signature of the bundle using the specified certificate hash.
        /// </summary>
        /// <param name="certificateHash">The hash of the certificate to use for verification.</param>
        /// <returns>True if the signature is valid; otherwise, false.</returns>
        public bool VerifySignature(string certificateHash)
        {
            Ensure.String.IsNotNullOrEmpty(certificateHash.Trim(), nameof(certificateHash));
            byte[] hash = Signatures.Entries[certificateHash];

            X509Certificate2 certificate = GetCertificate(certificateHash);
            var pubKey = certificate.GetRSAPublicKey() ?? throw new CryptographicException("Public key not found");

            Logger.LogInformation("Verifying signature with certificate: {name}", certificate.Subject);

            var manifestHash = GetBytes(".manifest.ec", ReadSource.Bundle);
            bool result = pubKey.VerifyHash(manifestHash, hash, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);

            Logger.LogInformation("Signature verification result for certificate {name}: {result}", certificate.Subject, result);

            return result;
        }

        /// <summary>
        /// Verifies the validity of a certificate using the specified certificate hash.
        /// </summary>
        /// <param name="certificateHash">The hash of the certificate to verify.</param>
        /// <param name="statuses">The chain statuses of the certificate.</param>
        /// <param name="policy">The chain policy to use for verification.</param>
        /// <returns>True if the certificate is valid; otherwise, false.</returns>
        public bool VerifyCertificate(string certificateHash, out X509ChainStatus[] statuses, X509ChainPolicy? policy = null)
        {
            Ensure.String.IsNotNullOrEmpty(certificateHash.Trim(), nameof(certificateHash));

            X509Certificate2 certificate = GetCertificate(certificateHash);
            return VerifyCertificate(certificate, out statuses, policy);
        }

        /// <summary>
        /// Verifies the validity of a certificate using the specified certificate hash.
        /// </summary>
        /// <param name="certificateHash">The hash of the certificate to verify.</param>
        /// <param name="policy">The chain policy to use for verification.</param>
        /// <returns>True if the certificate is valid; otherwise, false.</returns>
        public bool VerifyCertificate(string certificateHash, X509ChainPolicy? policy = null)
        {
            return VerifyCertificate(certificateHash, out _, policy);
        }

        /// <summary>
        /// Verifies the validity of a certificate.
        /// </summary>
        /// <param name="certificate">The certificate to verify.</param>
        /// <param name="statuses">The chain statuses of the certificate.</param>
        /// <param name="policy">The chain policy to use for verification.</param>
        /// <returns>True if the certificate is valid; otherwise, false.</returns>
        public bool VerifyCertificate(X509Certificate2 certificate, out X509ChainStatus[] statuses, X509ChainPolicy? policy = null)
        {
            Ensure.Any.IsNotNull(certificate, nameof(certificate));

            X509Chain chain = new X509Chain
            {
                ChainPolicy = policy ?? new X509ChainPolicy()
            };

            Logger.LogInformation("Verifying certificate: {name}", certificate.Subject);

            if (policy != null)
            {
                Logger.LogDebug("Using custom chain policy for verification");
            }

            bool isValid = chain.Build(certificate);
            statuses = chain.ChainStatus;

            Logger.LogInformation("Certificate verification result for {name}: {result}", certificate.Subject, isValid);

            return isValid;
        }

        /// <summary>
        /// Verifies the validity of a certificate.
        /// </summary>
        /// <param name="certificate">The certificate to verify.</param>
        /// <param name="policy">The chain policy to use for verification.</param>
        /// <returns>True if the certificate is valid; otherwise, false.</returns>
        public bool VerifyCertificate(X509Certificate2 certificate, X509ChainPolicy? policy = null)
        {
            return VerifyCertificate(certificate, out _, policy);
        }

        /// <summary>
        /// Gets a certificate from the bundle using the specified certificate hash. and caches the certificate if the bundle is Read-only.
        /// </summary>
        /// <param name="certificateHash">The hash of the certificate to get.</param>
        /// <returns>The certificate.</returns>
        public X509Certificate2 GetCertificate(string certificateHash)
        {
            Ensure.String.IsNotNullOrEmpty(certificateHash.Trim(), nameof(certificateHash));

            Logger.LogInformation("Getting certificate with hash: {hash}", certificateHash);

            var certData = GetBytes(certificateHash, ReadSource.Bundle);

#if NET9_0_OR_GREATER
            var certificate = X509CertificateLoader.LoadCertificate(certData);
#else
            var certificate = new X509Certificate2(certData);
#endif

            return certificate;
        }

        /// <summary>
        /// Gets a stream for an entry in the bundle and caches the entry data if the bundle is Read-only.
        /// </summary>
        /// <param name="entryName">The name of the entry to get the stream for.</param>
        /// <param name="readSource">The source from which to read the data.</param>
        /// <returns>A stream for the entry.</returns>
        public Stream GetStream(string entryName, ReadSource readSource = ReadSource.Both)
        {
            Ensure.String.IsNotNullOrEmpty(entryName.Trim(), nameof(entryName));

            Logger.LogInformation("Getting file stream for entry: {name}", entryName);

            if (_cache.TryGetValue(entryName, out var data))
            {
                Logger.LogDebug("Reading entry {name} from cache", entryName);
                return new MemoryStream(data);
            }
            else
            {
                Logger.LogDebug("Entry {name} not found in cache", entryName);
            }

            Stream stream;

            if (!CheckEntryNameSecurity(entryName, false))
            {
                readSource = ReadSource.Bundle;
            }

            if (readSource != ReadSource.Disk && (readSource == ReadSource.Bundle || Manifest.StoreOriginalFiles))
            {
                Logger.LogDebug("Reading file: {name} from the bundle", entryName);

                using var zip = OpenZipArchive();

                var entry = zip.GetEntry(entryName) ?? throw new FileNotFoundException("Entry not found", entryName);
                stream = entry.Open();
            }
            else
            {
                Logger.LogDebug("Reading file: {name} from the file system", entryName);

                string path = Path.GetFullPath(entryName, RootPath);
                stream =  File.OpenRead(path);
            }

            if (ReadOnly && stream.Length < _maxCacheSize)
            {
                _ = CacheEntry(entryName, ReadStream(stream));
            }

            return stream;
        }

        /// <summary>
        /// Gets the data of an entry in the bundle as bytes array and caches the entry data if the bundle is Read-only.
        /// </summary>
        /// <param name="entryName">The name of the entry to get the bytes for.</param>
        /// <param name="readSource">The source from which to read the data.</param>
        /// <returns>The entry data as bytes array.</returns>
        public byte[] GetBytes(string entryName, ReadSource readSource)
        {
            Ensure.String.IsNotNullOrEmpty(entryName.Trim(), nameof(entryName));

            Logger.LogInformation("Getting file data for entry: {name}", entryName);

            if (!_cache.TryGetValue(entryName, out var data))
            {
                data = ReadStream(GetStream(entryName, readSource));

                _ = CacheEntry(entryName, data);
            }

            return data;
        }
                
        /// <summary>
        /// Writes changes to the bundle file.
        /// </summary>
        public void Update()
        {
            EnsureWritable();

            Logger.LogInformation("Updating bundle file: {file}", BundlePath);

            using (ZipArchive zip = OpenZipArchive(ZipArchiveMode.Update))
            {
                Logger.LogDebug("Deleting pending files from the bundle");

                ZipArchiveEntry? tempEntry;
                foreach (var entryName in _pendingForRemove)
                {
                    if ((tempEntry = zip.GetEntry(entryName)) != null)
                    {
                        Logger.LogDebug("Deleting entry: {name}", entryName);
                        tempEntry.Delete();
                    }
                    else
                    {
                        Logger.LogWarning("Entry {name} not found in the bundle", entryName);
                    }
                }

                Logger.LogDebug("Raising OnUpdating event");
                OnUpdating?.Invoke(zip);

                Logger.LogDebug("Writing manifest to the bundle");
                var manifestData = Export(Manifest, SourceGenerationManifestContext.Default);
                WriteEntry(zip, ".manifest.ec", manifestData);

                Logger.LogDebug("Writing signatures to the bundle");
                var signatureData = Export(Signatures, SourceGenerationSignaturesContext.Default);
                WriteEntry(zip, ".signatures.ec", signatureData);

                Logger.LogDebug("Writing pending files to the bundle");
                foreach (var newFile in _pendingForAdd)
                {
                    WriteEntry(zip, newFile.Key, newFile.Value);
                }
            }
        }

        /// <summary>
        /// Exports the specified structured data to a byte array.
        /// </summary>
        /// <param name="structuredData">The structured data to export.</param>
        /// <param name="jsonSerializerContext">A metadata provider for serializable types.</param>
        /// <returns>A byte array containing the exported data.</returns>
        protected byte[] Export(object structuredData, JsonSerializerContext jsonSerializerContext)
        {
            Ensure.Any.IsNotNull(structuredData, nameof(structuredData));
            Ensure.Any.IsNotNull(jsonSerializerContext, nameof(jsonSerializerContext));

            Logger.LogInformation("Exporting data from a {type} object as byte array", structuredData.GetType().Name);

            var data = JsonSerializer.Serialize(structuredData, structuredData.GetType(), jsonSerializerContext);
            return Encoding.UTF8.GetBytes(data);
        }

        /// <summary>
        /// Exports the specified structured data to a byte array.
        /// </summary>
        /// <param name="structuredData">The structured data to export.</param>
        /// <returns>A byte array containing the exported data.</returns>
#if NET6_0_OR_GREATER
        [RequiresUnreferencedCode("This method is not compatible with AOT.")]
#endif
#if NET8_0_OR_GREATER
        [RequiresDynamicCode("This method is not compatible with AOT.")]
#endif
        protected byte[] Export(object structuredData)
        {
            Ensure.Any.IsNotNull(structuredData, nameof(structuredData));

            Logger.LogInformation("Exporting data from a {type} object as byte array", structuredData.GetType().Name);

            var data = JsonSerializer.Serialize(structuredData, SerializerOptions);
            return Encoding.UTF8.GetBytes(data);
        }

        /// <summary>
        /// Writes an entry to a <see cref="ZipArchive"/>.
        /// if the entry is already exists, it will be deleted.
        /// </summary>
        /// <param name="zip">The <see cref="ZipArchive"/> to write to.</param>
        /// <param name="entryName">The name of the entry to write.</param>
        /// <param name="data">The data to write.</param>
        protected void WriteEntry(ZipArchive zip, string entryName, byte[] data)
        {
            Ensure.Any.IsNotNull(zip, nameof(zip));
            Ensure.String.IsNotNullOrEmpty(entryName.Trim(), nameof(entryName));
            Ensure.Collection.HasItems(data, nameof(data));

            Logger.LogDebug("Writing entry: {name} to the bundle", entryName);

            ZipArchiveEntry? tempEntry;
            if ((tempEntry = zip.GetEntry(entryName)) != null)
            {
                Logger.LogDebug("Deleting existing entry: {name}", entryName);
                tempEntry.Delete();
            }

#if NET6_0_OR_GREATER
            var compressionLevel = CompressionLevel.SmallestSize;
#else
            var compressionLevel = CompressionLevel.Optimal;
#endif

            Logger.LogDebug("Creating new entry: {name} in the bundle with compression level {level}", entryName, compressionLevel);
            ZipArchiveEntry entry = zip.CreateEntry(entryName, compressionLevel);

            using var stream = entry.Open();
            stream.Write(data, 0, data.Length);
            stream.Flush();

            Logger.LogInformation("Wrote entry: {name} with {size} bytes to the bundle", entryName, data.Length);
        }

        /// <summary>
        /// Reads a stream into a byte array.
        /// </summary>
        /// <param name="stream">The stream to read.</param>
        /// <returns>A byte array containing the stream data.</returns>
        private static byte[] ReadStream(Stream stream)
        {
            Ensure.Any.IsNotNull(stream, nameof(stream));

            if (stream.Length > int.MaxValue)
            {
                throw new OverflowException("Stream length is too big for buffering");
            }

            MemoryStream ms = new();
            stream.CopyTo(ms);
            return ms.ToArray();
        }

        /// <summary>
        /// Computes the SHA-512 hash of a stream.
        /// </summary>
        /// <param name="stream">The stream to hash.</param>
        /// <returns>A byte array containing the hash.</returns>
        static byte[] ComputeSHA512Hash(Stream stream)
        {
            Ensure.Any.IsNotNull(stream, nameof(stream));

            using var sha512 = SHA512.Create();
            return sha512.ComputeHash(stream);
        }

        /// <summary>
        /// Computes the SHA-512 hash of a byte array.
        /// </summary>
        /// <param name="data">The data to hash.</param>
        /// <returns>A byte array containing the hash.</returns>
        static byte[] ComputeSHA512Hash(byte[] data)
        {
            Ensure.Collection.HasItems(data, nameof(data));

            using var sha512 = SHA512.Create();
            return sha512.ComputeHash(data);
        }
    }
}
