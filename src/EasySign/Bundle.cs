using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace SAPTeam.EasySign
{
    /// <summary>
    /// Represents a bundle that holds file hashes and signatures.
    /// </summary>
    public class Bundle
    {
        private readonly string bundleName = ".eSign";
        private byte[] rawZipContents = null;

        /// <summary>
        /// Gets the root path of the bundle. This path used for relative path resolution.
        /// </summary>
        public string RootPath { get; }

        /// <summary>
        /// Gets the name of the bundle file.
        /// </summary>
        public string BundleName
        {
            get
            {
                if (IsLoadedFromMemory)
                {
                    throw new InvalidOperationException("Bundle is loaded from memory");
                }

                return bundleName;
            }
        }

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

        private readonly Dictionary<string, X509Certificate2> certCache = new();

        private readonly ConcurrentDictionary<string, byte[]> newEmbeddedFiles = new();

        private readonly ConcurrentDictionary<string, byte[]> fileCache = new();

        /// <summary>
        /// Gets the JSON serializer options.
        /// </summary>
        protected readonly JsonSerializerOptions SerializerOptions = new JsonSerializerOptions()
        {
            WriteIndented = false,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault,
        };

        /// <summary>
        /// Gets a value indicating whether the bundle is read-only.
        /// </summary>
        public bool IsReadOnly { get; private set; }

        /// <summary>
        /// Gets a value indicating whether the bundle is loaded from memory.
        /// </summary>
        public bool IsLoadedFromMemory => rawZipContents != null && rawZipContents.Length > 0;

        /// <summary>
        /// Gets a value indicating whether the bundle is loaded.
        /// </summary>
        public bool IsLoaded { get; private set; }

        /// <summary>
        /// Occurs when the bundle file is being updated.
        /// </summary>
        public event Action<ZipArchive> OnUpdating;

        /// <summary>
        /// Initializes a new instance of the <see cref="Bundle"/> class with the specified root path and bundle name.
        /// </summary>
        /// <param name="rootPath">The root path of the bundle.</param>
        /// <param name="bundleName">The name of the bundle.</param>
        public Bundle(string rootPath, string bundleName) : this(rootPath)
        {
            this.bundleName = bundleName;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="Bundle"/> class with the specified root path and default bundle name.
        /// </summary>
        /// <param name="rootPath">The root path of the bundle.</param>
        public Bundle(string rootPath)
        {
            RootPath = Path.GetFullPath(rootPath);
        }

        /// <summary>
        /// Throws an exception if the bundle is read-only.
        /// </summary>
        private void EnsureWritable()
        {
            if (IsReadOnly)
                throw new InvalidOperationException("Bundle is read-only");
        }

        /// <summary>
        /// Gets a <see cref="ZipArchive"/> for the bundle.
        /// </summary>
        /// <param name="mode">The mode in which to open the archive.</param>
        /// <returns>A <see cref="ZipArchive"/> for the bundle.</returns>
        public ZipArchive OpenZipArchive(ZipArchiveMode mode = ZipArchiveMode.Read)
        {
            if (mode != ZipArchiveMode.Read)
                EnsureWritable();

            if (IsLoadedFromMemory)
            {
                var ms = new MemoryStream(rawZipContents);
                return new ZipArchive(ms, mode);
            }
            else
            {
                return ZipFile.Open(BundlePath, mode);
            }
        }

        /// <summary>
        /// Loads the bundle from the file system.
        /// </summary>
        /// <param name="readOnly">Whether to load the bundle in read-only mode.</param>
        public void LoadFromFile(bool readOnly = true)
        {
            if (IsLoaded)
            {
                throw new InvalidOperationException("The bundle is already loaded");
            }

            IsReadOnly = readOnly;
            using var zip = OpenZipArchive();
            ReadBundle(zip);

            IsLoaded = true;
        }

        /// <summary>
        /// Loads the bundle from a byte array. This method is more secure than loading from the file as it stores the bundle in memory.
        /// </summary>
        /// <param name="bundleContent">The byte array containing the bundle content.</param>
        public void LoadFromBytes(byte[] bundleContent)
        {
            if (IsLoaded)
            {
                throw new InvalidOperationException("The bundle is already loaded");
            }

            IsReadOnly = true;
            rawZipContents = bundleContent;

            using var zip = OpenZipArchive();
            ReadBundle(zip);

            IsLoaded = true;
        }

        /// <summary>
        /// Reads the bundle from a <see cref="ZipArchive"/>.
        /// </summary>
        /// <param name="zip">The <see cref="ZipArchive"/> to read from.</param>
        protected virtual void ReadBundle(ZipArchive zip)
        {
            ZipArchiveEntry entry;
            if ((entry = zip.GetEntry(".manifest.ec")) != null)
                Manifest = JsonSerializer.Deserialize<Manifest>(entry.Open(), SerializerOptions);

            if ((entry = zip.GetEntry(".signatures.ec")) != null)
                Signatures = JsonSerializer.Deserialize<Signatures>(entry.Open(), SerializerOptions);
        }

        /// <summary>
        /// Adds a file entry to the bundle.
        /// if the <see cref="Manifest.StoreOriginalFiles"/> is <see langword="true"/>, the file will be embedded in the bundle and it's hash added to manifest.
        /// Otherwise just the file hash added to the bundle.
        /// </summary>
        /// <param name="path">The path of the file to add.</param>
        /// <param name="destinationPath">The destination path within the bundle. Ignore when <see cref="Manifest.StoreOriginalFiles"/> is <see langword="false"/></param>
        /// <param name="rootPath">The root path for relative paths.</param>
        public void AddEntry(string path, string destinationPath = "./", string rootPath = null)
        {
            EnsureWritable();

            if (!destinationPath.EndsWith('/'))
                destinationPath += "/";

            if (string.IsNullOrEmpty(rootPath))
                rootPath = RootPath;

            using var file = File.OpenRead(path);
            string name = new UnifiedPath.OSPath(Path.GetRelativePath(rootPath, path)).Unix;
            var hash = ComputeSHA512Hash(file);

            if (Manifest.StoreOriginalFiles && !string.IsNullOrEmpty(destinationPath) && destinationPath != "./")
            {
                name = destinationPath + name;
            }

            Manifest.AddEntry(name, hash);

            if (Manifest.StoreOriginalFiles)
            {
                newEmbeddedFiles[name] = File.ReadAllBytes(path);
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

            var signature = privateKey.SignData(Export(Manifest), HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
            var cert = Convert.ToBase64String(certificate.Export(X509ContentType.Cert));
            var name = certificate.GetCertHashString();

            StringBuilder pemBuilder = new StringBuilder();
            pemBuilder.AppendLine("-----BEGIN CERTIFICATE-----");
            pemBuilder.AppendLine(cert);
            pemBuilder.AppendLine("-----END CERTIFICATE-----");
            string pemContents = pemBuilder.ToString();

            newEmbeddedFiles[name] = Encoding.UTF8.GetBytes(pemContents);
            Signatures.Entries[name] = signature;
        }

        /// <summary>
        /// Verifies the integrity of a file in the bundle.
        /// </summary>
        /// <param name="entryName">The name of the entry to verify.</param>
        /// <returns>True if the file is valid; otherwise, false.</returns>
        public bool VerifyFileIntegrity(string entryName)
        {
            byte[] hash;

            if (Manifest.StoreOriginalFiles)
            {
                using var zip = OpenZipArchive();
                hash = ComputeSHA512Hash(ReadEntry(zip, entryName));
            }
            else
            {
                string path = Path.GetFullPath(entryName, RootPath);
                using var file = File.OpenRead(path);
                hash = ComputeSHA512Hash(file);
            }

            return Manifest.GetConcurrentDictionary()[entryName].SequenceEqual(hash);
        }

        /// <summary>
        /// Verifies the signature of the bundle using the specified certificate hash.
        /// </summary>
        /// <param name="certificateHash">The hash of the certificate to use for verification.</param>
        /// <returns>True if the signature is valid; otherwise, false.</returns>
        public bool VerifySignature(string certificateHash)
        {
            X509Certificate2 certificate = GetCertificate(certificateHash);
            var pubKey = certificate.GetRSAPublicKey();

            return pubKey.VerifyData(Export(Manifest), Signatures.Entries[certificateHash], HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
        }

        /// <summary>
        /// Verifies the validity of a certificate using the specified certificate hash.
        /// </summary>
        /// <param name="certificateHash">The hash of the certificate to verify.</param>
        /// <param name="statuses">The chain statuses of the certificate.</param>
        /// <param name="policy">The chain policy to use for verification.</param>
        /// <returns>True if the certificate is valid; otherwise, false.</returns>
        public bool VerifyCertificate(string certificateHash, out X509ChainStatus[] statuses, X509ChainPolicy policy = null)
        {
            X509Certificate2 certificate = GetCertificate(certificateHash);
            return VerifyCertificate(certificate, out statuses, policy);
        }

        /// <summary>
        /// Verifies the validity of a certificate.
        /// </summary>
        /// <param name="certificate">The certificate to verify.</param>
        /// <param name="statuses">The chain statuses of the certificate.</param>
        /// <param name="policy">The chain policy to use for verification.</param>
        /// <returns>True if the certificate is valid; otherwise, false.</returns>
        public bool VerifyCertificate(X509Certificate2 certificate, out X509ChainStatus[] statuses, X509ChainPolicy policy = null)
        {
            X509Chain chain = new X509Chain
            {
                ChainPolicy = policy ?? new X509ChainPolicy()
            };

            bool isValid = chain.Build(certificate);
            statuses = chain.ChainStatus;
            return isValid;
        }

        /// <summary>
        /// Gets a certificate from the bundle using the specified certificate hash.
        /// </summary>
        /// <param name="certificateHash">The hash of the certificate to get.</param>
        /// <returns>The certificate.</returns>
        public X509Certificate2 GetCertificate(string certificateHash)
        {
            if (!certCache.TryGetValue(certificateHash, out X509Certificate2 certificate))
            {
                using var zip = OpenZipArchive();
                var certData = ReadEntry(zip, certificateHash);
                certCache[certificateHash] = certificate = new X509Certificate2(certData);
            }

            return certificate;
        }

        /// <summary>
        /// Gets a stream for a file entry in the bundle.
        /// </summary>
        /// <param name="entryName">The name of the entry to get the stream for.</param>
        /// <returns>A stream for the file.</returns>
        public Stream GetFileStream(string entryName)
        {
            if (Manifest.StoreOriginalFiles)
            {
                using var zip = OpenZipArchive();
                return zip.GetEntry(entryName).Open();
            }
            else
            {
                string path = Path.GetFullPath(entryName, RootPath);
                return File.OpenRead(path);
            }
        }

        /// <summary>
        /// Gets the bytes of a file entry in the bundle.
        /// </summary>
        /// <param name="entryName">The name of the entry to get the bytes for.</param>
        /// <returns>The bytes of the file.</returns>
        public byte[] GetFileBytes(string entryName)
        {
            if (Manifest.StoreOriginalFiles)
            {
                using var zip = OpenZipArchive();
                return ReadEntry(zip, entryName);
            }
            else
            {
                string path = Path.GetFullPath(entryName, RootPath);
                return ReadStream(File.OpenRead(path));
            }
        }

        /// <summary>
        /// Exports the specified structured data to a byte array.
        /// </summary>
        /// <param name="structuredData">The structured data to export.</param>
        /// <returns>A byte array containing the exported data.</returns>
        protected byte[] Export(object structuredData)
        {
            var data = JsonSerializer.Serialize(structuredData, SerializerOptions);
            return Encoding.UTF8.GetBytes(data);
        }

        /// <summary>
        /// Writes changes to the bundle file.
        /// </summary>
        public void Update()
        {
            EnsureWritable();

            using (ZipArchive zip = OpenZipArchive(ZipArchiveMode.Update))
            {
                OnUpdating?.Invoke(zip);

                WriteEntry(zip, ".manifest.ec", Export(Manifest));
                WriteEntry(zip, ".signatures.ec", Export(Signatures));

                foreach (var newFile in newEmbeddedFiles)
                {
                    WriteEntry(zip, newFile.Key, newFile.Value);
                }
            }
        }

        /// <summary>
        /// Reads an entry from a <see cref="ZipArchive"/> and caches the entry data if the bundle is Read-only.
        /// </summary>
        /// <param name="zip">The <see cref="ZipArchive"/> to read from.</param>
        /// <param name="entryName">The name of the entry to read.</param>
        /// <returns>A byte array containing the entry data.</returns>
        protected byte[] ReadEntry(ZipArchive zip, string entryName)
        {
            if (!fileCache.TryGetValue(entryName, out var data))
            {
                using var stream = zip.GetEntry(entryName).Open();
                data = ReadStream(stream);

                if (IsReadOnly)
                    fileCache[entryName] = data;
            }

            return data;
        }

        /// <summary>
        /// Reads a stream into a byte array.
        /// </summary>
        /// <param name="stream">The stream to read.</param>
        /// <returns>A byte array containing the stream data.</returns>
        private static byte[] ReadStream(Stream stream)
        {
            MemoryStream ms = new();
            stream.CopyTo(ms);
            return ms.ToArray();
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
            ZipArchiveEntry tempEntry;
            if ((tempEntry = zip.GetEntry(entryName)) != null)
                tempEntry.Delete();

#if NET6_0_OR_GREATER
            ZipArchiveEntry entry = zip.CreateEntry(entryName, CompressionLevel.SmallestSize);
#else
                ZipArchiveEntry entry = zip.CreateEntry(entryName, CompressionLevel.Optimal);
#endif

            using var stream = entry.Open();
            stream.Write(data, 0, data.Length);
            stream.Flush();
        }

        /// <summary>
        /// Computes the SHA-512 hash of a stream.
        /// </summary>
        /// <param name="stream">The stream to hash.</param>
        /// <returns>A byte array containing the hash.</returns>
        static byte[] ComputeSHA512Hash(Stream stream)
        {
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
            using var sha512 = SHA512.Create();
            return sha512.ComputeHash(data);
        }
    }
}
