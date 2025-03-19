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

namespace EasySign
{
    public class Bundle
    {
        public const string DefaultBundleName = ".eSign";

        byte[] rawZipContents = null;

        public string RootPath { get; }

        public string BundleName { get; } = DefaultBundleName;

        public string BundlePath => Path.Combine(RootPath, BundleName);

        public Manifest Manifest { get; private set; } = new();

        public Signature Signatures { get; private set; } = new();

        readonly Dictionary<string, X509Certificate2> certCache = new();

        readonly ConcurrentDictionary<string, byte[]> newEmbeddedFiles = new();
        
        readonly ConcurrentDictionary<string, byte[]> fileCache = new();

        protected readonly JsonSerializerOptions options = new JsonSerializerOptions()
        {
            WriteIndented = false,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault,
        };

        public bool ReadOnly { get; private set; }

        public event Action<ZipArchive> Updating;

        public Bundle(string rootPath, string bundleName) : this(rootPath)
        {
            BundleName = bundleName;
        }

        public Bundle(string rootPath)
        {
            RootPath = Path.GetFullPath(rootPath);
        }

        void ThrowIfReadOnly()
        {
            if (ReadOnly)
            {
                throw new InvalidOperationException("Bundle is read-only");
            }
        }

        public ZipArchive GetZipArchive(ZipArchiveMode mode = ZipArchiveMode.Read)
        {
            ZipArchive archive;

            if (mode != ZipArchiveMode.Read)
            {
                ThrowIfReadOnly();
            }

            if (rawZipContents != null && rawZipContents.Length > 0)
            {
                var ms = new MemoryStream(rawZipContents);
                archive = new ZipArchive(ms, mode);
            }
            else
            {
                archive = ZipFile.Open(BundlePath, mode);
            }

            return archive;
        }

        public void Load(bool readOnly = true)
        {
            ReadOnly = readOnly;
            using var zip = GetZipArchive();
            ReadBundle(zip);
        }

        public void Load(byte[] bundleContent)
        {
            ReadOnly = true;
            rawZipContents = bundleContent;

            using var zip = GetZipArchive();
            ReadBundle(zip);
        }

        protected virtual void ReadBundle(ZipArchive zip)
        {
            ZipArchiveEntry entry;
            if ((entry = zip.GetEntry(".manifest.ec")) != null)
            {
                Manifest = JsonSerializer.Deserialize<Manifest>(entry.Open(), options);
            }

            if ((entry = zip.GetEntry(".signatures.ec")) != null)
            {
                Signatures = JsonSerializer.Deserialize<Signature>(entry.Open(), options);
            }
        }

        public void AddEntry(string path)
        {
            ThrowIfReadOnly();

            using var file = File.OpenRead(path);
            string name;
            var hash = ComputeSHA512Hash(file);

            if (Manifest.BundleFiles)
            {
                name = Path.GetFileName(path);
                newEmbeddedFiles[name] = File.ReadAllBytes(path);
            }
            else
            {
                name = new Cds.Folders.OSPath(Path.GetRelativePath(RootPath, path)).Unix;
            }

            Manifest.GetConcurrentDictionary()[name] = hash;
        }

        public void SignBundle(X509Certificate2 certificate, RSA privateKey)
        {
            ThrowIfReadOnly();

            var signature = privateKey.SignData(ExportManifest(), HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
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

        public bool VerifyFile(string entryName)
        {
            byte[] hash;

            if (Manifest.BundleFiles)
            {
                using var zip = GetZipArchive();
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

        public bool VerifySignature(string certificateHash)
        {
            X509Certificate2 certificate = GetCertificate(certificateHash);
            var pubKey = certificate.GetRSAPublicKey();

            var result = pubKey.VerifyData(ExportManifest(), Signatures.Entries[certificateHash], HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
            return result;
        }

        public bool VerifyCertificate(string certificateHash, out X509ChainStatus[] statuses, X509ChainPolicy policy = null)
        {
            X509Certificate2 certificate = GetCertificate(certificateHash);

            return VerifyCertificate(certificate, out statuses, policy);
        }

        public bool VerifyCertificate(X509Certificate2 certificate, out X509ChainStatus[] statuses, X509ChainPolicy policy = null)
        {
            X509Chain chain = new X509Chain
            {
                ChainPolicy = policy ?? new()
            };

            bool isValid = chain.Build(certificate);
            statuses = chain.ChainStatus;
            return isValid;
        }

        public X509Certificate2 GetCertificate(string certificateHash)
        {
            if (!certCache.TryGetValue(certificateHash, out X509Certificate2 certificate))
            {
                using var zip = GetZipArchive();
                var certData = ReadEntry(zip, certificateHash);
                certCache[certificateHash] = certificate = new X509Certificate2(certData);
            }

            return certificate;
        }

        public Stream GetFileStream(string entryName)
        {
            if (Manifest.BundleFiles)
            {
                using var zip = GetZipArchive();
                return zip.GetEntry(entryName).Open();
            }
            else
            {
                string path = Path.GetFullPath(entryName, RootPath);
                return File.OpenRead(path);
            }
        }

        public byte[] GetFileBytes(string entryName)
        {
            if (Manifest.BundleFiles)
            {
                using var zip = GetZipArchive();
                return ReadEntry(zip, entryName);
            }
            else
            {
                string path = Path.GetFullPath(entryName, RootPath);
                return ReadStream(File.OpenRead(path));
            }
        }

        protected byte[] Export(object structuredData)
        {
            var data = JsonSerializer.Serialize(structuredData, options);
            return Encoding.UTF8.GetBytes(data);
        }

        public byte[] ExportManifest()
        {
            return Export(Manifest);
        }

        public byte[] ExportSignature()
        {
            return Export(Signatures);
        }

        public void Update()
        {
            ThrowIfReadOnly();

            using (ZipArchive zip = GetZipArchive(ZipArchiveMode.Update))
            {
                WriteEntry(zip, ".manifest.ec", ExportManifest());
                WriteEntry(zip, ".signatures.ec", ExportSignature());

                Updating?.Invoke(zip);
                
                foreach (var newFile in newEmbeddedFiles)
                {
                    WriteEntry(zip, newFile.Key, newFile.Value);
                }
            }
        }

        private byte[] ReadEntry(ZipArchive zip, string entryName)
        {
            if (!fileCache.TryGetValue(entryName, out var data))
            {
                using var stream = zip.GetEntry(entryName).Open();
                data = ReadStream(stream);

                if (ReadOnly)
                {
                    fileCache[entryName] = data;
                }
            }
            
            return data;
        }

        private static byte[] ReadStream(Stream stream)
        {
            MemoryStream ms = new();
            stream.CopyTo(ms);
            return ms.ToArray();
        }

        protected void WriteEntry(ZipArchive zip, string entryName, byte[] data)
        {
            ZipArchiveEntry tempEntry;
            if ((tempEntry = zip.GetEntry(entryName)) != null)
            {
                tempEntry.Delete();
            }

            ZipArchiveEntry entry = zip.CreateEntry(entryName, CompressionLevel.SmallestSize);

            using var stream = entry.Open();
            stream.Write(data, 0, data.Length);
            stream.Flush();
        }

        public static byte[] ComputeSHA512Hash(Stream stream)
        {
            using var sha512 = SHA512.Create();

            return sha512.ComputeHash(stream);
        }

        public static byte[] ComputeSHA512Hash(byte[] data)
        {
            using var sha512 = SHA512.Create();

            return sha512.ComputeHash(data);
        }
    }
}
