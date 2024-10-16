using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
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

        readonly JsonSerializerOptions options = new JsonSerializerOptions()
        {
            WriteIndented = false,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingDefault,
        };

        public bool ReadOnly { get; private set; }

        public Bundle(string rootPath, string bundleName) : this(rootPath)
        {
            BundleName = bundleName;
        }

        public Bundle(string rootPath)
        {
            RootPath = rootPath;
        }

        public ZipArchive GetZipArchive(ZipArchiveMode mode = ZipArchiveMode.Read)
        {
            ZipArchive archive;

            if (ReadOnly && mode != ZipArchiveMode.Read)
            {
                throw new InvalidOperationException("Bundle is read-only");
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

        public void Load()
        {
            ReadBundle(GetZipArchive());
        }

        public void Load(byte[] bundleContent)
        {
            ReadOnly = true;
            rawZipContents = bundleContent;

            ReadBundle(GetZipArchive());
        }

        private void ReadBundle(ZipArchive zip)
        {
            foreach (ZipArchiveEntry entry in zip.Entries)
            {
                if (entry.Name == ".manifest.ec")
                {
                    Manifest = JsonSerializer.Deserialize<Manifest>(entry.Open(), options);
                }

                if (entry.Name == ".signatures.ec")
                {
                    Signatures = JsonSerializer.Deserialize<Signature>(entry.Open(), options);
                }
            }
        }

        public void AddEntry(string path)
        {
            string name;
            var hash = ComputeSHA512Hash(File.OpenRead(path));

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
            var signature = privateKey.SignData(ExportManifest(), HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
            var cert = Convert.ToBase64String(certificate.Export(X509ContentType.Cert));
            var name = certificate.GetCertHashString();

            StringBuilder pemBuilder = new StringBuilder();
            pemBuilder.AppendLine("-----BEGIN CERTIFICATE-----");
            pemBuilder.AppendLine(cert);
            pemBuilder.AppendLine("-----END CERTIFICATE-----");
            string pemContents = pemBuilder.ToString();

            Signatures.Entries[name] = signature;
            newEmbeddedFiles[name] = Encoding.UTF8.GetBytes(pemContents);
        }

        public bool VerifyFile(string entryName)
        {
            byte[] hash;

            if (Manifest.BundleFiles)
            {
                hash = ComputeSHA512Hash(ReadEntry(GetZipArchive(), entryName));
            }
            else
            {
                string path = Path.GetFullPath(entryName, RootPath);
                hash = ComputeSHA512Hash(File.OpenRead(path));
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

        public bool VerifyCertificate(string certificateHash, X509ChainPolicy policy = null)
        {
            X509Certificate2 certificate = GetCertificate(certificateHash);

            X509Chain chain = new X509Chain
            {
                ChainPolicy = policy ?? new()
            };

            bool isValid = chain.Build(certificate);
            return isValid;
        }

        public X509Certificate2 GetCertificate(string certificateHash)
        {
            if (!certCache.TryGetValue(certificateHash, out X509Certificate2 certificate))
            {
                var certData = ReadEntry(GetZipArchive(), certificateHash);
                certCache[certificateHash] = certificate = new X509Certificate2(certData);
            }

            return certificate;
        }

        public byte[] ExportManifest()
        {
            var data = JsonSerializer.Serialize(Manifest, options);
            return Encoding.UTF8.GetBytes(data);
        }

        public byte[] ExportSignature()
        {
            var data = JsonSerializer.Serialize(Signatures, options);
            return Encoding.UTF8.GetBytes(data);
        }

        public void Update()
        {
            using (ZipArchive zip = GetZipArchive(ZipArchiveMode.Update))
            {
                WriteEntry(zip, ".manifest.ec", ExportManifest());
                WriteEntry(zip, ".signatures.ec", ExportSignature());
                
                foreach (var newFile in newEmbeddedFiles)
                {
                    WriteEntry(zip, newFile.Key, newFile.Value);
                }
            }
        }

        private static byte[] ReadEntry(ZipArchive zip, string entryName)
        {
            var entry = zip.GetEntry(entryName);

            var stream = entry.Open();
            var ms = new MemoryStream();
            stream.CopyTo(ms);
            return ms.ToArray();
        }

        private static void WriteEntry(ZipArchive zip, string entryName, byte[] data)
        {
            ZipArchiveEntry entry = zip.GetEntry(entryName);
            
            if (entry == null)
            {
                entry = zip.CreateEntry(entryName, CompressionLevel.SmallestSize);
            }

            var stream = entry.Open();
            stream.Write(data, 0, data.Length);
            stream.Flush();
            stream.Close();
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
