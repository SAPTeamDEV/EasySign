using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace SAPTeam.EasySign.CommandLine
{
    /// <summary>
    /// Represents the configuration for the EasySign command provider.
    /// </summary>
    public class CommandProviderConfiguration
    {
        /// <summary>
        /// Gets or sets the list of prefixes that should be protected from modification.
        /// </summary>
        protected string[] ProtectedPrefixes { get; } = [];

        /// <summary>
        /// Gets or sets the list of trusted root CA certificates.
        /// </summary>
        public Dictionary<string, byte[]> TrustedRootCA { get; set; } = [];

        /// <summary>
        /// Gets or sets the list of intermediate CA certificates.
        /// </summary>
        public Dictionary<string, byte[]> IntermediateCA { get; set; } = [];

        /// <summary>
        /// Gets or sets the list of issued certificates by the self signing root CA.
        /// </summary>
        public Dictionary<string, byte[]> IssuedCertificates { get; set; } = [];

        /// <summary>
        /// Gets or sets the self-signed root CA certificate.
        /// </summary>
        public byte[]? SelfSignedRootCA { get; set; } = null;

        /// <summary>
        /// Initializes a new instance of the <see cref="CommandProviderConfiguration"/> class.
        /// </summary>
        public CommandProviderConfiguration()
        {
            
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CommandProviderConfiguration"/> class with the specified protected prefixes.
        /// </summary>
        /// <remarks>
        /// IDs with these prefixes cannot be modified in the trusted root CA and intermediate CA stores with the <see cref="AddCertificate(CertificateStore, X509Certificate2, string?)"/> and <see cref="RemoveCertificate(CertificateStore, string)"/> methods.
        /// </remarks>
        /// <param name="protectedPrefixes">
        /// The prefixes that should be protected from modification.
        /// </param>
        public CommandProviderConfiguration(string[] protectedPrefixes)
        {
            ProtectedPrefixes = ProtectedPrefixes.Union(protectedPrefixes).ToArray();
        }

        /// <summary>
        /// Checks if the given ID starts with any of the protected prefixes.
        /// </summary>
        /// <param name="id">
        /// The ID to check.
        /// </param>
        /// <exception cref="InvalidOperationException"></exception>
        protected void CheckProtectedPrefix(string id)
        {
            if (IsProtected(id))
            {
                throw new InvalidOperationException($"The ID '{id}' is protected and cannot be modified.");
            }
        }

        /// <summary>
        /// Checks if the given ID starts with any of the protected prefixes.
        /// </summary>
        /// <param name="id">
        /// The ID to check.
        /// </param>
        /// <returns>
        /// <see langword="true"/> if the ID is protected; otherwise, <see langword="false"/>.
        /// </returns>
        public bool IsProtected(string id)
        {
            return ProtectedPrefixes.Any(id.StartsWith);
        }

        /// <summary>
        /// Adds a certificate to the specified certificate store.
        /// </summary>
        /// <param name="certificateStore">
        /// The certificate store to which the certificate will be added.
        /// </param>
        /// <param name="certificate">
        /// The certificate to add.
        /// </param>
        /// <param name="id">
        /// The ID of the certificate. If not provided, the last 6 characters of the certificate's thumbprint will be used.
        /// </param>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        /// <returns>
        /// The ID of the added certificate.
        /// </returns>
        public string AddCertificate(CertificateStore certificateStore, X509Certificate2 certificate, string? id = null)
        {
            id = !string.IsNullOrEmpty(id) ? id : certificate.Thumbprint.ToLowerInvariant()[^6..];
            if (certificateStore != CertificateStore.IssuedCertificates)
            {
                CheckProtectedPrefix(id);
            }

            byte[] data = certificateStore == CertificateStore.IssuedCertificates ? certificate.Export(X509ContentType.Pfx) : certificate.Export(X509ContentType.Cert);

            switch (certificateStore)
            {
                case CertificateStore.TrustedRootCA:
                    TrustedRootCA[id] = data;
                    break;
                case CertificateStore.IntermediateCA:
                    IntermediateCA[id] = data;
                    break;
                case CertificateStore.IssuedCertificates:
                    IssuedCertificates[id] = data;
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(certificateStore), certificateStore, null);
            }

            return id;
        }

        /// <summary>
        /// Loads all certificates from the specified certificate store.
        /// </summary>
        /// <param name="certificateStore">
        /// The certificate store from which to load the certificates.
        /// </param>
        /// <returns>
        /// A collection of certificates from the specified store.
        /// </returns>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public X509Certificate2Collection LoadCertificates(CertificateStore certificateStore)
        {
            X509Certificate2Collection certificates = new X509Certificate2Collection();

            switch (certificateStore)
            {
                case CertificateStore.TrustedRootCA:
                    foreach (var id in TrustedRootCA.Keys)
                    {
                        certificates.Add(LoadCertificate(certificateStore, id));
                    }
                    break;
                case CertificateStore.IntermediateCA:
                    foreach (var id in IntermediateCA.Keys)
                    {
                        certificates.Add(LoadCertificate(certificateStore, id));
                    }
                    break;
                case CertificateStore.IssuedCertificates:
                    foreach (var id in IssuedCertificates.Keys)
                    {
                        certificates.Add(LoadCertificate(certificateStore, id));
                    }
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(certificateStore), certificateStore, null);
            }

            return certificates;
        }

        /// <summary>
        /// Loads a certificate from the specified certificate store using the given ID.
        /// </summary>
        /// <param name="certificateStore">
        /// The certificate store from which to load the certificate.
        /// </param>
        /// <param name="id">
        /// The ID of the certificate to load.
        /// </param>
        /// <returns></returns>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public X509Certificate2 LoadCertificate(CertificateStore certificateStore, string id)
        {
            byte[] data;

            switch (certificateStore)
            {
                case CertificateStore.TrustedRootCA:
                    data = TrustedRootCA[id];
                    break;
                case CertificateStore.IntermediateCA:
                    data = IntermediateCA[id];
                    break;
                case CertificateStore.IssuedCertificates:
                    data = IssuedCertificates[id];
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(certificateStore), certificateStore, null);
            }

            return certificateStore == CertificateStore.IssuedCertificates
                ? CertificateUtilities.ImportPFX(data).Single()
                : CertificateUtilities.Import(data);
        }

        /// <summary>
        /// Removes a certificate from the specified certificate store using the given ID.
        /// </summary>
        /// <param name="certificateStore">
        /// The certificate store from which to remove the certificate.
        /// </param>
        /// <param name="id">
        /// The ID of the certificate to remove.
        /// </param>
        /// <returns>
        /// <see langword="true"/> if the certificate was removed successfully; otherwise, <see langword="false"/>.
        /// </returns>
        /// <exception cref="ArgumentOutOfRangeException"></exception>
        public bool RemoveCertificate(CertificateStore certificateStore, string id)
        {
            if (certificateStore != CertificateStore.IssuedCertificates)
            {
                CheckProtectedPrefix(id);
            }

            bool result;

            switch (certificateStore)
            {
                case CertificateStore.TrustedRootCA:
                    result = TrustedRootCA.Remove(id);
                    break;
                case CertificateStore.IntermediateCA:
                    result = IntermediateCA.Remove(id);
                    break;
                case CertificateStore.IssuedCertificates:
                    result = IssuedCertificates.Remove(id);
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(certificateStore), certificateStore, null);
            }

            return result;
        }
    }
}
