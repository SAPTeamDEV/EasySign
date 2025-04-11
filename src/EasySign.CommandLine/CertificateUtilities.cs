using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using EnsureThat;
using Spectre.Console;

namespace SAPTeam.EasySign.CommandLine
{
    /// <summary>
    /// Provides functionality for creating and importing X.509 certificates
    /// </summary>
    public static class CertificateUtilities
    {
        /// <summary>
        /// Prints the details of given X.509 certificates to the console.
        /// </summary>
        /// <param name="certificates">
        /// The X.509 certificates to display.
        /// </param>
        public static void DisplayCertificate(params X509Certificate2[] certificates)
        {
            Grid grid = new Grid();
            grid.AddColumn(new GridColumn().NoWrap());
            grid.AddColumn(new GridColumn().PadLeft(2));

            int index = 1;
            foreach (var certificate in certificates)
            {
                if (index > 1)
                {
                    grid.AddRow();
                }

                if (certificates.Length > 1)
                {
                    grid.AddRow($"Certificate #{index}:");
                }
                else
                {
                    grid.AddRow("Certificate Info:");
                }
                
                grid.AddRow("   Common Name", certificate.GetNameInfo(X509NameType.SimpleName, false));
                grid.AddRow("   Issuer Name", certificate.GetNameInfo(X509NameType.SimpleName, true));
                grid.AddRow("   Holder Email", certificate.GetNameInfo(X509NameType.EmailName, false));
                grid.AddRow("   Valid From", certificate.GetEffectiveDateString());
                grid.AddRow("   Valid To", certificate.GetExpirationDateString());
                grid.AddRow("   Thumbprint", certificate.Thumbprint);

                index++;
            }

            AnsiConsole.Write(grid);
            AnsiConsole.WriteLine();
        }

        /// <summary>
        /// Prompts the user for certificate subject information and generates a standardized subject name.
        /// </summary>
        /// <returns>
        /// The formatted certificate subject string.
        /// </returns>
        public static string GetSubjectNameFromUser()
        {
            string? commonName = null;

            while (string.IsNullOrEmpty(commonName))
            {
                Console.Write("Common Name (CN): ");
                commonName = Console.ReadLine();
            }

            Console.Write("Organization (O) (optional): ");
            string? organization = Console.ReadLine();

            Console.Write("Organizational Unit (OU) (optional): ");
            string? organizationalUnit = Console.ReadLine();

            Console.Write("Locality (L) (optional): ");
            string? locality = Console.ReadLine();

            Console.Write("State or Province (S) (optional): ");
            string? state = Console.ReadLine();

            Console.Write("Country (C) (optional): ");
            string? country = Console.ReadLine();

            return GenerateSubjectName(commonName, organization, organizationalUnit, locality, state, country);
        }

        /// <summary>
        /// Generates a standardized certificate subject name.
        /// Only non-empty components are included.
        /// </summary>
        /// <param name="commonName">Common Name (CN) - required.</param>
        /// <param name="organization">Organization (O) - optional.</param>
        /// <param name="organizationalUnit">Organizational Unit (OU) - optional.</param>
        /// <param name="locality">Locality (L) - optional.</param>
        /// <param name="stateOrProvince">State or Province (S) - optional.</param>
        /// <param name="country">Country (C) - optional.</param>
        /// <returns>The formatted certificate subject string.</returns>
        public static string GenerateSubjectName(string commonName, string? organization, string? organizationalUnit, string? locality, string? stateOrProvince, string? country)
        {
            Ensure.String.IsNotNullOrEmpty(commonName, nameof(commonName));

            var components = new List<string>
            {
                // Required fields
                $"CN={commonName}"
            };

            // Optional fields: add only if they are not null or empty.
            if (!string.IsNullOrWhiteSpace(organization))
            {
                components.Add($"O={organization}");
            }

            if (!string.IsNullOrWhiteSpace(organizationalUnit))
            {
                components.Add($"OU={organizationalUnit}");
            }

            if (!string.IsNullOrWhiteSpace(locality))
            {
                components.Add($"L={locality}");
            }

            if (!string.IsNullOrWhiteSpace(stateOrProvince))
            {
                components.Add($"S={stateOrProvince}");
            }

            if (!string.IsNullOrWhiteSpace(country))
            {
                components.Add($"C={country}");
            }

            // Combine with comma separators.
            return string.Join(", ", components);
        }

        /// <summary>
        /// Retrieves a collection of certificates from a PFX file or the current user's certificate store.
        /// </summary>
        /// <param name="pfxFilePath">The path to the PFX file.</param>
        /// <param name="pfxFilePassword">The password for the PFX file.</param>
        /// <param name="pfxNoPasswordPrompt">Indicates whether to prompt for a password if not provided.</param>
        /// <returns>A collection of certificates.</returns>
        public static X509Certificate2Collection GetCertificates(string pfxFilePath, string pfxFilePassword, bool pfxNoPasswordPrompt)
        {
            X509Certificate2Collection collection;

            if (!string.IsNullOrEmpty(pfxFilePath))
            {
                collection = LoadCertificatesFromPfx(pfxFilePath, pfxFilePassword, pfxNoPasswordPrompt);
            }
            else
            {
                try
                {
                    X509Store store = new X509Store("MY", StoreLocation.CurrentUser);
                    store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                    collection = store.Certificates;

                    store.Close();
                }
                catch
                {
                    collection = [];
                }
            }

            return collection;
        }

        /// <summary>
        /// Loads certificates from a PFX file.
        /// </summary>
        /// <param name="pfxFilePath">
        /// The path to the PFX file.
        /// </param>
        /// <param name="pfxFilePassword">
        /// The password for the PFX file.
        /// </param>
        /// <param name="pfxNoPasswordPrompt">
        /// Indicates whether to prompt for a password if not provided.
        /// </param>
        /// <returns></returns>
        private static X509Certificate2Collection LoadCertificatesFromPfx(string pfxFilePath, string? pfxFilePassword, bool pfxNoPasswordPrompt)
        {
            X509Certificate2Collection collection = [];

            string pfpass = !string.IsNullOrEmpty(pfxFilePassword) ? pfxFilePassword : !pfxNoPasswordPrompt ? Utilities.SecurePrompt("Enter PFX File password (if needed): ") : "";

#if NET9_0_OR_GREATER
            X509Certificate2Collection tempCollection = X509CertificateLoader.LoadPkcs12CollectionFromFile(pfxFilePath, pfpass, X509KeyStorageFlags.EphemeralKeySet);
#else
            X509Certificate2Collection tempCollection = [];
            tempCollection.Import(pfxFilePath, pfpass, X509KeyStorageFlags.EphemeralKeySet);
#endif

            IEnumerable<X509Certificate2> cond = tempCollection.Where(x => x.HasPrivateKey);
            if (cond.Any())
            {
                collection.AddRange(cond.ToArray());
            }
            else
            {
                collection.AddRange(tempCollection);
            }

            return collection;
        }

        /// <summary>
        /// Creates a self-signed certificate which acts as a Root Certificate Authority (CA).
        /// </summary>
        /// <param name="subjectName">The certificate subject.</param>
        /// <returns>A self-signed X509Certificate2 representing the Root CA.</returns>
        public static X509Certificate2 CreateSelfSignedCACertificate(string subjectName)
        {
            using (RSA rsa = RSA.Create(4096))
            {
                // Build the certificate request for the CA.
                var caRequest = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                // Mark this certificate as a Certificate Authority with the Basic Constraints extension.
                caRequest.CertificateExtensions.Add(
                    new X509BasicConstraintsExtension(true, false, 0, true));

                // Set key usages to allow certificate signing and CRL signing.
                caRequest.CertificateExtensions.Add(
                    new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));

                // Add a Subject Key Identifier.
                caRequest.CertificateExtensions.Add(
                    new X509SubjectKeyIdentifierExtension(caRequest.PublicKey, false));

                // Create the self-signed certificate. Validity is set from yesterday to 10 years in the future.
                var rootCert = caRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),
                                                          DateTimeOffset.UtcNow.AddYears(10));

                // Export and re-import to mark the key as exportable (if needed for further signing).
#if NET9_0_OR_GREATER
                var cert = X509CertificateLoader.LoadPkcs12(rootCert.Export(X509ContentType.Pfx), null, X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
#else
                var cert = new X509Certificate2(rootCert.Export(X509ContentType.Pfx), "", X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
#endif

                return cert;
            }
        }

        /// <summary>
        /// Creates a certificate and signs it using the provided Root CA certificate.
        /// </summary>
        /// <param name="subjectName">The subject name for the new certificate.</param>
        /// <param name="caCert">The Root CA certificate that will sign the new certificate. Must include the private key.</param>
        /// <returns>The issued X509Certificate2 signed by the provided Root CA.</returns>
        public static X509Certificate2 IssueCertificate(string subjectName, X509Certificate2 caCert)
        {
            using (RSA rsa = RSA.Create(2048))
            {
                _ = rsa.ExportRSAPrivateKey(); // Ensure the RSA key is created.

                // Build the certificate request for the issued certificate.
                var req = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                // This certificate is not a CA, so basic constraints are set accordingly.
                req.CertificateExtensions.Add(
                    new X509BasicConstraintsExtension(false, false, 0, false));

                // Use key usage flags appropriate for, e.g., a server certificate.
                req.CertificateExtensions.Add(
                    new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));

                // Add a Subject Key Identifier.
                req.CertificateExtensions.Add(
                    new X509SubjectKeyIdentifierExtension(req.PublicKey, false));

                // Generate a random serial number.
                byte[] serialNumber = new byte[16];
                using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(serialNumber);
                }

                // Sign the new certificate with the CA certificate.
                // Note: The CA certificate must contain its private key for signing.
                using (RSA? caPrivateKey = caCert.GetRSAPrivateKey())
                {
                    if (caPrivateKey == null)
                    {
                        throw new InvalidOperationException("The provided CA certificate does not contain a private key.");
                    }

                    // Create the certificate valid from yesterday until 2 years in the future.
                    var issuedCert = req.Create(caCert, DateTimeOffset.UtcNow.AddDays(-1),
                                                  DateTimeOffset.UtcNow.AddYears(2), serialNumber);

                    return issuedCert.CopyWithPrivateKey(rsa);
                }
            }
        }
    }
}
