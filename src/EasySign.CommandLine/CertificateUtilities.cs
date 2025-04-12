using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using EnsureThat;
using Spectre.Console;
using System.Text.RegularExpressions;
using Spectre.Console.Rendering;

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
                CertificateSubject subject = new CertificateSubject(certificate);

                if (index > 1)
                {
                    grid.AddRow();
                }

                grid.AddRow($"Certificate {(certificates.Length > 1 ? $"#{index}" : "Info")}:");
                grid.AddRow("   Common Name", subject.CommonName);
                grid.AddRow("   Issuer Name", certificate.GetNameInfo(X509NameType.SimpleName, true));

                if (!string.IsNullOrEmpty(subject.Email))
                {
                    grid.AddRow("   Email Address", subject.Email);
                }

                if (!string.IsNullOrEmpty(subject.Organization))
                {
                    grid.AddRow("   Organization", subject.Organization);
                }

                if (!string.IsNullOrEmpty(subject.OrganizationalUnit))
                {
                    grid.AddRow("   Organizational Unit", subject.OrganizationalUnit);
                }

                if (!string.IsNullOrEmpty(subject.Locality))
                {
                    grid.AddRow("   Locality", subject.Locality);
                }

                if (!string.IsNullOrEmpty(subject.State))
                {
                    grid.AddRow("   State", subject.State);
                }

                if (!string.IsNullOrEmpty(subject.Country))
                {
                    grid.AddRow("   Country", subject.Country);
                }

                grid.AddRow("   Valid From", certificate.GetEffectiveDateString());
                grid.AddRow("   Valid To", certificate.GetExpirationDateString());
                grid.AddRow("   Thumbprint", Regex.Replace(certificate.Thumbprint, "(.{2})(?!$)", "$1:"));
                grid.AddRow("   Serial Number", Regex.Replace(certificate.SerialNumber, "(.{2})(?!$)", "$1:"));

                if (subject.Unknown.Count > 0)
                {
                    grid.AddRow(new Text("   Other Properties"), new Text(string.Join("\n", subject.Unknown.Select(x => $"{x.Key}={x.Value}"))));
                }

                index++;
            }

            AnsiConsole.Write(grid);
            AnsiConsole.WriteLine();
        }

        /// <summary>
        /// Imports a PEM or DER encoded certificate from a file.
        /// </summary>
        /// <param name="filePath">
        /// The path to the certificate file.
        /// </param>
        /// <returns>
        /// An X509Certificate2 object representing the imported certificate.
        /// </returns>
        public static X509Certificate2 Import(string filePath)
        {
            byte[] buffer;
            using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                buffer = new byte[fs.Length];
                fs.Read(buffer, 0, buffer.Length);
            }

            return Import(buffer);
        }

        /// <summary>
        /// Imports a PEM or DER encoded certificate from a byte array.
        /// </summary>
        /// <param name="data">
        /// The byte array containing the certificate data.
        /// </param>
        /// <returns>
        /// An X509Certificate2 object representing the imported certificate.
        /// </returns>
        public static X509Certificate2 Import(byte[] data)
        {
            X509Certificate2 certificate;

#if NET9_0_OR_GREATER
            certificate = X509CertificateLoader.LoadCertificate(data);
#else
            certificate = new X509Certificate2(data);
#endif

            return certificate;
        }

        /// <summary>
        /// Imports a PFX file and returns a collection of certificates.
        /// </summary>
        /// <param name="filePath">
        /// The path to the PFX file.
        /// </param>
        /// <param name="password">
        /// The password for the PFX file. If null, no password is used.
        /// </param>
        /// <returns>
        /// A collection of X509Certificate2 objects representing the certificates in the PFX file.
        /// </returns>
        public static X509Certificate2Collection ImportPFX(string filePath, string? password = null)
        {
            byte[] buffer;

            using (FileStream fs = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                buffer = new byte[fs.Length];
                fs.Read(buffer, 0, buffer.Length);
            }

            return ImportPFX(buffer, password);
        }

        /// <summary>
        /// Imports a PFX file from a byte array and returns a collection of certificates.
        /// </summary>
        /// <param name="data">
        /// The byte array containing the PFX data.
        /// </param>
        /// <param name="password">
        /// The password for the PFX file. If null, no password is used.
        /// </param>
        /// <returns>
        /// A collection of X509Certificate2 objects representing the certificates in the PFX data.
        /// </returns>
        public static X509Certificate2Collection ImportPFX(byte[] data, string? password = null)
        {
            X509Certificate2Collection collection = new X509Certificate2Collection();

#if NET9_0_OR_GREATER
            collection.AddRange(X509CertificateLoader.LoadPkcs12Collection(data, password, X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable));
#else
            collection.Import(data, password, X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
#endif

            return collection;
        }

        /// <summary>
        /// Prompts the user for certificate subject information and generates a <see cref="CertificateSubject"/>.
        /// </summary>
        /// <returns>
        /// The <see cref="CertificateSubject"/> representing the generated subject.
        /// </returns>
        public static CertificateSubject GetSubjectFromUser()
        {
            string? commonName = null;

            while (string.IsNullOrEmpty(commonName))
            {
                Console.Write("Common Name (CN): ");
                commonName = Console.ReadLine();
            }

            Console.Write("Email (E) (optional): ");
            string? email = Console.ReadLine();

            Console.Write("Organization (O) (optional): ");
            string? organization = Console.ReadLine();

            Console.Write("Organizational Unit (OU) (optional): ");
            string? organizationalUnit = Console.ReadLine();

            Console.Write("Locality (L) (optional): ");
            string? locality = Console.ReadLine();

            Console.Write("State or Province (ST) (optional): ");
            string? state = Console.ReadLine();

            Console.Write("Country (C) (optional): ");
            string? country = Console.ReadLine();

            return new CertificateSubject(commonName: commonName,
                                          email: email,
                                          organization: organization,
                                          organizationalUnit: organizationalUnit,
                                          locality: locality,
                                          state: state,
                                          country: country);
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

            X509Certificate2Collection tempCollection = ImportPFX(pfxFilePath, pfpass);

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

                // Create the self-signed certificate. Validity is set from now to 100 years in the future.
                var rootCert = caRequest.CreateSelfSigned(DateTimeOffset.UtcNow,
                                                          DateTimeOffset.UtcNow.AddYears(100));

                // Export and re-import to mark the key as exportable (if needed for further signing).
                var cert = ImportPFX(rootCert.Export(X509ContentType.Pfx)).Single();

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

                    // Create the certificate valid from now until 20 years in the future.
                    var issuedCert = req.Create(caCert, DateTimeOffset.UtcNow,
                                                  DateTimeOffset.UtcNow.AddYears(20), serialNumber);

                    return issuedCert.CopyWithPrivateKey(rsa);
                }
            }
        }
    }
}
