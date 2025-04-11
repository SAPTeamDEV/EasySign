using System;
using System.Collections.Generic;
using System.Diagnostics.Metrics;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

using EnsureThat;

namespace SAPTeam.EasySign.CommandLine
{
    /// <summary>
    /// Represents the subject of a certificate.
    /// </summary>
    public class CertificateSubject
    {
        /// <summary>
        /// Gets or sets the common name (CN) of the certificate subject.
        /// </summary>
        public string CommonName { get; set; }

        /// <summary>
        /// Gets or sets the email address (E) of the certificate subject.
        /// </summary>
        public string? Email { get; set; }

        /// <summary>
        /// Gets or sets the organization (O) of the certificate subject.
        /// </summary>
        public string? Organization { get; set; }

        /// <summary>
        /// Gets or sets the organizational unit (OU) of the certificate subject.
        /// </summary>
        public string? OrganizationalUnit { get; set; }

        /// <summary>
        /// Gets or sets the locality (L) of the certificate subject.
        /// </summary>
        public string? Locality { get; set; }

        /// <summary>
        /// Gets or sets the state or province (ST) of the certificate subject.
        /// </summary>
        public string? State { get; set; }

        /// <summary>
        /// Gets or sets the country (C) of the certificate subject.
        /// </summary>
        public string? Country { get; set; }

        /// <summary>
        /// Gets a dictionary of unknown keys and their values from the parsed subject string.
        /// </summary>
        public Dictionary<string, string> Unknown { get; } = [];

        /// <summary>
        /// Initializes a new instance of the <see cref="CertificateSubject"/> class with the specified X509Certificate2 certificate.
        /// </summary>
        /// <param name="certificate">
        /// The certificate to extract the subject from.
        /// </param>
        public CertificateSubject(X509Certificate2 certificate) : this(certificate.Subject)
        {
            var commonName = certificate.GetNameInfo(X509NameType.SimpleName, false);
            if (string.IsNullOrEmpty(commonName))
            {
                commonName = certificate.GetNameInfo(X509NameType.DnsName, false);
            }

            if (!string.IsNullOrEmpty(commonName))
            {
                CommonName = commonName;
            }

            var email = certificate.GetNameInfo(X509NameType.EmailName, false);
            if (!string.IsNullOrEmpty(email))
            {
                Email = email;
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CertificateSubject"/> class with the specified subject string.
        /// </summary>
        /// <param name="subject">
        /// The subject string in the comma-delimited format.
        /// </param>
        public CertificateSubject(string subject)
        {
            Ensure.String.IsNotNullOrEmpty(subject, nameof(subject));

            var parts = subject.Split([","], StringSplitOptions.RemoveEmptyEntries);

            foreach (var part in parts)
            {
                int index = part.IndexOf('=');
                if (index <= 0 || index >= part.Length - 1)
                    continue; // Ignore malformed parts.

                string key = part.Substring(0, index).Trim();
                string value = part.Substring(index + 1).Trim();

                // Map each key abbreviation to a property of the object
                switch (key.ToUpperInvariant())
                {
                    case "CN":
                        CommonName = value;
                        break;
                    case "E":
                        Email = value;
                        break;
                    case "O":
                        Organization = value;
                        break;
                    case "OU":
                        OrganizationalUnit = value;
                        break;
                    case "L":
                        Locality = value;
                        break;
                    case "ST":
                    case "S":
                        State = value;
                        break;
                    case "C":
                        Country = value;
                        break;
                    default:
                        Unknown[key.ToUpperInvariant()] = value; // Store unknown keys in the dictionary
                        break;
                }
            }

            if (string.IsNullOrEmpty(CommonName))
            {
                CommonName = string.Empty;
            }
        }


        /// <summary>
        /// Initializes a new instance of the <see cref="CertificateSubject"/> class with the specified properties.
        /// </summary>
        /// <param name="commonName">Common Name (CN) - required.</param>
        /// <param name="email">Email (E) - optional.</param>
        /// <param name="organization">Organization (O) - optional.</param>
        /// <param name="organizationalUnit">Organizational Unit (OU) - optional.</param>
        /// <param name="locality">Locality (L) - optional.</param>
        /// <param name="state">State or Province (ST) - optional.</param>
        /// <param name="country">Country (C) - optional.</param>
        public CertificateSubject(string commonName, string? email, string? organization, string? organizationalUnit, string? locality, string? state, string? country)
        {
            Ensure.String.IsNotNullOrEmpty(commonName, nameof(commonName));

            CommonName = commonName;
            Email = email;
            Organization = organization;
            OrganizationalUnit = organizationalUnit;
            Locality = locality;
            State = state;
            Country = country;
        }


        /// <summary>
        /// Generates a comma-delimited string representation of the certificate subject.
        /// </summary>
        /// <returns>
        /// A comma-delimited string representation of the certificate subject.
        /// </returns>
        public override string ToString()
        {
            var components = new List<string>
            {
                $"CN={CommonName}"
            };

            if (!string.IsNullOrEmpty(Email))
            {
                components.Add($"E={Email}");
            }

            if (!string.IsNullOrEmpty(Organization))
            {
                components.Add($"O={Organization}");
            }

            if (!string.IsNullOrEmpty(OrganizationalUnit))
            {
                components.Add($"OU={OrganizationalUnit}");
            }

            if (!string.IsNullOrEmpty(Locality))
            {
                components.Add($"L={Locality}");
            }

            if (!string.IsNullOrEmpty(State))
            {
                components.Add($"ST={State}");
            }

            if (!string.IsNullOrEmpty(Country))
            {
                components.Add($"C={Country}");
            }

            return string.Join(", ", components);
        }
    }

}
