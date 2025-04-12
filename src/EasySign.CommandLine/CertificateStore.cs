using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SAPTeam.EasySign.CommandLine
{
    /// <summary>
    /// Enumeration of certificate stores in the <see cref="CommandProviderConfiguration"/>.
    /// </summary>
    public enum CertificateStore
    {
        /// <summary>
        /// The trusted root CA store.
        /// </summary>
        TrustedRootCA,

        /// <summary>
        /// The intermediate CA store.
        /// </summary>
        IntermediateCA,

        /// <summary>
        /// The self-signed certificate store.
        /// </summary>
        IssuedCertificates,
    }
}
