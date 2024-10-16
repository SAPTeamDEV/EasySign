using System.Security.Cryptography.X509Certificates;

namespace CertVerifier
{
    internal class Program
    {
        static void Main(string[] args)
        {
            byte[] rootCAData = Convert.FromBase64String("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");
            var rootCA = new X509Certificate2(rootCAData);

            Console.Write("Enter pfx password as needed: ");

            var certCollection = new X509Certificate2Collection();
            certCollection.Import(args[0], Console.ReadLine(), X509KeyStorageFlags.Exportable);

            X509Certificate2 certificate = certCollection.Last();

            foreach (var crt in certCollection)
            {
                Console.WriteLine($"Common Name: {crt.GetNameInfo(X509NameType.SimpleName, false)}");
            }

            X509Chain chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // Adjust as needed
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            chain.ChainPolicy.CustomTrustStore.Add(rootCA);

            // Build the chain
            bool isValid = chain.Build(certificate);

            // Check if the chain validation succeeded
            if (isValid)
            {
                Console.WriteLine("Certificate chain validation succeeded!");
            }
            else
            {
                Console.WriteLine("Certificate chain validation failed.");
                foreach (X509ChainStatus status in chain.ChainStatus)
                {
                    Console.WriteLine($"Status: {status.Status} - {status.StatusInformation}");
                }
            }

        }
    }
}
