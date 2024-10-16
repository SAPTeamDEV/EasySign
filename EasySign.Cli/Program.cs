using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace EasySign.Cli
{
    internal class Program
    {
        static void Main(string[] args)
        {
            bool doAdd = args[0] == "add";

            string path = Path.GetFullPath(args[1]);

            var signInfra = new Bundle(path);

            Console.WriteLine(path);

            if (doAdd)
            {
                Parallel.ForEach(Directory.GetFiles(path, "*", SearchOption.AllDirectories), (file) =>
                {
                    signInfra.AddEntry(file);
                    Console.WriteLine($"Added: {file}");
                });

                X509Store store = new X509Store("MY", StoreLocation.CurrentUser);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                X509Certificate2Collection collection = store.Certificates;
                foreach (var cert in collection.Where(x => x.HasPrivateKey))
                {
                    if (cert.GetRSAPrivateKey() == null) continue;
                    Console.WriteLine($"Signing with: {cert.GetNameInfo(X509NameType.SimpleName, false)}");
                    signInfra.SignBundle(cert);
                    Console.WriteLine($"Signed by: {cert.GetNameInfo(X509NameType.SimpleName, false)}");
                }

                signInfra.Update();
            }
            else
            {
                signInfra.Load();

                foreach (var cert in signInfra.Signatures.Entries.Keys)
                {
                    var certificate = signInfra.GetCertificate(cert);
                    Console.WriteLine(certificate.Subject);
                    Console.WriteLine($"Is Verified: {certificate.Verify()}");
                    Console.WriteLine($"Is Valid Sign: {signInfra.VerifySignature(cert)}");
                    Console.WriteLine();
                }

                Parallel.ForEach(signInfra.Manifest.Entries, (entry) =>
                {
                    Console.WriteLine($"{entry.Key}: {signInfra.VerifyFile(entry.Key)}");
                });

                Console.WriteLine($"Verified {signInfra.Manifest.Entries.Count()} files");
            }
        }
    }
}
