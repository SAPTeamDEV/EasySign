using System.Security.Cryptography;

namespace KeyGen
{
    internal class Program
    {
        static void Main(string[] args)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                // Generate a new key pair
                var privateKey = rsa.ToXmlString(true);
                var publicKey = rsa.ToXmlString(false);

                // Save these keys securely (e.g., in a file or database)
                Console.WriteLine("Private Key:\n" + privateKey);
                Console.WriteLine("\nPublic Key:\n" + publicKey);
            }
        }
    }
}
