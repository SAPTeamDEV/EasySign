using System.Security.Cryptography;
using System.Text;

namespace Verifier
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string originalData = "Hello, world!";
            byte[] originalDataBytes = Encoding.UTF8.GetBytes(originalData);

            Console.Write("Enter signature: ");
            string signatureBase64 = Console.ReadLine();
            byte[] signature = Convert.FromBase64String(signatureBase64);

            using (var rsa = new RSACryptoServiceProvider())
            {
                Console.Write("Enter Public Key: ");
                rsa.FromXmlString(Console.ReadLine());
                bool isSignatureValid = rsa.VerifyData(originalDataBytes, SHA256.Create(), signature);

                Console.WriteLine("Signature is valid: " + isSignatureValid);
            }

        }
    }
}
