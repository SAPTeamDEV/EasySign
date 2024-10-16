using System.Security.Cryptography;
using System.Text;

namespace Signer
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string dataToSign = "Hello, world!";
            byte[] dataBytes = Encoding.UTF8.GetBytes(dataToSign);

            using (var rsa = new RSACryptoServiceProvider())
            {
                Console.Write("Enter Private key: ");
                rsa.FromXmlString(Console.ReadLine());
                byte[] signature = rsa.SignData(dataBytes, SHA256.Create());

                // Save the signature
                Console.WriteLine("Signature:\n" + Convert.ToBase64String(signature));
            }

        }
    }
}
