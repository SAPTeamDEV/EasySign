﻿using System;
using System.Security.Cryptography;
using System.Security.Permissions;
using System.IO;
using System.Security.Cryptography.X509Certificates;

class CertSelect
{
    static void Main()
    {
        X509Store store = new X509Store("MY", StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

        X509Certificate2Collection collection = store.Certificates;
        X509Certificate2Collection fcollection = collection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
        X509Certificate2Collection scollection = X509Certificate2UI.SelectFromCollection(fcollection, "Test Certificate Select", "Select a certificate from the following list to get information on that certificate", X509SelectionFlag.SingleSelection);
        Console.WriteLine("Number of certificates: {0}{1}", scollection.Count, Environment.NewLine);

        foreach (X509Certificate2 x509 in scollection)
        {
            try
            {
                byte[] rawdata = x509.RawData;
                Console.WriteLine("Content Type: {0}{1}", X509Certificate2.GetCertContentType(rawdata), Environment.NewLine);
                Console.WriteLine("Friendly Name: {0}{1}", x509.FriendlyName, Environment.NewLine);
                Console.WriteLine("Certificate Verified?: {0}{1}", x509.Verify(), Environment.NewLine);
                Console.WriteLine("Simple Name: {0}{1}", x509.GetNameInfo(X509NameType.SimpleName, false), Environment.NewLine);
                Console.WriteLine("Signature Algorithm: {0}{1}", x509.SignatureAlgorithm.FriendlyName, Environment.NewLine);
                Console.WriteLine("Public Key: {0}{1}", x509.GetRSAPublicKey().ToXmlString(false), Environment.NewLine);
                Console.WriteLine("Has Private Key: {0}{1}", x509.HasPrivateKey, Environment.NewLine);
                Console.WriteLine("Certificate Archived?: {0}{1}", x509.Archived, Environment.NewLine);
                Console.WriteLine("Length of Raw Data: {0}{1}", x509.RawData.Length, Environment.NewLine);
                x509.Reset();
            }
            catch (CryptographicException)
            {
                Console.WriteLine("Information could not be written out for this certificate.");
                throw;
            }
        }
        store.Close();
    }
}