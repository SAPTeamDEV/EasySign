# Easy Sign

Easy Sign is a simple C# library for signing and verifying files. It supports multiple .NET targets, including .NET Standard 2.1, .NET 6, and .NET 8.

## Features

- Sign files with X.509 certificates.
- Verify file integrity and signatures.
- Store files within the bundle.
- Support for concurrent operations.
- AOT compilation support.
- Logging support.

## Installation

To install Easy Sign, run the following command:


```
dotnet add package SAPTeam.EasySign

```

## Usage

### Creating a Bundle


```
using SAPTeam.EasySign;

// Initialize a new bundle
var bundle = new Bundle("path/to/dir");

// Add files to the bundle
bundle.AddEntry("path/to/dir/file1.txt");
bundle.AddEntry("path/to/dir/file2.txt");

// Sign the bundle
var certificate = new X509Certificate2("path/to/certificate.pfx", "password");
var privateKey = certificate.GetRSAPrivateKey();
bundle.Sign(certificate, privateKey);

// Save the bundle
bundle.Update();

```

### Loading and Verifying a Bundle


```
using SAPTeam.EasySign;

// Load an existing bundle
var bundle = new Bundle("path/to/dir");
bundle.LoadFromFile();

// Get certificate hash
string certificateHash = bundle.Signatures.Entries.First().Key;

// Verify certificate
bool isCertificateValid = bundle.VerifyCertificate(certificateHash);

// Verify signature
bool isSignatureValid = bundle.VerifySignature(certificateHash);

// Verify files integrity
bool isFileValid = bundle.VerifyFileIntegrity("file1.txt");
bool isFile2Valid = bundle.VerifyFileIntegrity("file2.txt");

```

## Command Line Interface

Easy Sign also provides a command line interface (CLI) for signing and verifying files. To install the CLI tool, use the following command:


```
dotnet tool install -g SAPTeam.EasySign.Tool

```

For more informations, see the [CLI Readme](https://github.com/SAPTeamDEV/EasySign/blob/master/src/EasySign.Cli/README.md).


## License

This project is licensed under the MIT License.
