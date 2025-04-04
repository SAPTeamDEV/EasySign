# EasySign Project

Welcome to the EasySign project! EasySign is a comprehensive suite of tools and libraries designed to simplify the process of signing and verifying files using X.509 certificates. Our project supports multiple .NET targets, including .NET Standard 2.1, .NET 6, .NET 8, and .NET 9, ensuring compatibility across a wide range of applications.

## Overview

EasySign consists of three main components:

1. **EasySign Library**: A C# library for signing and verifying files.
2. **EasySign Command-Line Helper**: A helper library for creating console applications using EasySign.
3. **EasySign CLI**: A command-line interface tool for signing and verifying files.

## Features

- **Sign Files**: Sign files with X.509 certificates without modifying the original files.
- **Verify Files**: Verify file integrity and signatures.
- **Bundle Management**: Create and manage file bundles.
- **Concurrent Operations**: Support for concurrent operations for faster processing.
- **AOT Compilation**: Ahead-of-time compilation support.
- **Logging**: Integrated logging support.

## Installation

### EasySign Library

To install the EasySign library, run the following command:


```
dotnet add package SAPTeam.EasySign

```

### EasySign CLI

To install the EasySign CLI tool, use the following command:


```
dotnet tool install -g SAPTeam.EasySign.Tool

```

## Usage

### EasySign Library

#### Creating a Bundle


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

#### Loading and Verifying a Bundle


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
bool isFileValid = bundle.VerifyFile("file1.txt");
bool isFile2Valid = bundle.VerifyFile("file2.txt");

```

### EasySign CLI

#### Adding Files to a Bundle


```
esign add /path/to/dir

```

#### Signing a Bundle


```
esign sign /path/to/dir --pfx /path/to/certificate.pfx --pfx-password mypassword

```

#### Verifying a Bundle


```
esign verify /path/to/dir

```

## Security Vulnerability Reporting

If you discover any security vulnerabilities, please report them by following our guidelines [Security Guidelines](SECURITY.md).

## Contributing

We welcome contributions! Please see our [Contributing](CONTRIBUTING.md) guide for more information on how to get started.

## License

This project is licensed under the MIT License. See the [LICENSE.md](LICENSE) file for more details.

Thank you for using EasySign!
