# Easy Sign

[![Gawe CI](https://github.com/SAPTeamDEV/EasySign/actions/workflows/main.yml/badge.svg?event=push)](https://github.com/SAPTeamDEV/EasySign/actions/workflows/main.yml)
[![CodeQL](https://github.com/SAPTeamDEV/EasySign/actions/workflows/codeql.yml/badge.svg?event=push)](https://github.com/SAPTeamDEV/EasySign/actions/workflows/codeql.yml)
[![NuGet Package Version](https://img.shields.io/nuget/v/SAPTeam.EasySign)](https://www.nuget.org/packages/SAPTeam.EasySign)
[![NuGet Total Downloads](https://img.shields.io/nuget/dt/SAPTeam.EasySign)](https://www.nuget.org/packages/SAPTeam.EasySign)

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
bool isFileValid = bundle.VerifyFile("file1.txt");
bool isFile2Valid = bundle.VerifyFile("file2.txt");

```

## Documentation

A full API Documentation is available at [EasySign Project Site](https://sapteamdev.github.io/EasySign).

## Command Line Interface

Easy Sign also provides a command line interface (CLI) for signing and verifying files. To install the CLI tool, use the following command:


```
dotnet tool install -g SAPTeam.EasySign.Tool

```

For more informations, see the [CLI Readme](https://github.com/SAPTeamDEV/EasySign/blob/master/src/EasySign.Cli/README.md).


## Security Reporting

If you discover any security vulnerabilities, please report them by following our [Security Guidelines](https://github.com/SAPTeamDEV/EasySign/blob/master/SECURITY.md).

## Contributing

We welcome contributions! Please see our [Contributing guide](https://github.com/SAPTeamDEV/EasySign/blob/master/CONTRIBUTING.md) for more information on how to get started.

## License

This project is licensed under the [MIT License](https://github.com/SAPTeamDEV/EasySign/blob/master/LICENSE.md).
