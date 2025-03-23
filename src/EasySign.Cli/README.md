# Easy Sign Command Line Interface

Easy Sign CLI is a simple .NET tool for signing and verifying files. It supports multiple .NET targets, including .NET 6, .NET 8, and .NET 9.

## Features

- Create and update eSign bundles.
- Sign bundles with X.509 certificates.
- Verify file integrity and signatures within bundles.
- Support for concurrent operations.

## Installation

To install the Easy Sign CLI tool, use the following command:


```
dotnet tool install -g SAPTeam.EasySign.Tool

```

## Usage

### Commands

#### `add`

Creates a new bundle or updates an existing one by adding files from the specified directory.


```
esign add <directory> [-f <bundleFileName>]

```

- `directory`: The working directory containing the eSign bundle and files to be added to the bundle.
- `-f`: (Optional) The name of the bundle file. Default is `.eSign`.

#### `sign`

Signs the bundle with a specified certificate.


```
esign sign <directory> [-f <bundleFileName>] [--pfx <pfxFilePath>] [--pfx-password <pfxFilePassword>] [--no-password]

```

- `directory`: The working directory containing the bundle to be signed.
- `-f`: (Optional) The name of the bundle file. Default is `.eSign`.
- `--pfx`: (Optional) The path to the PFX file containing the certificate and private key.
- `--pfx-password`: (Optional) The password for the PFX file.
- `--no-password`: (Optional) Ignore the PFX file password prompt.

#### `verify`

Verifies the file integrity and signatures of the bundle.


```
esign verify <directory> [-f <bundleFileName>]

```

- `directory`: The working directory containing the bundle to be verified.
- `-f`: (Optional) The name of the bundle file. Default is `.eSign`.

## Examples

### Adding Files to a Bundle

if there is no bundle file in the directory, a new bundle will be created. Otherwise, the files will be added to the existing bundle.


```
esign add /path/to/dir

```

### Signing a Bundle


```
esign sign /path/to/dir --pfx /path/to/certificate.pfx --pfx-password mypassword

```

### Verifying a Bundle


```
esign verify /path/to/dir

```

## License

This project is licensed under the MIT License.
