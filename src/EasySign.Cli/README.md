# Easy Sign Command Line Interface

Easy Sign CLI is a simple .NET tool for signing and verifying files. It supports multiple .NET targets, including .NET 6, .NET 8, and .NET 9.

## Features

- Create and update eSign bundles.
- Sign bundles with X.509 certificates.
- Verify file integrity and signatures within bundles.
- Support for concurrent operations.
- Ahead-of-time (AOT) compilation support.
- Integrated logging support.

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
esign add <bundle> [--replace] [--continue]

```

- `bundle`: The path or directory containing the bundle. If the bundle name is not specified, a default name will be used.
- `--replace` or `-r`: (Optional) Replace existing entries.
- `--continue` or `-c`: (Optional) Continue adding files if an error occurs.

#### `sign`

Signs the bundle with a specified certificate.


```
esign sign <bundle> [--pfx <pfxFilePath>] [--pfx-password <pfxFilePassword>] [--no-password]

```

- `bundle`: The path or directory containing the bundle to be signed. If the bundle name is not specified, a default name will be used.
- `--pfx`: (Optional) The path to the PFX file containing the certificate and private key.
- `--pfx-password`: (Optional) The password for the PFX file.
- `--no-password`: (Optional) Ignore the PFX file password prompt.

#### `verify`

Verifies the file integrity and signatures of the bundle.


```
esign verify <bundle>

```

- `bundle`: The path or directory containing the bundle to be verified. If the bundle name is not specified, a default name will be used.

## Examples

### Adding Files to a Bundle

If there is no bundle file in the directory, a new bundle will be created. Otherwise, the files will be added to the existing bundle.


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
