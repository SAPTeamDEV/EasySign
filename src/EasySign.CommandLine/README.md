# EasySign Command Line Helper

[![Gawe CI](https://github.com/SAPTeamDEV/EasySign/actions/workflows/main.yml/badge.svg?event=push)](https://github.com/SAPTeamDEV/EasySign/actions/workflows/main.yml)
[![CodeQL](https://github.com/SAPTeamDEV/EasySign/actions/workflows/codeql.yml/badge.svg?event=push)](https://github.com/SAPTeamDEV/EasySign/actions/workflows/codeql.yml)
[![NuGet Package Version](https://img.shields.io/nuget/v/SAPTeam.EasySign.CommandLine)](https://www.nuget.org/packages/SAPTeam.EasySign.CommandLine)
[![NuGet Total Downloads](https://img.shields.io/nuget/dt/SAPTeam.EasySign.CommandLine)](https://www.nuget.org/packages/SAPTeam.EasySign.CommandLine)

Easy Sign Command Line Helper is a library that provides an API for creating console applications using the EasySign library. It supports multiple .NET targets, including .NET 6, .NET 8, and .NET 9.

## Features

- **File Signing**: Digitally sign files using X.509 certificates without modifying the original files by storing signatures in a bundle.
- **File Verification**: Verify the integrity and signatures of files using a bundle.
- **Easy Certificate Usage**: Retrieve and use certificates from PFX files or the current user's certificate store.
- **Argument Parsing**: Uses `System.CommandLine` for parsing command line arguments.
- **Command Line Interface**: Provides standard commands for adding files to a bundle, signing and verifying bundles.
- **Customizable**: Easily extendable to add custom commands or modify existing ones.
- **AOT Support**: Compatible with Ahead-of-Time (AOT) compilation for better performance.
- **Cross-Platform**: Compatible with Windows, Linux, and macOS.
- **Logging**: Integrated logging support for better debugging and monitoring.

## Installation

To install the EasySign Command Line Helper library, run the following command:


```
dotnet add package SAPTeam.EasySign.CommandLine


```

## Getting Started

### Implementing a Command Provider

The `ExampleCommandProvider` class demonstrates how to implement a command provider for the EasySign Bundle. It initializes the bundle and provides the root command for the console application.

The CommandProvider is Designed to be flexible and extensible, allowing you to use custom `Bundle` implementations or add additional commands as needed.

```
public class ExampleCommandProvider : CommandProvider<Bundle>
{
    public ExampleCommandProvider(ILogger logger)
    {
        Logger = logger;
    }

    public override void InitializeBundle(string bundlePath)
    {
        Logger.LogInformation("Initializing bundle at {bundlePath}", bundlePath);
        Bundle = new Bundle(bundlePath, Logger);
    }

    public override RootCommand GetRootCommand()
    {
        RootCommand root = new RootCommand("Easy Digital Signing Tool")
        {
            Add,
            Sign,
            Verify
        };

        return root;
    }
}
```

### Creating the Console Application

The `Program` class demonstrates how to create a console application using the `ExampleCommandProvider`. It sets up the command line parser, initializes the bundle, and executes the commands automatically.

```
public class Program
{
    public static int Main(string[] args)
    {
        // Create a logger, if you don't want to use logger, pass NullLogger.Instance to the command provider.
        var loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.AddConsole();
            builder.SetMinimumLevel(LogLevel.Information);
        });
        var logger = loggerFactory.CreateLogger<Program>();

        // Create a command provider
        var commandProvider = new ExampleCommandProvider(logger);
        var rootCommand = commandProvider.GetRootCommand();

        // Parse the incoming args and invoke the handler
        return rootCommand.Invoke(args);
    }
}
```

## Commands

Currently, the following commands are available:

### `add`

Creates a new bundle or updates an existing one by adding files from the specified directory.


```
esign add <bundle> [--replace] [--continue]
```

- `bundle`: The path or directory containing the bundle. If the bundle name is not specified, a default name will be used.
- `--replace` or `-r`: (Optional) Replace existing entries.
- `--continue` or `-c`: (Optional) Continue adding files if an error occurs.

### `sign`

Signs the bundle with a specified certificate.


```
esign sign <bundle> [--pfx <pfxFilePath>] [--pfx-password <pfxFilePassword>] [--no-password]
```

- `bundle`: The path or directory containing the bundle to be signed. If the bundle name is not specified, a default name will be used.
- `--pfx`: (Optional) The path to the PFX file containing the certificate and private key.
- `--pfx-password`: (Optional) The password for the PFX file.
- `--no-password`: (Optional) Ignore the PFX file password prompt.

### `verify`

Verifies the file integrity and signatures of the bundle.


```
esign verify <bundle>
```

- `bundle`: The path or directory containing the bundle to be verified. If the bundle name is not specified, a default name will be used.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.
