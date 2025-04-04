# EasySign .NET Development Container

This repository contains the Dockerfile for the EasySign .NET Development Container. The container is based on the official Visual Studio Code Dev Containers image for .NET 9.0 and is pre-configured for EasySign build requirements.

## Features

- **Base Image**: Uses the official `mcr.microsoft.com/vscode/devcontainers/dotnet:9.0` image.
- **Pre-installed Tools**:
    - `git`
    - `curl`
    - `clang`
    - `zlib1g-dev`
- **Doxygen 1.12**: Pre-installed for generating documentation.

## Usage

To use this container, you can build it locally or pull it from a container registry. Below is an example of how to build and run the container:

### Build the Image

```bash
docker build -t easydev build/docker
```

### Pull the Container

```bash
docker pull ghcr.io/sapteamdev/easydev:master
```

### Use as base image

```
FROM ghcr.io/sapteamdev/easydev:master
```

## Environment Variables

- `PATH`: The container automatically includes `/usr/share/dotnet` in the `PATH`.

## Additional Notes

- The container is optimized for .NET development and includes tools for building and documenting .NET applications.
- Doxygen 1.12 is installed for generating project documentation.

For more details, visit the [EasySign GitHub Repository](https://github.com/SAPTeamDEV/EasySign).  