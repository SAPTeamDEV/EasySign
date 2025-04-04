# Use the official devcontainer .NET 8 image
FROM mcr.microsoft.com/vscode/devcontainers/dotnet:9.0

LABEL org.opencontainers.image.source https://github.com/SAPTeamDEV/EasySign
LABEL org.opencontainers.image.title "EasyDev"
LABEL org.opencontainers.image.description ".NET Development Container"
LABEL org.opencontainers.image.vendor "SAPTeamDEV"
LABEL org.opencontainers.image.licenses MIT

# Install additional apt packages
RUN apt-get update && apt-get install -y \
    git \
    curl \
    clang \
	zlib1g-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Setup Doxygen 1.12
RUN mkdir /tmp/doxygen \
    && cd /tmp/doxygen \
    && wget -q https://www.doxygen.nl/files/doxygen-1.12.0.linux.bin.tar.gz \
    && tar xf doxygen-1.12.0.linux.bin.tar.gz --strip-components=1 \
    && make install

ENV PATH="/usr/share/dotnet:${PATH}"
