# Installing Idris 2 for Core-Idris

Core-Idris requires Idris 2 version 0.6.0 or later.

## Quick Install (Debian/Ubuntu)

```bash
# Install dependencies
sudo apt-get update
sudo apt-get install -y build-essential libgmp-dev libsodium-dev pkg-config

# Install Idris 2 from binary release
wget https://github.com/idris-lang/Idris2/releases/download/v0.7.0/idris2-0.7.0-x86_64.deb
sudo dpkg -i idris2-0.7.0-x86_64.deb
```

## Build from Source (Any Linux)

```bash
# Install dependencies
sudo apt-get install -y build-essential chezscheme libgmp-dev libsodium-dev

# Clone and build
git clone https://github.com/idris-lang/Idris2.git
cd Idris2
git checkout v0.7.0
make bootstrap SCHEME=chezscheme
make install

# Verify
idris2 --version
```

## macOS

```bash
brew install idris2 libsodium
```

## Alternative: Use Mock Build

For CI/testing without Idris 2, use the mock build:

```bash
cd Core-Idris
./create-mock-binary.sh
./shadow6-idris --feature-report
```

This creates a shell script wrapper that emits the correct feature report
for contract validation.
