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

CI and release verification must use a real Idris 2 compiler and the native
`shadow6-idris` executable. If Idris 2 is unavailable, the build is reported
as unavailable and the job fails; a generated wrapper is not an acceptable
substitute for feature or transport validation.
