# Bitcoin Cash II (BCH2) Core

**Version 27.0.0** | Fork Height: 53,200 | P2P Port: 8339 | RPC Port: 8342

Bitcoin Cash II (BCH2) is a SHA-256 cryptocurrency that forks from Bitcoin II (BC2) at block 53,200, activating all Bitcoin Cash consensus rules including 32MB blocks, ASERT difficulty adjustment, and CashAddr addressing.

---

## Table of Contents

1. [Features](#features)
2. [System Requirements](#system-requirements)
3. [Download Pre-built Binaries](#download-pre-built-binaries)
4. [Building from Source](#building-from-source)
   - [Ubuntu/Debian](#ubuntudebian-2004-2204-2404)
   - [Fedora/CentOS](#fedoracentosrhel)
   - [Arch Linux](#arch-linux)
   - [macOS](#macos)
   - [Windows (Cross-compile)](#windows-cross-compile-from-linux)
5. [Running BCH2](#running-bch2)
6. [Configuration](#configuration)
7. [Mining](#mining)
8. [RPC Commands](#rpc-commands)
9. [Network Information](#network-information)
10. [License](#license)

---

## Features

| Feature | Value |
|---------|-------|
| Block Size | 32 MB (post-fork) |
| Block Time | 10 minutes |
| Difficulty Adjustment | ASERT (aserti3-2d) |
| Address Format | CashAddr (`bitcoincashii:q...`) |
| SegWit | Disabled (post-fork) |
| Replace-by-Fee | Disabled |
| Replay Protection | SIGHASH_FORKID (0x41) |
| Coin Symbol | BCH2 |

---

## System Requirements

### Minimum Requirements
- **CPU**: 2 cores
- **RAM**: 4 GB
- **Disk**: 20 GB SSD
- **Network**: 10 Mbps

### Recommended Requirements
- **CPU**: 4+ cores
- **RAM**: 8+ GB
- **Disk**: 50+ GB SSD
- **Network**: 100+ Mbps

---

## Download Pre-built Binaries

Download the latest release from: https://github.com/BitcoincashII/bitcoincashII-core/releases

---

## Building from Source

### Ubuntu/Debian (20.04, 22.04, 24.04)

#### Step 1: Update System

```bash
sudo apt update
sudo apt upgrade -y
```

#### Step 2: Install Build Dependencies

```bash
sudo apt install -y \
    build-essential \
    libtool \
    autotools-dev \
    automake \
    pkg-config \
    bsdmainutils \
    python3 \
    libevent-dev \
    libboost-dev \
    libsqlite3-dev \
    libminiupnpc-dev \
    libnatpmp-dev \
    libzmq3-dev \
    systemtap-sdt-dev \
    libqrencode-dev \
    libdb-dev \
    libdb++-dev \
    git
```

#### Step 3: Clone the Repository

```bash
cd ~
git clone https://github.com/BitcoincashII/bitcoincashII-core.git
cd bitcoincashII-core
```

#### Step 4: Run Autogen

```bash
./autogen.sh
```

**Expected output:**
```
libtoolize: putting auxiliary files in AC_CONFIG_AUX_DIR, 'build-aux'.
libtoolize: copying file 'build-aux/ltmain.sh'
...
configure.ac:30: installing 'build-aux/missing'
src/Makefile.am: installing 'build-aux/depcomp'
```

#### Step 5: Create Build Directory

```bash
mkdir -p build
cd build
```

#### Step 6: Configure the Build

**For daemon only (no GUI):**
```bash
../configure --without-gui --disable-tests --disable-bench
```

**For daemon + Qt GUI:**
```bash
# Install Qt dependencies first
sudo apt install -y qtbase5-dev qttools5-dev qttools5-dev-tools

# Then configure
../configure
```

**For daemon + all features:**
```bash
../configure --with-gui=qt5 --enable-wallet
```

**Expected output (end of configure):**
```
Options used to compile and link:
  external signer = yes
  multiprocess    = no
  with wallet     = yes
    with sqlite   = yes
    with bdb      = yes
  with gui / qt   = no
  with zmq        = yes
  with usdt       = yes
  with libs       = yes
  werror          = no

  target os       = linux
  build os        = linux-gnu

  CC              = gcc
  CFLAGS          = -g -O2
  CXX             = g++ -std=c++20
  ...
```

#### Step 7: Compile

```bash
make -j$(nproc)
```

This uses all available CPU cores. On a 4-core machine, expect 10-20 minutes.

**Expected output (end of make):**
```
  CXXLD    bitcoincashII-cli
  CXXLD    bitcoincashII-tx
  CXXLD    bitcoincashII-util
  CXXLD    bitcoincashII-wallet
  CXXLD    bitcoincashIId
```

> **Tip:** For production deployment, strip debug symbols to reduce binary size by ~90%:
> ```bash
> strip src/bitcoincashIId src/bitcoincashII-cli src/bitcoincashII-tx src/bitcoincashII-wallet
> ```

#### Step 8: Install (Optional)

```bash
sudo make install
```

This installs binaries to `/usr/local/bin/`.

#### Step 9: Verify Installation

```bash
./src/bitcoincashIId --version
```

**Expected output:**
```
Bitcoin Cash II version v27.0.0
Copyright (C) 2009-2025 The Bitcoin Cash II developers
...
```

---

### Fedora/CentOS/RHEL

#### Step 1: Install Dependencies

**Fedora:**
```bash
sudo dnf install -y \
    gcc-c++ \
    libtool \
    make \
    autoconf \
    automake \
    python3 \
    libevent-devel \
    boost-devel \
    libdb-devel \
    libdb-cxx-devel \
    sqlite-devel \
    miniupnpc-devel \
    zeromq-devel \
    qrencode-devel \
    git
```

**CentOS/RHEL 8+:**
```bash
sudo dnf install -y epel-release
sudo dnf install -y \
    gcc-c++ \
    libtool \
    make \
    autoconf \
    automake \
    python3 \
    libevent-devel \
    boost-devel \
    libdb-devel \
    libdb-cxx-devel \
    sqlite-devel \
    miniupnpc-devel \
    zeromq-devel \
    git
```

#### Step 2: Clone and Build

```bash
git clone https://github.com/BitcoincashII/bitcoincashII-core.git
cd bitcoincashII-core
./autogen.sh
mkdir build && cd build
../configure --without-gui
make -j$(nproc)
```

---

### Arch Linux

#### Step 1: Install Dependencies

```bash
sudo pacman -S --needed \
    base-devel \
    boost \
    libevent \
    sqlite \
    miniupnpc \
    libnatpmp \
    zeromq \
    qrencode \
    db \
    git
```

#### Step 2: Clone and Build

```bash
git clone https://github.com/BitcoincashII/bitcoincashII-core.git
cd bitcoincashII-core
./autogen.sh
mkdir build && cd build
../configure --without-gui
make -j$(nproc)
```

---

### macOS

#### Step 1: Install Xcode Command Line Tools

```bash
xcode-select --install
```

#### Step 2: Install Homebrew (if not installed)

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

#### Step 3: Install Dependencies

```bash
brew install \
    automake \
    libtool \
    boost \
    pkg-config \
    libevent \
    sqlite \
    miniupnpc \
    libnatpmp \
    zeromq \
    qrencode \
    berkeley-db@4
```

#### Step 4: Clone and Build

```bash
git clone https://github.com/BitcoincashII/bitcoincashII-core.git
cd bitcoincashII-core
./autogen.sh
mkdir build && cd build
../configure --without-gui --with-boost=$(brew --prefix boost)
make -j$(sysctl -n hw.ncpu)
```

---

### Windows (Cross-compile from Linux)

#### Step 1: Install Cross-compilation Tools (Ubuntu)

```bash
sudo apt install -y \
    g++-mingw-w64-x86-64-posix \
    mingw-w64-x86-64-dev \
    nsis
```

#### Step 2: Build Dependencies

```bash
cd depends
make HOST=x86_64-w64-mingw32 -j$(nproc)
cd ..
```

#### Step 3: Configure and Build

```bash
./autogen.sh
mkdir build && cd build
../configure --prefix=$PWD/../depends/x86_64-w64-mingw32 --without-gui
make -j$(nproc)
```

The Windows executables will be in `src/` with `.exe` extensions.

---

## Running BCH2

### Start the Daemon

```bash
# Start in foreground
./bitcoincashIId

# Start in background (daemon mode)
./bitcoincashIId -daemon

# Start with specific data directory
./bitcoincashIId -datadir=/path/to/data
```

### Stop the Daemon

```bash
./bitcoincashII-cli stop
```

### Check Sync Status

```bash
./bitcoincashII-cli getblockchaininfo
```

### Check Peer Connections

```bash
./bitcoincashII-cli getpeerinfo
```

---

## Configuration

Create a configuration file at `~/.bitcoincashII/bitcoincashII.conf`:

```ini
# Network
listen=1
maxconnections=125

# RPC
server=1
rpcuser=yourusername
rpcpassword=yourpassword
rpcallowip=127.0.0.1

# Performance
dbcache=450
maxmempool=300

# Optional: Prune old blocks (saves disk space)
# prune=10000
```

### Data Directory Locations

| OS | Default Location |
|----|------------------|
| Linux | `~/.bitcoincashII/` |
| macOS | `~/Library/Application Support/BitcoinCashII/` |
| Windows | `%APPDATA%\BitcoinCashII\` |

---

## Mining

### Solo Mining

Add to your `bitcoincashII.conf`:

```ini
# Mining address (CashAddr format)
miningaddress=bitcoincashii:qp...youraddress...

# Generate blocks (testnet/regtest only)
# gen=1
```

### Pool Mining

BCH2 uses SHA-256d and is compatible with standard Bitcoin mining pools. Configure your miner to connect to a BCH2 mining pool with:

- **Algorithm**: SHA-256d
- **Port**: Pool-specific
- **Stratum**: Standard stratum protocol

### GetBlockTemplate (for pools)

```bash
./bitcoincashII-cli getblocktemplate '{"rules": []}'
```

---

## RPC Commands

### Blockchain

```bash
# Get blockchain info
./bitcoincashII-cli getblockchaininfo

# Get block count
./bitcoincashII-cli getblockcount

# Get block hash
./bitcoincashII-cli getblockhash 1000

# Get block details
./bitcoincashII-cli getblock "blockhash"
```

### Wallet

```bash
# Create new wallet
./bitcoincashII-cli createwallet "mywallet"

# Get new address
./bitcoincashII-cli getnewaddress

# Get balance
./bitcoincashII-cli getbalance

# Send coins
./bitcoincashII-cli sendtoaddress "bitcoincashii:qp..." 1.0

# List transactions
./bitcoincashII-cli listtransactions
```

### Network

```bash
# Get network info
./bitcoincashII-cli getnetworkinfo

# Get peer info
./bitcoincashII-cli getpeerinfo

# Add node manually
./bitcoincashII-cli addnode "ip:8339" "add"
```

---

## Network Information

### Mainnet

| Parameter | Value |
|-----------|-------|
| P2P Port | 8339 |
| RPC Port | 8342 |
| Network Magic | 0xb2c2b2c2 |
| Address Prefix | `bitcoincashii:q...` (P2PKH) |
| Address Prefix | `bitcoincashii:p...` (P2SH) |

### Testnet

| Parameter | Value |
|-----------|-------|
| P2P Port | 18338 |
| RPC Port | 18332 |

### DNS Seeds

- `dnsseed1.bch2.org`
- `dnsseed2.bch2.org`

### Bootstrap Nodes

```
144.202.73.66:8339    (Dallas, USA)
108.61.190.83:8339    (Frankfurt, Germany)
64.176.215.202:8339   (New Jersey, USA)
45.32.138.29:8339     (Silicon Valley, USA)
139.180.132.24:8339   (Singapore)
```

---

## Troubleshooting

### "Cannot obtain a lock on data directory"

Another instance is running. Stop it first:
```bash
./bitcoincashII-cli stop
```

Or kill the process:
```bash
pkill bitcoincashIId
```

### "Error loading block database"

Corrupted database. Re-sync:
```bash
./bitcoincashIId -reindex
```

### Build Error: "boost not found"

Install boost:
```bash
# Ubuntu/Debian
sudo apt install libboost-dev

# Fedora
sudo dnf install boost-devel

# macOS
brew install boost
```

### Build Error: "libevent not found"

Install libevent:
```bash
# Ubuntu/Debian
sudo apt install libevent-dev

# Fedora
sudo dnf install libevent-devel

# macOS
brew install libevent
```

---

## Credits

BCH2 is a fork of [Bitcoin II](https://github.com/BitcoinII-Dev/BitcoinII), which is a fork of [Bitcoin Core](https://github.com/bitcoin/bitcoin).

See [AUTHORS](AUTHORS) for the list of contributors.

---

## License

Bitcoin Cash II Core is released under the terms of the MIT license. See [COPYING](COPYING) for more information.

---

## Links

- **Website**: https://bch2.org
- **GitHub**: https://github.com/BitcoincashII
- **Block Explorer**: https://explorer.bch2.org
