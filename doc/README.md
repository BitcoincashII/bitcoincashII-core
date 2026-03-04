Bitcoin Cash II Core
=============

Setup
---------------------
Bitcoin Cash II Core is a fork of Bitcoin II (BC2) that activates Bitcoin Cash consensus rules. It downloads and stores the blockchain, which requires several gigabytes of disk space. Depending on the speed of your computer and network connection, the synchronization process can take anywhere from a few hours to a day or more.

To download Bitcoin Cash II Core, visit the [GitHub Releases](https://github.com/BitcoincashII/bitcoincashII-core/releases) page.

Running
---------------------
The following are some helpful notes on how to run Bitcoin Cash II Core on your native platform.

### Unix

Unpack the files into a directory and run:

- `bin/bitcoincashII-qt` (GUI) or
- `bin/bitcoincashIId` (headless)

### Windows

Unpack the files into a directory, and then run bitcoincashII-qt.exe.

### macOS

Drag Bitcoin Cash II to your applications folder, and then run Bitcoin Cash II.

### Need Help?

* Join the BCH2 community on [Discord](https://discord.gg/bch2)
* Ask for help on the [GitHub Discussions](https://github.com/BitcoincashII/bitcoincashII-core/discussions)

Building
---------------------
The following are developer notes on how to build Bitcoin Cash II Core on your native platform. They are not complete guides, but include notes on the necessary libraries, compile flags, etc.

- [Dependencies](dependencies.md)
- [macOS Build Notes](build-osx.md)
- [Unix Build Notes](build-unix.md)
- [Windows Build Notes](build-windows.md)
- [FreeBSD Build Notes](build-freebsd.md)
- [OpenBSD Build Notes](build-openbsd.md)
- [NetBSD Build Notes](build-netbsd.md)
- [Android Build Notes](build-android.md)

Development
---------------------
The [root README](/README.md) contains relevant information on the development process and automated testing.

- [Developer Notes](developer-notes.md)
- [Productivity Notes](productivity.md)
- [Release Process](release-process.md)
- [Translation Process](translation_process.md)
- [Translation Strings Policy](translation_strings_policy.md)
- [JSON-RPC Interface](JSON-RPC-interface.md)
- [Unauthenticated REST Interface](REST-interface.md)
- [Shared Libraries](shared-libraries.md)
- [BIPS](bips.md)
- [Dnsseed Policy](dnsseed-policy.md)
- [Benchmarking](benchmarking.md)
- [Internal Design Docs](design/)

### Resources
* Join the BCH2 community on [Discord](https://discord.gg/bch2)
* Open issues or discussions on [GitHub](https://github.com/BitcoincashII/bitcoincashII-core)

### Miscellaneous
- [Assets Attribution](assets-attribution.md)
- [bitcoincashII.conf Configuration File](bitcoin-conf.md)
- [CJDNS Support](cjdns.md)
- [Files](files.md)
- [Fuzz-testing](fuzzing.md)
- [I2P Support](i2p.md)
- [Init Scripts (systemd/upstart/openrc)](init.md)
- [Managing Wallets](managing-wallets.md)
- [Multisig Tutorial](multisig-tutorial.md)
- [Offline Signing Tutorial](offline-signing-tutorial.md)
- [P2P bad ports definition and list](p2p-bad-ports.md)
- [PSBT support](psbt.md)
- [Reduce Memory](reduce-memory.md)
- [Reduce Traffic](reduce-traffic.md)
- [Tor Support](tor.md)
- [Transaction Relay Policy](policy/README.md)
- [ZMQ](zmq.md)

License
---------------------
Distributed under the [MIT software license](/COPYING).
