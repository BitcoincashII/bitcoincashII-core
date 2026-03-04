// Copyright (c) 2025 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// This file provides a main entry point for bch2-seeder
// The actual implementation is in libbitcoinII_seeder.a

extern int seeder_main(int argc, char* argv[]);

int main(int argc, char* argv[]) {
    return seeder_main(argc, argv);
}
