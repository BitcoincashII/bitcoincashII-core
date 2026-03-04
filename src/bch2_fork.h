// Copyright (c) 2025 BCH2 Developers
// Distributed under the MIT software license
// BCH2 Fork from BC2 - Network Parameters

#ifndef BITCOINII_BCH2_FORK_H
#define BITCOINII_BCH2_FORK_H

#include <cstdint>

namespace BCH2 {

//
// Fork Configuration
//

// BC2 blocks 0 to FORK_HEIGHT are preserved with SegWit
// BCH consensus rules activate at FORK_HEIGHT + 1
static constexpr int FORK_HEIGHT = 53200;

// Network identification
static constexpr unsigned char MAGIC[4] = {0xb2, 0xc2, 0xb2, 0xc2};
static constexpr int P2P_PORT = 8339;
static constexpr int RPC_PORT = 8342;

//
// BCH Consensus Rules (activate at FORK_HEIGHT + 1)
//

// Block size: 32MB (BCH standard) — matches BCH2_MAX_BLOCK_SIZE in consensus.h
static constexpr uint64_t MAX_BLOCK_SIZE = 32000000;

// SIGHASH_FORKID for replay protection
static constexpr uint32_t SIGHASH_FORKID = 0x40;
static constexpr uint32_t FORKID = 0;

//
// Helper Functions
//

// Is BCH2 fork active at this height?
inline bool IsForkActive(int height) {
    return height > FORK_HEIGHT;
}

// Is SegWit allowed at this height?
// YES for historical BC2 blocks, NO after fork
inline bool IsSegWitAllowed(int height) {
    return height <= FORK_HEIGHT;
}

// Get max block size for height
inline uint64_t GetMaxBlockSize(int height) {
    if (IsForkActive(height)) {
        return MAX_BLOCK_SIZE;  // 32MB
    }
    return 4 * 1024 * 1024;  // 4MB (BC2/BTC limit)
}

} // namespace BCH2

#endif // BITCOINII_BCH2_FORK_H
