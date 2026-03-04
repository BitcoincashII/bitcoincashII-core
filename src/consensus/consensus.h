// Copyright (c) 2009-2025 Satoshi Nakamoto
// Copyright (c) 2009-2024 The Bitcoin Core developers
// Copyright (c) 2024-2025 The BitcoinII developers
// Copyright (c) 2025 The Bitcoin Cash II developers
// Forked from Bitcoin Core version 0.27.0
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOINII_CONSENSUS_CONSENSUS_H
#define BITCOINII_CONSENSUS_CONSENSUS_H

#include <cstdlib>
#include <stdint.h>

static const unsigned int BCH2_MAX_BLOCK_SIZE = 32000000;
static const unsigned int BCH2_LEGACY_MAX_BLOCK_SIZE = 4000000;

/** Default consensus block size for ABLA initialization (32MB) */
inline constexpr uint64_t DEFAULT_CONSENSUS_BLOCK_SIZE = 32000000;
/** Maximum consensus block size (2GB) — ABLA hard cap */
inline constexpr uint64_t MAX_CONSENSUS_BLOCK_SIZE = 2'000'000'000;

/** The maximum allowed size for a serialized block, in bytes (only for buffer size limits) */
static const unsigned int MAX_BLOCK_SERIALIZED_SIZE = BCH2_MAX_BLOCK_SIZE;
/** The maximum allowed weight for a block, see BIP 141 (network rule) */
static const unsigned int MAX_BLOCK_WEIGHT = BCH2_MAX_BLOCK_SIZE;
static const int64_t BCH2_MAX_BLOCK_SIGOPS_COST = 640000;
static const int64_t BCH2_LEGACY_MAX_BLOCK_SIGOPS_COST = 80000;
/** The maximum allowed number of signature check operations in a block (network rule) */
static const int64_t MAX_BLOCK_SIGOPS_COST = BCH2_MAX_BLOCK_SIGOPS_COST;
/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
static const int COINBASE_MATURITY = 100;

static const int WITNESS_SCALE_FACTOR = 1;

static const size_t MIN_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 60; // 60 is the lower bound for the size of a valid serialized CTransaction
static const size_t MIN_SERIALIZABLE_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 10; // 10 is the lower bound for the size of a serialized CTransaction

/** Flags for nSequence and nLockTime locks */
/** Interpret sequence numbers as relative lock-time constraints. */
static constexpr unsigned int LOCKTIME_VERIFY_SEQUENCE = (1 << 0);

#endif // BITCOINII_CONSENSUS_CONSENSUS_H
