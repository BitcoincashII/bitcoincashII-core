// Copyright (c) 2009-2025 Satoshi Nakamoto
// Copyright (c) 2009-2024 The Bitcoin Core developers
// Copyright (c) 2024-2025 The BitcoinII developers
// Copyright (c) 2025 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOINII_CONSENSUS_PARAMS_H
#define BITCOINII_CONSENSUS_PARAMS_H

#include <uint256.h>

#include <chrono>
#include <limits>
#include <map>
#include <optional>
#include <vector>

namespace Consensus {

/**
 * A buried deployment is one where the height of the activation has been hardcoded into
 * the client implementation long after the consensus change has activated. See BIP 90.
 */
enum BuriedDeployment : int16_t {
    // buried deployments get negative values to avoid overlap with DeploymentPos
    DEPLOYMENT_HEIGHTINCB = std::numeric_limits<int16_t>::min(),
    DEPLOYMENT_CLTV,
    DEPLOYMENT_DERSIG,
    DEPLOYMENT_CSV,
    DEPLOYMENT_SEGWIT,
};
constexpr bool ValidDeployment(BuriedDeployment dep) { return dep <= DEPLOYMENT_SEGWIT; }

enum DeploymentPos : uint16_t {
    DEPLOYMENT_TESTDUMMY,
    DEPLOYMENT_TAPROOT, // Deployment of Schnorr/Taproot (BIPs 340-342)
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in deploymentinfo.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};
constexpr bool ValidDeployment(DeploymentPos dep) { return dep < MAX_VERSION_BITS_DEPLOYMENTS; }

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit{28};
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime{NEVER_ACTIVE};
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout{NEVER_ACTIVE};
    /** If lock in occurs, delay activation until at least this block
     *  height.  Note that activation will only occur on a retarget
     *  boundary.
     */
    int min_activation_height{0};

    /** Constant for nTimeout very far in the future. */
    static constexpr int64_t NO_TIMEOUT = std::numeric_limits<int64_t>::max();

    /** Special value for nStartTime indicating that the deployment is always active.
     *  This is useful for testing, as it means tests don't need to deal with the activation
     *  process (which takes at least 3 BIP9 intervals). Only tests that specifically test the
     *  behaviour during activation cannot use this. */
    static constexpr int64_t ALWAYS_ACTIVE = -1;

    /** Special value for nStartTime indicating that the deployment is never active.
     *  This is useful for integrating the code changes for a new feature
     *  prior to deploying it on some or all networks. */
    static constexpr int64_t NEVER_ACTIVE = -2;
};

/**
 * ASERT anchor block parameters for aserti3-2d difficulty adjustment.
 *
 * The anchor block is the reference point for ASERT calculations.
 * All difficulty adjustments are computed relative to this anchor.
 */
struct ASERTAnchor {
    /** Height of the anchor block */
    int nHeight{-1};

    /** Compact difficulty target (nBits) of the anchor block */
    uint32_t nBits{0};

    /** Timestamp of the anchor block's PARENT (used for time delta calculation) */
    int64_t nPrevBlockTime{0};

    /** Check if anchor parameters are properly configured */
    bool IsValid() const {
        return nHeight >= 0 && nBits != 0 && nPrevBlockTime > 0;
    }
};

/** Special value indicating a fork/upgrade is not active (height set very high) */
static constexpr int NEVER_ACTIVE_HEIGHT = std::numeric_limits<int>::max();

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;
    /**
     * Hashes of blocks that
     * - are known to be consensus valid, and
     * - buried in the chain, and
     * - fail if the default script verify flags are applied.
     */
    std::map<uint256, uint32_t> script_flag_exceptions;

    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    uint256 BIP34Hash;
    /** Block height at which BIP65 becomes active */
    int BIP65Height;
    /** Block height at which BIP66 becomes active */
    int BIP66Height;
    /** Block height at which CSV (BIP68, BIP112 and BIP113) becomes active */
    int CSVHeight;
    /** Block height at which Segwit (BIP141, BIP143 and BIP147) becomes active.
     * Note that segwit v0 script rules are enforced on all blocks except the
     * BIP 16 exception blocks.
     * IMPORTANT: After BCH2 fork, SegWit is disabled regardless of this height. */
    int SegwitHeight;

    // =========================================================================
    // BCH2 Fork Parameters
    // =========================================================================

    /** BCH2 fork height - all BCH rules activate after this block.
     *  Set to NEVER_ACTIVE_HEIGHT to disable BCH2 fork. */
    int BCH2ForkHeight{NEVER_ACTIVE_HEIGHT};

    /** August 1, 2017 UAHF (User Activated Hard Fork) - original BCH fork
     *  - 8MB block size
     *  - No SegWit
     *  - SIGHASH_FORKID replay protection
     */
    int uahfHeight{NEVER_ACTIVE_HEIGHT};

    /** November 13, 2017 - New DAA (Difficulty Adjustment Algorithm)
     *  - Replaced Emergency DAA with better algorithm
     */
    int daaHeight{NEVER_ACTIVE_HEIGHT};

    /** November 15, 2018 - Magnetic Anomaly upgrade
     *  - CTOR (Canonical Transaction Ordering)
     *  - OP_CHECKDATASIG, OP_CHECKDATASIGVERIFY
     *  - Minimum transaction size 100 bytes
     *  - NULLDUMMY rule (clean stack)
     */
    int magneticAnomalyHeight{NEVER_ACTIVE_HEIGHT};

    /** November 15, 2019 - Graviton upgrade
     *  - Schnorr signatures for OP_CHECKSIG and OP_CHECKDATASIG
     *  - SegWit recovery (allow spending of SegWit-looking outputs)
     */
    int gravitonHeight{NEVER_ACTIVE_HEIGHT};

    /** May 15, 2020 - Phonon upgrade
     *  - OP_REVERSEBYTES
     *  - SigChecks (replace SigOps)
     */
    int phononHeight{NEVER_ACTIVE_HEIGHT};

    /** November 15, 2020 - Axion upgrade
     *  - ASERT DAA (aserti3-2d)
     *  Note: For BCH2, ASERT activates at BCH2ForkHeight, not by timestamp.
     */
    int axionHeight{NEVER_ACTIVE_HEIGHT};

    /** May 15, 2022 - Upgrade 8
     *  - Native introspection opcodes
     *  - Bigger integers (64-bit)
     */
    int upgrade8Height{NEVER_ACTIVE_HEIGHT};

    /** May 15, 2023 - Upgrade 9
     *  - CHIP limits increase
     *  - P2SH32 (32-byte hash P2SH)
     *  - CashTokens (CHIP-2022-02-CashTokens)
     */
    int upgrade9Height{NEVER_ACTIVE_HEIGHT};

    /** May 15, 2024 - Upgrade 10
     *  - VM Limits
     *  - BigInt math
     *  - ABLA (Adaptive Block Limit Algorithm) preparation
     */
    int upgrade10Height{NEVER_ACTIVE_HEIGHT};

    /** May 15, 2025 - Upgrade 11
     *  - ABLA activation
     */
    int upgrade11Height{NEVER_ACTIVE_HEIGHT};

    /** May 15, 2026 - Upgrade 12
     *  - OP_LSHIFT, OP_RSHIFT (shift opcodes)
     */
    int upgrade12Height{NEVER_ACTIVE_HEIGHT};

    /** Axion activation time (MTP-based, for chains without anchor) */
    int64_t axionActivationTime{0};

    /** Upgrade 12 activation time (MTP-based) */
    int64_t upgrade12ActivationTime{std::numeric_limits<int64_t>::max()};

    /** Upgrade 2027 activation time (MTP-based) */
    int64_t upgrade2027ActivationTime{std::numeric_limits<int64_t>::max()};

    /** ASERT anchor parameters - must be valid when ASERT is active */
    std::optional<ASERTAnchor> asertAnchorParams;

    /** ASERT half-life constants */
    static constexpr int64_t ASERT_HALFLIFE_1_HOUR = 60 * 60;        // 3600 seconds
    static constexpr int64_t ASERT_HALFLIFE_2_DAYS = 2 * 24 * 60 * 60; // 172800 seconds

    /** ASERT half-life in seconds (initial value).
     *  Mainnet: 3600 (1 hour) - fast recovery for new chain launch
     *  After nASERTHalfLifeTransitionHeight: 172800 (2 days) - stability
     */
    int64_t nASERTHalfLife{ASERT_HALFLIFE_2_DAYS};

    /** Block height at which ASERT half-life transitions from 1 hour to 2 days.
     *  Set to NEVER_ACTIVE_HEIGHT to disable transition (always use nASERTHalfLife).
     *  Mainnet: 92736 (epoch 46, ~9 months after fork)
     */
    int nASERTHalfLifeTransitionHeight{NEVER_ACTIVE_HEIGHT};

    /** Default consensus block size (32MB for BCH, 1MB pre-fork) */
    uint64_t nDefaultConsensusBlockSize{1000000};

    /** Maximum reorg depth (BCHN automatic finalization / rolling checkpoints).
     *  Blocks deeper than this from the tip are considered finalized and
     *  cannot be reorged away. Default: 10 (BCHN standard).
     *  Set to 0 to disable automatic finalization.
     */
    int maxReorgDepth{10};

    // =========================================================================
    // End BCH2 Fork Parameters
    // =========================================================================

    /** Don't warn about unknown BIP 9 activations below this height.
     * This prevents us from warning about the CSV and segwit activations. */
    int MinBIP9WarningHeight;
    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t nRuleChangeActivationThreshold;
    uint32_t nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];
    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    std::chrono::seconds PowTargetSpacing() const
    {
        return std::chrono::seconds{nPowTargetSpacing};
    }
    int64_t DifficultyAdjustmentInterval() const { return nPowTargetTimespan / nPowTargetSpacing; }
    /** The best chain should have at least this much work */
    uint256 nMinimumChainWork;
    /** By default assume that the signatures in ancestors of this block are valid */
    uint256 defaultAssumeValid;

    /**
     * If true, witness commitments contain a payload equal to a Bitcoin Script solution
     * to the signet challenge. See BIP325.
     */
    bool signet_blocks{false};
    std::vector<uint8_t> signet_challenge;

    int DeploymentHeight(BuriedDeployment dep) const
    {
        switch (dep) {
        case DEPLOYMENT_HEIGHTINCB:
            return BIP34Height;
        case DEPLOYMENT_CLTV:
            return BIP65Height;
        case DEPLOYMENT_DERSIG:
            return BIP66Height;
        case DEPLOYMENT_CSV:
            return CSVHeight;
        case DEPLOYMENT_SEGWIT:
            return SegwitHeight;
        } // no default case, so the compiler can warn about missing cases
        return std::numeric_limits<int>::max();
    }

    // =========================================================================
    // BCH2 Fork Activation Helpers
    // =========================================================================

    /** Check if BCH2 fork is active at given height.
     *  Fork activates at BCH2ForkHeight + 1, matching all other BCH upgrade checks.
     *  Block BCH2ForkHeight is the LAST pre-fork block. */
    bool IsBCH2ForkActive(int height) const {
        return height > BCH2ForkHeight;
    }

    /** Check if SegWit is active at given height.
     *  IMPORTANT: SegWit is DISABLED after BCH2 fork activates. */
    bool IsSegwitActive(int height) const {
        // BCH2 fork disables SegWit
        if (IsBCH2ForkActive(height)) return false;
        return height >= SegwitHeight;
    }

    /** Check if UAHF (8MB blocks, no SegWit) is active */
    bool IsUAHFActive(int height) const {
        return height > uahfHeight;
    }

    /** Check if new DAA (pre-ASERT) is active */
    bool IsDAAActive(int height) const {
        return height > daaHeight;
    }

    /** Check if Magnetic Anomaly (CTOR, OP_CHECKDATASIG) is active */
    bool IsMagneticAnomalyActive(int height) const {
        return height > magneticAnomalyHeight;
    }

    /** Check if Graviton (Schnorr sigs) is active */
    bool IsGravitonActive(int height) const {
        return height > gravitonHeight;
    }

    /** Check if Phonon (OP_REVERSEBYTES, SigChecks) is active */
    bool IsPhononActive(int height) const {
        return height > phononHeight;
    }

    /** Check if Axion/ASERT DAA is active */
    bool IsAxionActive(int height) const {
        return height > axionHeight;
    }

    /** Check if ASERT difficulty adjustment is active.
     *  Alias for IsAxionActive() for clarity in pow.cpp */
    bool IsASERTActive(int height) const {
        return IsAxionActive(height);
    }

    /** Check if Upgrade 8 (native introspection, 64-bit integers) is active */
    bool IsUpgrade8Active(int height) const {
        return height > upgrade8Height;
    }

    /** Check if Upgrade 9 (CHIP limits, P2SH32, CashTokens) is active */
    bool IsUpgrade9Active(int height) const {
        return height > upgrade9Height;
    }

    /** Check if CashTokens (CHIP-2022-02) is active.
     *  Alias for IsUpgrade9Active() since CashTokens activated in Upgrade 9. */
    bool IsCashTokensActive(int height) const {
        return IsUpgrade9Active(height);
    }

    /** Check if Upgrade 10 (VM limits, BigInt) is active */
    bool IsUpgrade10Active(int height) const {
        return height > upgrade10Height;
    }

    /** Check if Upgrade 11 (ABLA) is active */
    bool IsUpgrade11Active(int height) const {
        return height > upgrade11Height;
    }

    /** Check if Upgrade 12 (shift opcodes) is active */
    bool IsUpgrade12Active(int height) const {
        return height > upgrade12Height;
    }

    /** Get ASERT half-life for the given height.
     *  Returns 1-hour half-life before transition, 2-day after.
     *  This allows fast difficulty recovery during chain launch,
     *  transitioning to stable 2-day half-life once chain matures.
     */
    int64_t GetASERTHalfLife(int height) const {
        if (nASERTHalfLifeTransitionHeight != NEVER_ACTIVE_HEIGHT &&
            height >= nASERTHalfLifeTransitionHeight) {
            return ASERT_HALFLIFE_2_DAYS;
        }
        return nASERTHalfLife;
    }
};

} // namespace Consensus

#endif // BITCOINII_CONSENSUS_PARAMS_H
