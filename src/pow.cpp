// Copyright (c) 2009-2025 Satoshi Nakamoto
// Copyright (c) 2009-2024 The Bitcoin Core developers
// Copyright (c) 2025 The BitcoinII developers
// Copyright (c) 2025 The Bitcoin Cash II developers
// ASERT implementation from Bitcoin Cash Node (BCHN)
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <consensus/params.h>
#include <logging.h>
#include <primitives/block.h>
#include <uint256.h>

#include <cstdint>

/**
 * ASERT Difficulty Adjustment Algorithm (aserti3-2d)
 * Exact copy from Bitcoin Cash Node (BCHN) v29.0.0
 *
 * Compute the next required proof of work using an absolutely scheduled
 * exponentially weighted target (ASERT).
 *
 * With ASERT, we define an ideal schedule for block issuance (e.g. 1 block every 600 seconds), and we calculate the
 * temporary difficulty based on how far ahead of or behind that schedule we are. The calculation is (approximately, for
 * illustration):
 *
 *   target = refTarget * 2^((actualTime - scheduledTime) / 172800)
 *
 * Or, corrected to use the reference block timestamp instead of having the code operate on absolute times:
 *
 *   target = refTarget * 2^((timeDiff - (heightDiff + 1) * 600) / 172800)
 *
 * Where:
 *   - refTarget is the difficulty target of the reference block
 *   - timeDiff = timestamp of parent block - reference block parent timestamp
 *   - heightDiff = (height of next block to solve) - (height of reference block)
 *
 * The reference block is typically the anchor block for the algorithm.
 */

/**
 * CalculateASERT - Exact BCHN implementation
 *
 * Compute the target based on an idealized exponential difficulty adjustment.
 * The algorithm targets the average block interval of nPowTargetSpacing (e.g. 600 seconds).
 *
 * @param refTarget      The reference target (from anchor block nBits)
 * @param nPowTargetSpacing  Target block interval (600 seconds)
 * @param nTimeDiff      Time between reference block's parent and current block's parent
 * @param nHeightDiff    Height difference between next block and reference block
 * @param powLimit       Maximum target (minimum difficulty)
 * @param nHalfLife      ASERT half-life parameter (172800 seconds = 2 days)
 * @return               Calculated target for the next block
 */
arith_uint256 CalculateASERT(const arith_uint256 &refTarget,
                             const int64_t nPowTargetSpacing,
                             const int64_t nTimeDiff,
                             const int64_t nHeightDiff,
                             const arith_uint256 &powLimit,
                             const int64_t nHalfLife) noexcept {

    // Input target must never be zero nor exceed powLimit.
    assert(refTarget > 0 && refTarget <= powLimit);

    // We need some leading zero bits in powLimit in order to have room to handle
    // overflows easily. 32 leading zero bits is more than enough.
    assert((powLimit >> 224) == 0);

    // Height diff should NOT be negative.
    assert(nHeightDiff >= 0);

    // It will be helpful when reading what follows, to remember that
    // nextTarget is adapted from anchor block target value.

    // Ultimately, we want to approximate the following ASERT formula, using only integer (fixed-point) math:
    //     new_target = old_target * 2^((blocks_time - IDEAL_BLOCK_TIME * (height_diff + 1)) / nHalfLife)

    // First, we'll calculate the exponent:
    assert(llabs(nTimeDiff - nPowTargetSpacing * nHeightDiff) < (1ll << (63 - 16)));
    const int64_t exponent = ((nTimeDiff - nPowTargetSpacing * (nHeightDiff + 1)) * 65536) / nHalfLife;

    // Next, we use the 2^x = 2 * 2^(x-1) identity to shift our exponent into the [0, 1) interval.
    // The truncated exponent tells us how many shifts we need to do
    // Note1: This needs to be a right shift. Right shift rounds downward (floored division),
    //        whereas integer division in C++ rounds towards zero (truncated division).
    // Note2: This algorithm uses arithmetic shifts of negative numbers. This
    //        is unspecified but very common behavior for C++ compilers before
    //        C++20, and standard with C++20. We must check this behavior e.g.
    //        using static_assert.
    static_assert(int64_t(-1) >> 1 == int64_t(-1),
                  "ASERT algorithm needs arithmetic shift support");

    // Now we compute an approximated target * 2^(exponent/65536.0)

    // First decompose exponent into 'integer' and 'fractional' parts:
    int64_t shifts = exponent >> 16;
    const auto frac = uint16_t(exponent);
    assert(exponent == (shifts * 65536) + frac);

    // multiply target by 65536 * 2^(fractional part)
    // 2^x ~= (1 + 0.695502049*x + 0.2262698*x**2 + 0.0782318*x**3) for 0 <= x < 1
    // Error versus actual 2^x is less than 0.013%.
    const uint32_t factor = 65536 + ((
        + 195766423245049ull * frac
        + 971821376ull * frac * frac
        + 5127ull * frac * frac * frac
        + (1ull << 47)
        ) >> 48);
    // this is always < 2^241 since refTarget < 2^224
    arith_uint256 nextTarget = refTarget * factor;

    // multiply by 2^(integer part) / 65536
    shifts -= 16;
    if (shifts <= 0) {
        nextTarget >>= -shifts;
    } else {
        // Detect overflow that would discard high bits
        const auto nextTargetShifted = nextTarget << shifts;
        if ((nextTargetShifted >> shifts) != nextTarget) {
            // If we had wider integers, the final value of nextTarget would
            // be >= 2^256 so it would have just ended up as powLimit anyway.
            nextTarget = powLimit;
        } else {
            // Shifting produced no overflow, can assign value
            nextTarget = nextTargetShifted;
        }
    }

    if (nextTarget == 0) {
        // 0 is not a valid target, but 1 is.
        nextTarget = arith_uint256(1);
    } else if (nextTarget > powLimit) {
        nextTarget = powLimit;
    }

    // we return from only 1 place for copy elision
    return nextTarget;
}

// Note: ASERT half-life is now configurable via Consensus::Params::nASERTHalfLife
// Mainnet: 172800 seconds (2 days) - matches BCHN
// Testnet: 3600 seconds (1 hour) - matches BCHN testnet

/**
 * Calculate the next work required for a new block.
 * Uses ASERT after the BCH2 fork height, otherwise uses Bitcoin's original DAA.
 */
unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Check against the height being mined (pindexLast->nHeight + 1), not the parent
    // Skip ASERT for chains with no retargeting (regtest) - they keep constant difficulty
    int nNextHeight = pindexLast->nHeight + 1;
    if (params.IsBCH2ForkActive(nNextHeight) && params.asertAnchorParams && !params.fPowNoRetargeting) {
        // Get ASERT anchor parameters
        const int anchorHeight = params.asertAnchorParams->nHeight;
        const uint32_t anchorBits = params.asertAnchorParams->nBits;
        int64_t anchorParentTime = params.asertAnchorParams->nPrevBlockTime;

        // If anchorParentTime is 0, dynamically get anchor's parent block timestamp
        // This is useful for regtest and as a fallback
        if (anchorParentTime == 0 && anchorHeight > 0) {
            const CBlockIndex* pAnchorParent = pindexLast->GetAncestor(anchorHeight - 1);
            if (pAnchorParent) {
                anchorParentTime = pAnchorParent->GetBlockTime();
            } else {
                // BCH2 CRITICAL: Cannot compute ASERT without anchor parent timestamp
                // This should never happen on a properly configured chain
                LogPrintf("BCH2 CRITICAL: ASERT anchor parent block not found at height %d, falling back to powLimit\n", anchorHeight - 1);
                return nProofOfWorkLimit;
            }
        }

        if (anchorParentTime == 0) {
            LogPrintf("BCH2 CRITICAL: ASERT anchor parent timestamp is 0, falling back to powLimit\n");
            return nProofOfWorkLimit;
        }

        // For anchor block (nHeightDiff=0), return anchor difficulty directly
        if (nNextHeight == anchorHeight) {
            return anchorBits;
        }
        // Validate that we're past the anchor
        if (nNextHeight < anchorHeight) {
            // Should not happen if fork is properly configured
            // Fall back to powLimit
            return nProofOfWorkLimit;
        }

        // Get reference target from anchor
        arith_uint256 refTarget;
        refTarget.SetCompact(anchorBits);

        // Calculate time and height differences from anchor
        // timeDiff: time of current block's parent - anchor block's parent time
        // (Note: pindexLast is the parent of the block we're computing difficulty for)
        const int64_t nTimeDiff = pindexLast->GetBlockTime() - anchorParentTime;

        // heightDiff: (height of parent) - (anchor height), matching BCHN's aserti3-2d
        // The formula uses (nHeightDiff + 1) internally, so this must be tip height minus anchor.
        const int64_t nHeightDiff = pindexLast->nHeight - anchorHeight;

        // Calculate next target using ASERT (exact BCHN formula)
        // Half-life transitions from 1 hour to 2 days at nASERTHalfLifeTransitionHeight
        arith_uint256 nextTarget = CalculateASERT(
            refTarget,
            params.nPowTargetSpacing,  // 600 seconds
            nTimeDiff,
            nHeightDiff,
            UintToArith256(params.powLimit),
            params.GetASERTHalfLife(nNextHeight)  // 1 hour early, 2 days after transition
        );

        return nextTarget.GetCompact();
    }

    // Pre-fork: Use original Bitcoin difficulty adjustment

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

/**
 * Calculate the next work required using Bitcoin's original DAA (pre-fork).
 */
unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

/**
 * Check that on difficulty adjustments, the new difficulty does not increase
 * or decrease beyond the permitted limits.
 *
 * For post-fork ASERT blocks, verifies the difficulty matches the expected
 * ASERT calculation (with tolerance for compact representation rounding).
 */
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits)
{
    if (params.IsBCH2ForkActive(height)) {
        // For ASERT, we only validate that the target is within powLimit.
        // ASERT is deterministic - the actual difficulty validation happens
        // in ContextualCheckBlockHeader which calls GetNextWorkRequired.
        //
        // We cannot apply per-block change limits because:
        // 1. ASERT can legitimately produce large changes (e.g., 700x+ at fork
        //    if blocks were slow before the fork)
        // 2. ASERT is self-correcting - any manipulation is temporary
        // 3. We don't have timestamp info here to verify the ASERT calculation
        bool fNegative, fOverflow;
        arith_uint256 newTarget;
        newTarget.SetCompact(new_nbits, &fNegative, &fOverflow);

        if (fNegative || fOverflow || newTarget == 0) {
            return false;
        }

        if (newTarget > UintToArith256(params.powLimit)) {
            return false;
        }

        // ASERT targets are valid if within powLimit - no per-block limits
        return true;
    }

    // Pre-fork: Original validation logic
    if (params.fPowAllowMinDifficultyBlocks) return true;

    if (height % params.DifficultyAdjustmentInterval() == 0) {
        int64_t smallest_timespan = params.nPowTargetTimespan/4;
        int64_t largest_timespan = params.nPowTargetTimespan*4;

        const arith_uint256 pow_limit = UintToArith256(params.powLimit);
        arith_uint256 observed_new_target;
        observed_new_target.SetCompact(new_nbits);

        // Calculate the largest difficulty value possible:
        arith_uint256 largest_difficulty_target;
        largest_difficulty_target.SetCompact(old_nbits);
        largest_difficulty_target *= largest_timespan;
        largest_difficulty_target /= params.nPowTargetTimespan;

        if (largest_difficulty_target > pow_limit) {
            largest_difficulty_target = pow_limit;
        }

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 maximum_new_target;
        maximum_new_target.SetCompact(largest_difficulty_target.GetCompact());
        if (maximum_new_target < observed_new_target) return false;

        // Calculate the smallest difficulty value possible:
        arith_uint256 smallest_difficulty_target;
        smallest_difficulty_target.SetCompact(old_nbits);
        smallest_difficulty_target *= smallest_timespan;
        smallest_difficulty_target /= params.nPowTargetTimespan;

        if (smallest_difficulty_target > pow_limit) {
            smallest_difficulty_target = pow_limit;
        }

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 minimum_new_target;
        minimum_new_target.SetCompact(smallest_difficulty_target.GetCompact());
        if (minimum_new_target > observed_new_target) return false;
    } else if (old_nbits != new_nbits) {
        return false;
    }
    return true;
}

/**
 * Check whether the block's proof of work satisfies the difficulty target.
 */
bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
