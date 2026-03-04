// Copyright (c) 2022-2024 The Bitcoin Cash Node developers
// Copyright (c) 2025 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOINII_PRIMITIVES_TOKEN_H
#define BITCOINII_PRIMITIVES_TOKEN_H

#include <serialize.h>
#include <uint256.h>
#include <util/heapoptional.h>

#include <cstdint>
#include <string>
#include <vector>

/**
 * CashTokens (CHIP-2022-02-CashTokens) support for BCH2.
 *
 * Token categories are identified by a 32-byte category ID (the txid of the
 * genesis transaction's input 0). Tokens can be fungible (with an amount) or
 * non-fungible (NFTs with optional commitment data).
 *
 * Token capability levels for NFTs:
 * - none (0x00): Immutable NFT - cannot be modified
 * - mutable (0x01): Can update commitment data
 * - minting (0x02): Can mint new NFTs of the same category
 */

/** Token capability levels */
namespace token {

/** NFT capability flags */
enum Capability : uint8_t {
    None = 0x00,     // Immutable NFT
    Mutable = 0x01,  // Can update commitment
    Minting = 0x02,  // Can mint new NFTs
};

/** Bitfield structure byte flags */
namespace BitfieldFlag {
    static constexpr uint8_t HasAmount = 0x10;
    static constexpr uint8_t HasNFT = 0x20;
    static constexpr uint8_t HasCommitmentLength = 0x40;
    static constexpr uint8_t Reserved = 0x80;  // Must be 0
    static constexpr uint8_t CapabilityMask = 0x0f;
}

/** Maximum commitment length */
static constexpr size_t MAX_COMMITMENT_LENGTH = 40;

/** Maximum token amount (same as MAX_MONEY for fungible tokens) */
static constexpr int64_t MAX_AMOUNT = 2099999997690000LL;

} // namespace token

/**
 * Token data attached to a transaction output.
 *
 * Serialization format (when present, after SPECIAL_TOKEN_PREFIX 0xef):
 * - 32 bytes: category ID (txid)
 * - 1 byte: bitfield (capability | flags)
 * - if HasCommitmentLength: varint commitment length + commitment bytes
 * - if HasAmount: compact size amount
 */
class OutputToken {
public:
    uint256 categoryId;              // 32-byte token category ID
    uint8_t bitfield{0};             // Capability and flags
    std::vector<uint8_t> commitment; // NFT commitment data (0-40 bytes)
    int64_t amount{0};               // Fungible token amount

    OutputToken() = default;

    OutputToken(const uint256& catId, int64_t amt)
        : categoryId(catId), bitfield(token::BitfieldFlag::HasAmount), amount(amt) {}

    OutputToken(const uint256& catId, token::Capability cap,
                const std::vector<uint8_t>& nftCommitment = {})
        : categoryId(catId)
        , bitfield(static_cast<uint8_t>(cap) | token::BitfieldFlag::HasNFT |
                   (nftCommitment.empty() ? 0 : token::BitfieldFlag::HasCommitmentLength))
        , commitment(nftCommitment) {}

    OutputToken(const uint256& catId, token::Capability cap,
                const std::vector<uint8_t>& nftCommitment, int64_t amt)
        : categoryId(catId)
        , bitfield(static_cast<uint8_t>(cap) | token::BitfieldFlag::HasNFT |
                   token::BitfieldFlag::HasAmount |
                   (nftCommitment.empty() ? 0 : token::BitfieldFlag::HasCommitmentLength))
        , commitment(nftCommitment)
        , amount(amt) {}

    /** Check if this token has fungible amount */
    bool HasAmount() const { return bitfield & token::BitfieldFlag::HasAmount; }

    /** Check if this token has NFT data */
    bool HasNFT() const { return bitfield & token::BitfieldFlag::HasNFT; }

    /** Check if NFT has commitment */
    bool HasCommitment() const { return bitfield & token::BitfieldFlag::HasCommitmentLength; }

    /** Get NFT capability level */
    token::Capability GetCapability() const {
        return static_cast<token::Capability>(bitfield & token::BitfieldFlag::CapabilityMask);
    }

    /** Check if this is a minting token */
    bool IsMintingToken() const {
        return HasNFT() && GetCapability() == token::Minting;
    }

    /** Check if this is a mutable token */
    bool IsMutableToken() const {
        return HasNFT() && GetCapability() == token::Mutable;
    }

    /** Check if this is an immutable NFT */
    bool IsImmutableToken() const {
        return HasNFT() && GetCapability() == token::None;
    }

    /** Validate token data */
    bool IsValid() const {
        // Reserved bit must be 0
        if (bitfield & token::BitfieldFlag::Reserved) return false;

        // If no NFT, capability must be 0
        if (!HasNFT() && (bitfield & token::BitfieldFlag::CapabilityMask)) return false;

        // If no NFT, no commitment allowed
        if (!HasNFT() && HasCommitment()) return false;

        // Capability must be valid (0, 1, or 2)
        if (HasNFT() && GetCapability() > token::Minting) return false;

        // Commitment length check
        if (commitment.size() > token::MAX_COMMITMENT_LENGTH) return false;

        // Commitment presence must match flag
        if (HasCommitment() != !commitment.empty()) return false;

        // Amount check
        if (HasAmount() && (amount <= 0 || amount > token::MAX_AMOUNT)) return false;

        // Must have at least NFT or amount
        if (!HasNFT() && !HasAmount()) return false;

        return true;
    }

    template <typename Stream>
    void Serialize(Stream& s) const {
        s << categoryId;
        s << bitfield;
        if (HasCommitment()) {
            WriteCompactSize(s, commitment.size());
            s.write(MakeByteSpan(commitment));
        }
        if (HasAmount()) {
            WriteCompactSize(s, static_cast<uint64_t>(amount));
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s) {
        s >> categoryId;
        s >> bitfield;
        if (HasCommitment()) {
            size_t commitLen = ReadCompactSize(s);
            if (commitLen > token::MAX_COMMITMENT_LENGTH) {
                throw std::ios_base::failure("Token commitment too long");
            }
            commitment.resize(commitLen);
            s.read(MakeWritableByteSpan(commitment));
        } else {
            commitment.clear();
        }
        if (HasAmount()) {
            amount = static_cast<int64_t>(ReadCompactSize(s));
            if (amount <= 0 || amount > token::MAX_AMOUNT) {
                throw std::ios_base::failure("Invalid token amount");
            }
        } else {
            amount = 0;
        }
    }

    bool operator==(const OutputToken& o) const {
        return categoryId == o.categoryId &&
               bitfield == o.bitfield &&
               commitment == o.commitment &&
               amount == o.amount;
    }

    bool operator!=(const OutputToken& o) const { return !(*this == o); }

    bool operator<(const OutputToken& o) const {
        if (categoryId != o.categoryId) return categoryId < o.categoryId;
        if (bitfield != o.bitfield) return bitfield < o.bitfield;
        if (commitment != o.commitment) return commitment < o.commitment;
        return amount < o.amount;
    }

    std::string ToString() const;
};

/** Heap-allocated optional token for memory efficiency */
using TokenDataPtr = HeapOptional<OutputToken>;

#endif // BITCOINII_PRIMITIVES_TOKEN_H
