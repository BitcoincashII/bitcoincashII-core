// Copyright (c) 2026 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests for CashAddr encoding/decoding (cashaddr.cpp).
// Covers Encode/Decode roundtrip, error paths, PackAddrData/UnpackAddrData.

#include <cashaddr.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(bch2_cashaddr_tests)

// ===== Encode/Decode roundtrip =====

BOOST_AUTO_TEST_CASE(encode_decode_roundtrip_p2pkh)
{
    // 20-byte P2PKH hash, type 0
    std::vector<uint8_t> hash(20, 0xAB);
    std::vector<uint8_t> packed = cashaddr::PackAddrData(hash, 0);
    BOOST_CHECK(!packed.empty());

    std::string encoded = cashaddr::Encode("bitcoincashii", packed);
    BOOST_CHECK(encoded.find("bitcoincashii:") == 0);

    auto [prefix, payload] = cashaddr::Decode(encoded, "bitcoincashii");
    BOOST_CHECK_EQUAL(prefix, "bitcoincashii");
    BOOST_CHECK(payload == packed);

    auto [type, decoded_hash] = cashaddr::UnpackAddrData(payload);
    BOOST_CHECK_EQUAL(type, 0);
    BOOST_CHECK(decoded_hash == hash);
}

BOOST_AUTO_TEST_CASE(encode_decode_roundtrip_p2sh)
{
    // 20-byte P2SH hash, type 1
    std::vector<uint8_t> hash(20, 0xCD);
    std::vector<uint8_t> packed = cashaddr::PackAddrData(hash, 1);
    std::string encoded = cashaddr::Encode("bitcoincashii", packed);

    auto [prefix, payload] = cashaddr::Decode(encoded, "bitcoincashii");
    BOOST_CHECK_EQUAL(prefix, "bitcoincashii");

    auto [type, decoded_hash] = cashaddr::UnpackAddrData(payload);
    BOOST_CHECK_EQUAL(type, 1);
    BOOST_CHECK(decoded_hash == hash);
}

// ===== Decode error paths =====

BOOST_AUTO_TEST_CASE(decode_no_colon_uses_default_prefix)
{
    // Encode with prefix, then strip prefix and decode with default
    std::vector<uint8_t> hash(20, 0x11);
    std::vector<uint8_t> packed = cashaddr::PackAddrData(hash, 0);
    std::string encoded = cashaddr::Encode("bitcoincashii", packed);

    // Strip prefix to get just the payload part
    std::string payload_only = encoded.substr(encoded.find(':') + 1);

    auto [prefix, payload] = cashaddr::Decode(payload_only, "bitcoincashii");
    BOOST_CHECK_EQUAL(prefix, "bitcoincashii");
    BOOST_CHECK(payload == packed);
}

BOOST_AUTO_TEST_CASE(decode_invalid_char_rejected)
{
    // Characters not in the CashAddr charset should fail
    auto [prefix, payload] = cashaddr::Decode("bitcoincashii:INVALID!", "bitcoincashii");
    BOOST_CHECK(prefix.empty());
    BOOST_CHECK(payload.empty());
}

BOOST_AUTO_TEST_CASE(decode_non_ascii_rejected)
{
    // Non-ASCII chars (>127) should fail
    std::string bad = "bitcoincashii:";
    bad += static_cast<char>(0x80);
    bad += "qqqqqqqq";
    auto [prefix, payload] = cashaddr::Decode(bad, "bitcoincashii");
    BOOST_CHECK(prefix.empty());
    BOOST_CHECK(payload.empty());
}

BOOST_AUTO_TEST_CASE(decode_payload_too_short)
{
    // Payload < 8 bytes (less than checksum size) should fail
    auto [prefix, payload] = cashaddr::Decode("bitcoincashii:qq", "bitcoincashii");
    BOOST_CHECK(prefix.empty());
    BOOST_CHECK(payload.empty());
}

BOOST_AUTO_TEST_CASE(decode_corrupted_checksum)
{
    // Valid encoding but flip one char in the checksum
    std::vector<uint8_t> hash(20, 0x22);
    std::vector<uint8_t> packed = cashaddr::PackAddrData(hash, 0);
    std::string encoded = cashaddr::Encode("bitcoincashii", packed);

    // Corrupt last character
    char last = encoded.back();
    encoded.back() = (last == 'q') ? 'p' : 'q';

    auto [prefix, payload] = cashaddr::Decode(encoded, "bitcoincashii");
    BOOST_CHECK(prefix.empty());
    BOOST_CHECK(payload.empty());
}

BOOST_AUTO_TEST_CASE(decode_empty_string)
{
    auto [prefix, payload] = cashaddr::Decode("", "bitcoincashii");
    BOOST_CHECK(prefix.empty());
    BOOST_CHECK(payload.empty());
}

BOOST_AUTO_TEST_CASE(decode_uppercase_prefix_normalized)
{
    // CashAddr should normalize prefix to lowercase
    std::vector<uint8_t> hash(20, 0x33);
    std::vector<uint8_t> packed = cashaddr::PackAddrData(hash, 0);
    std::string encoded = cashaddr::Encode("bitcoincashii", packed);

    // Replace prefix with uppercase
    std::string upper_encoded = "BITCOINCASHII" + encoded.substr(encoded.find(':'));
    auto [prefix, payload] = cashaddr::Decode(upper_encoded, "bitcoincashii");
    BOOST_CHECK_EQUAL(prefix, "bitcoincashii");
    BOOST_CHECK(payload == packed);
}

// ===== PackAddrData =====

BOOST_AUTO_TEST_CASE(pack_addr_data_all_valid_sizes)
{
    // All 8 valid sizes should return non-empty packed data
    std::vector<size_t> valid_sizes = {20, 24, 28, 32, 40, 48, 56, 64};
    for (size_t sz : valid_sizes) {
        std::vector<uint8_t> hash(sz, 0x44);
        std::vector<uint8_t> packed = cashaddr::PackAddrData(hash, 0);
        BOOST_CHECK_MESSAGE(!packed.empty(), "PackAddrData failed for size " + std::to_string(sz));
    }
}

BOOST_AUTO_TEST_CASE(pack_addr_data_invalid_size)
{
    // Invalid sizes should return empty
    std::vector<size_t> invalid_sizes = {0, 1, 10, 19, 21, 25, 33, 65, 100};
    for (size_t sz : invalid_sizes) {
        std::vector<uint8_t> hash(sz, 0x55);
        std::vector<uint8_t> packed = cashaddr::PackAddrData(hash, 0);
        BOOST_CHECK_MESSAGE(packed.empty(), "PackAddrData should fail for size " + std::to_string(sz));
    }
}

BOOST_AUTO_TEST_CASE(pack_addr_data_type_values)
{
    // Different type values (0-31) should encode correctly
    std::vector<uint8_t> hash(20, 0x66);
    for (uint8_t type = 0; type < 4; ++type) {
        std::vector<uint8_t> packed = cashaddr::PackAddrData(hash, type);
        BOOST_CHECK(!packed.empty());
        auto [decoded_type, decoded_hash] = cashaddr::UnpackAddrData(packed);
        BOOST_CHECK_EQUAL(decoded_type, type);
        BOOST_CHECK(decoded_hash == hash);
    }
}

// ===== UnpackAddrData =====

BOOST_AUTO_TEST_CASE(unpack_addr_data_too_short)
{
    // < 2 bytes should return empty
    std::vector<uint8_t> data0;
    auto [type0, hash0] = cashaddr::UnpackAddrData(data0);
    BOOST_CHECK(hash0.empty());

    std::vector<uint8_t> data1 = {0x00};
    auto [type1, hash1] = cashaddr::UnpackAddrData(data1);
    BOOST_CHECK(hash1.empty());
}

BOOST_AUTO_TEST_CASE(pack_unpack_roundtrip_all_sizes)
{
    // PackAddrData + UnpackAddrData roundtrip for every valid size
    std::vector<size_t> valid_sizes = {20, 24, 28, 32, 40, 48, 56, 64};
    for (size_t sz : valid_sizes) {
        std::vector<uint8_t> hash(sz);
        for (size_t i = 0; i < sz; ++i) hash[i] = static_cast<uint8_t>(i & 0xFF);

        std::vector<uint8_t> packed = cashaddr::PackAddrData(hash, 0);
        auto [type, decoded_hash] = cashaddr::UnpackAddrData(packed);
        BOOST_CHECK_EQUAL(type, 0);
        BOOST_CHECK_MESSAGE(decoded_hash == hash,
            "Round-trip failed for size " + std::to_string(sz));
    }
}

// ===== Full encode/decode roundtrip for all valid sizes =====

BOOST_AUTO_TEST_CASE(full_roundtrip_all_sizes)
{
    std::vector<size_t> valid_sizes = {20, 24, 28, 32, 40, 48, 56, 64};
    for (size_t sz : valid_sizes) {
        std::vector<uint8_t> hash(sz, static_cast<uint8_t>(sz));
        std::vector<uint8_t> packed = cashaddr::PackAddrData(hash, 0);
        std::string encoded = cashaddr::Encode("bitcoincashii", packed);

        auto [prefix, payload] = cashaddr::Decode(encoded, "bitcoincashii");
        BOOST_CHECK_EQUAL(prefix, "bitcoincashii");

        auto [type, decoded_hash] = cashaddr::UnpackAddrData(payload);
        BOOST_CHECK_EQUAL(type, 0);
        BOOST_CHECK_MESSAGE(decoded_hash == hash,
            "Full roundtrip failed for size " + std::to_string(sz));
    }
}

// ===== VerifyChecksum =====

BOOST_AUTO_TEST_CASE(verify_checksum_valid)
{
    std::vector<uint8_t> hash(20, 0x77);
    std::vector<uint8_t> packed = cashaddr::PackAddrData(hash, 0);
    std::string encoded = cashaddr::Encode("bitcoincashii", packed);

    // Decode the full string to get prefix + payload with checksum
    // Then re-verify manually
    auto [prefix, payload] = cashaddr::Decode(encoded, "bitcoincashii");
    BOOST_CHECK(!prefix.empty());
    BOOST_CHECK(!payload.empty());
}

BOOST_AUTO_TEST_CASE(decode_with_multiple_colons)
{
    // rfind(':') should handle multiple colons (take the last one)
    std::vector<uint8_t> hash(20, 0x88);
    std::vector<uint8_t> packed = cashaddr::PackAddrData(hash, 0);
    std::string encoded = cashaddr::Encode("bitcoincashii", packed);

    // Replace "bitcoincashii:" with "bit:coinca:shii:"
    // This should fail because the prefix is wrong for checksum
    std::string payload_part = encoded.substr(encoded.find(':') + 1);
    std::string multi_colon = "bit:coinca:shii:" + payload_part;
    auto [prefix, payload] = cashaddr::Decode(multi_colon, "bitcoincashii");
    // The prefix would be "bit:coinca:shii" (last colon), checksum won't verify
    BOOST_CHECK(prefix.empty());
}

BOOST_AUTO_TEST_CASE(encode_produces_lowercase)
{
    std::vector<uint8_t> hash(20, 0x99);
    std::vector<uint8_t> packed = cashaddr::PackAddrData(hash, 0);
    std::string encoded = cashaddr::Encode("bitcoincashii", packed);

    // All characters should be lowercase or digits or colon
    for (char c : encoded) {
        BOOST_CHECK(c == ':' || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'));
    }
}

// ===== 64-byte max hash roundtrip =====

BOOST_AUTO_TEST_CASE(encode_decode_64byte_max_hash)
{
    // Maximum valid CashAddr hash: 64 bytes
    std::vector<uint8_t> maxHash(64);
    for (size_t i = 0; i < 64; ++i) {
        maxHash[i] = static_cast<uint8_t>(i);
    }
    std::vector<uint8_t> packed = cashaddr::PackAddrData(maxHash, 0);
    BOOST_CHECK(!packed.empty());

    std::string encoded = cashaddr::Encode("bitcoincashii", packed);
    auto [prefix, payload] = cashaddr::Decode(encoded, "bitcoincashii");
    BOOST_CHECK_EQUAL(prefix, "bitcoincashii");

    auto [type, decoded] = cashaddr::UnpackAddrData(payload);
    BOOST_CHECK_EQUAL(type, 0);
    BOOST_CHECK_EQUAL(decoded.size(), 64u);
    BOOST_CHECK(decoded == maxHash);
}

// ===== Type values 0-7 roundtrip =====

BOOST_AUTO_TEST_CASE(pack_addr_data_all_type_values_0_to_7)
{
    std::vector<uint8_t> hash(20, 0x77);
    for (uint8_t type = 0; type < 8; ++type) {
        std::vector<uint8_t> packed = cashaddr::PackAddrData(hash, type);
        BOOST_CHECK(!packed.empty());
        auto [decoded_type, decoded_hash] = cashaddr::UnpackAddrData(packed);
        BOOST_CHECK_EQUAL(decoded_type, type);
        BOOST_CHECK(decoded_hash == hash);
    }
}

// ===== Mixed case decoding =====

BOOST_AUTO_TEST_CASE(decode_mixed_case_accepted)
{
    // BCH2 CashAddr: CHARSET_REV maps upper and lower to same values,
    // and ExpandPrefix uses & 0x1f (case-insensitive). Mixed case decodes OK.
    std::vector<uint8_t> hash(20, 0xAA);
    std::vector<uint8_t> packed = cashaddr::PackAddrData(hash, 0);
    std::string encoded = cashaddr::Encode("bitcoincashii", packed);

    // Create mixed case: uppercase some payload chars
    std::string mixed = encoded;
    size_t colonPos = mixed.find(':');
    if (colonPos + 2 < mixed.size()) {
        mixed[colonPos + 1] = toupper(mixed[colonPos + 1]);
        // Keep the next char lowercase — mixed case
    }

    auto [prefix, payload] = cashaddr::Decode(mixed, "bitcoincashii");
    // Case-insensitive: decodes successfully
    BOOST_CHECK_EQUAL(prefix, "bitcoincashii");
    BOOST_CHECK(payload == packed);
}

// ===== Corrupted data (middle) detection =====

BOOST_AUTO_TEST_CASE(decode_corrupted_middle_detected)
{
    std::vector<uint8_t> hash(20, 0xBB);
    std::vector<uint8_t> packed = cashaddr::PackAddrData(hash, 0);
    std::string encoded = cashaddr::Encode("bitcoincashii", packed);

    // Corrupt a character in the middle of the data
    size_t mid = encoded.find(':') + 5;
    char orig = encoded[mid];
    encoded[mid] = (orig == 'q') ? 'p' : 'q';

    auto [prefix, payload] = cashaddr::Decode(encoded, "bitcoincashii");
    BOOST_CHECK(prefix.empty());
}

// ===== Prefix mismatch =====

BOOST_AUTO_TEST_CASE(decode_wrong_default_prefix_ignored_when_colon_present)
{
    // default_prefix is only used when there's no colon in the string.
    // When the encoded string contains "bitcoincashii:", the actual prefix
    // is extracted and checksum verifies against it.
    std::vector<uint8_t> hash(20, 0xCC);
    std::vector<uint8_t> packed = cashaddr::PackAddrData(hash, 0);
    std::string encoded = cashaddr::Encode("bitcoincashii", packed);

    // Decode with wrong default_prefix — but the string has a colon,
    // so the actual prefix "bitcoincashii" is used, and checksum passes.
    auto [prefix, payload] = cashaddr::Decode(encoded, "wrongprefix");
    BOOST_CHECK_EQUAL(prefix, "bitcoincashii");
    BOOST_CHECK(payload == packed);
}

BOOST_AUTO_TEST_CASE(decode_replaced_prefix_fails_checksum)
{
    // Actually replace the prefix in the encoded string with a wrong one.
    // The checksum was computed with "bitcoincashii", so it will fail.
    std::vector<uint8_t> hash(20, 0xCC);
    std::vector<uint8_t> packed = cashaddr::PackAddrData(hash, 0);
    std::string encoded = cashaddr::Encode("bitcoincashii", packed);

    // Replace prefix portion
    std::string payload_part = encoded.substr(encoded.find(':') + 1);
    std::string wrong_prefix_addr = "wrongprefix:" + payload_part;

    auto [prefix, payload] = cashaddr::Decode(wrong_prefix_addr, "bitcoincashii");
    BOOST_CHECK(prefix.empty()); // Checksum mismatch
}

// ===== Deterministic encoding =====

BOOST_AUTO_TEST_CASE(encode_same_data_twice_identical)
{
    std::vector<uint8_t> hash(20, 0xDD);
    std::vector<uint8_t> packed = cashaddr::PackAddrData(hash, 0);

    std::string enc1 = cashaddr::Encode("bitcoincashii", packed);
    std::string enc2 = cashaddr::Encode("bitcoincashii", packed);
    BOOST_CHECK_EQUAL(enc1, enc2);
}

// ===== Different hash produces different address =====

BOOST_AUTO_TEST_CASE(different_hash_different_address)
{
    std::vector<uint8_t> hash1(20, 0xEE);
    std::vector<uint8_t> hash2(20, 0xFF);

    std::string enc1 = cashaddr::Encode("bitcoincashii", cashaddr::PackAddrData(hash1, 0));
    std::string enc2 = cashaddr::Encode("bitcoincashii", cashaddr::PackAddrData(hash2, 0));
    BOOST_CHECK(enc1 != enc2);
}

// ===== Different type same hash produces different address =====

BOOST_AUTO_TEST_CASE(different_type_different_address)
{
    std::vector<uint8_t> hash(20, 0xAA);

    std::string enc0 = cashaddr::Encode("bitcoincashii", cashaddr::PackAddrData(hash, 0));
    std::string enc1 = cashaddr::Encode("bitcoincashii", cashaddr::PackAddrData(hash, 1));
    BOOST_CHECK(enc0 != enc1);
}

// ===== High type values (above standard 0-7) =====

BOOST_AUTO_TEST_CASE(high_type_8_roundtrip)
{
    // PackAddrData/UnpackAddrData support type values > 7
    // Type is encoded as the upper 5 bits of the version byte
    std::vector<uint8_t> hash(20, 0xBB);
    auto packed = cashaddr::PackAddrData(hash, 8);
    BOOST_CHECK(!packed.empty());

    std::string encoded = cashaddr::Encode("bitcoincashii", packed);
    auto decoded = cashaddr::Decode(encoded, "bitcoincashii");
    BOOST_CHECK(!decoded.second.empty());

    auto [type, unpacked] = cashaddr::UnpackAddrData(decoded.second);
    BOOST_CHECK_EQUAL(type, 8);
    BOOST_CHECK(unpacked == hash);
}

BOOST_AUTO_TEST_CASE(high_type_31_roundtrip)
{
    // Maximum 5-bit type value (31) should round-trip
    std::vector<uint8_t> hash(20, 0xCC);
    auto packed = cashaddr::PackAddrData(hash, 31);
    BOOST_CHECK(!packed.empty());

    std::string encoded = cashaddr::Encode("bitcoincashii", packed);
    auto decoded = cashaddr::Decode(encoded, "bitcoincashii");
    BOOST_CHECK(!decoded.second.empty());

    auto [type, unpacked] = cashaddr::UnpackAddrData(decoded.second);
    BOOST_CHECK_EQUAL(type, 31);
    BOOST_CHECK(unpacked == hash);
}

BOOST_AUTO_TEST_CASE(type_32_wraps_to_zero)
{
    // Type 32: version_byte = 32 << 3 = 256 → wraps to 0x00 in uint8_t
    // So type 32 encodes identically to type 0
    std::vector<uint8_t> hash(20, 0xDD);
    auto packed32 = cashaddr::PackAddrData(hash, 32);
    auto packed0 = cashaddr::PackAddrData(hash, 0);
    BOOST_CHECK(packed32 == packed0);
}

// ============================================================================
// Encode/Decode edge cases
// ============================================================================

BOOST_AUTO_TEST_CASE(decode_wrong_prefix)
{
    // Encode with one prefix, decode with different default prefix
    std::vector<uint8_t> hash(20, 0x11);
    auto packed = cashaddr::PackAddrData(hash, 0);
    std::string encoded = cashaddr::Encode("bitcoincashii", packed);

    // Decode with wrong default prefix — should still work if prefix is in the string
    auto [prefix, payload] = cashaddr::Decode(encoded, "wrongprefix");
    BOOST_CHECK_EQUAL(prefix, "bitcoincashii");
    BOOST_CHECK(payload == packed);
}

BOOST_AUTO_TEST_CASE(decode_without_prefix_uses_default)
{
    // If the encoded string has no colon, it should use the default prefix
    std::vector<uint8_t> hash(20, 0x22);
    auto packed = cashaddr::PackAddrData(hash, 0);
    std::string full = cashaddr::Encode("bitcoincashii", packed);

    // Strip the prefix, keep only the payload part
    std::string payload_only = full.substr(full.find(':') + 1);

    auto [prefix, payload] = cashaddr::Decode(payload_only, "bitcoincashii");
    BOOST_CHECK_EQUAL(prefix, "bitcoincashii");
    BOOST_CHECK(payload == packed);
}

BOOST_AUTO_TEST_CASE(decode_invalid_checksum)
{
    std::vector<uint8_t> hash(20, 0x33);
    auto packed = cashaddr::PackAddrData(hash, 0);
    std::string encoded = cashaddr::Encode("bitcoincashii", packed);

    // Corrupt the last character (part of checksum)
    char last = encoded.back();
    encoded.back() = (last == 'q') ? 'p' : 'q';

    auto [prefix, payload] = cashaddr::Decode(encoded, "bitcoincashii");
    // Invalid checksum should return empty payload
    BOOST_CHECK(payload.empty());
}

BOOST_AUTO_TEST_CASE(decode_invalid_character)
{
    // CashAddr uses a specific character set — 'b' is valid but '1' is not in some positions
    auto [prefix, payload] = cashaddr::Decode("bitcoincashii:INVALID!!!CHARS", "bitcoincashii");
    BOOST_CHECK(payload.empty());
}

BOOST_AUTO_TEST_CASE(encode_empty_prefix)
{
    std::vector<uint8_t> hash(20, 0x44);
    auto packed = cashaddr::PackAddrData(hash, 0);
    // Empty prefix should still produce an encoded string
    std::string encoded = cashaddr::Encode("", packed);
    BOOST_CHECK(!encoded.empty());
    BOOST_CHECK(encoded[0] == ':'); // Starts with colon (no prefix)
}

BOOST_AUTO_TEST_CASE(encode_decode_all_zeros)
{
    std::vector<uint8_t> hash(20, 0x00);
    auto packed = cashaddr::PackAddrData(hash, 0);
    std::string encoded = cashaddr::Encode("bitcoincashii", packed);

    auto [prefix, payload] = cashaddr::Decode(encoded, "bitcoincashii");
    BOOST_CHECK_EQUAL(prefix, "bitcoincashii");
    BOOST_CHECK(payload == packed);

    auto [type, decoded_hash] = cashaddr::UnpackAddrData(payload);
    BOOST_CHECK_EQUAL(type, 0);
    BOOST_CHECK(decoded_hash == hash);
}

BOOST_AUTO_TEST_CASE(encode_decode_all_ones)
{
    std::vector<uint8_t> hash(20, 0xFF);
    auto packed = cashaddr::PackAddrData(hash, 0);
    std::string encoded = cashaddr::Encode("bitcoincashii", packed);

    auto [prefix, payload] = cashaddr::Decode(encoded, "bitcoincashii");
    auto [type, decoded_hash] = cashaddr::UnpackAddrData(payload);
    BOOST_CHECK_EQUAL(type, 0);
    BOOST_CHECK(decoded_hash == hash);
}

BOOST_AUTO_TEST_CASE(case_insensitive_prefix)
{
    std::vector<uint8_t> hash(20, 0x55);
    auto packed = cashaddr::PackAddrData(hash, 0);
    std::string encoded = cashaddr::Encode("bitcoincashii", packed);

    // Replace prefix with uppercase
    std::string upper = "BITCOINCASHII" + encoded.substr(encoded.find(':'));
    auto [prefix, payload] = cashaddr::Decode(upper, "bitcoincashii");
    BOOST_CHECK_EQUAL(prefix, "bitcoincashii");
    BOOST_CHECK(payload == packed);
}

BOOST_AUTO_TEST_CASE(mixed_case_accepted_by_decode)
{
    // CashAddr implementation lowercases the entire string before decoding,
    // so mixed case in the payload is actually accepted
    std::vector<uint8_t> hash(20, 0x66);
    auto packed = cashaddr::PackAddrData(hash, 0);
    std::string encoded = cashaddr::Encode("bitcoincashii", packed);

    std::string mixed = encoded;
    size_t colonPos = mixed.find(':');
    if (colonPos != std::string::npos && colonPos + 2 < mixed.size()) {
        mixed[colonPos + 1] = toupper(mixed[colonPos + 1]);
    }
    auto [prefix, payload] = cashaddr::Decode(mixed, "bitcoincashii");
    // Decode lowercases everything, so mixed case succeeds
    BOOST_CHECK(!payload.empty());
    BOOST_CHECK(payload == packed);
}

BOOST_AUTO_TEST_SUITE_END()
