// Copyright (c) 2026 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests for ScriptNumEncoding: IsMinimallyEncoded and MinimallyEncode.
// Covers boundary conditions for different maxIntegerSize values (4, 8, 10000).

#include <script/script_num_encoding.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(bch2_scriptnum_tests)

// ============================================================================
// IsMinimallyEncoded — basic cases
// ============================================================================

BOOST_AUTO_TEST_CASE(is_minimally_encoded_empty)
{
    // Empty vector is always minimally encoded
    std::vector<uint8_t> v{};
    BOOST_CHECK(ScriptNumEncoding::IsMinimallyEncoded(v, 4));
    BOOST_CHECK(ScriptNumEncoding::IsMinimallyEncoded(v, 8));
    BOOST_CHECK(ScriptNumEncoding::IsMinimallyEncoded(v, 10000));
}

BOOST_AUTO_TEST_CASE(is_minimally_encoded_single_byte)
{
    // Single non-zero byte is minimal
    std::vector<uint8_t> v{0x42};
    BOOST_CHECK(ScriptNumEncoding::IsMinimallyEncoded(v, 4));
}

BOOST_AUTO_TEST_CASE(is_minimally_encoded_positive_one)
{
    // {0x01} = +1, minimal
    std::vector<uint8_t> v{0x01};
    BOOST_CHECK(ScriptNumEncoding::IsMinimallyEncoded(v, 4));
}

BOOST_AUTO_TEST_CASE(is_minimally_encoded_negative_one)
{
    // {0x81} = -1, minimal (sign bit set on value byte)
    std::vector<uint8_t> v{0x81};
    BOOST_CHECK(ScriptNumEncoding::IsMinimallyEncoded(v, 4));
}

BOOST_AUTO_TEST_CASE(is_minimally_encoded_negative_zero_not_minimal)
{
    // {0x80} = negative zero, NOT minimal
    std::vector<uint8_t> v{0x80};
    BOOST_CHECK(!ScriptNumEncoding::IsMinimallyEncoded(v, 4));
}

BOOST_AUTO_TEST_CASE(is_minimally_encoded_zero_byte_not_minimal)
{
    // {0x00} has MSB & 0x7f == 0 and is only 1 byte → not minimal
    std::vector<uint8_t> v{0x00};
    BOOST_CHECK(!ScriptNumEncoding::IsMinimallyEncoded(v, 4));
}

BOOST_AUTO_TEST_CASE(is_minimally_encoded_unnecessary_zero_prefix)
{
    // {0x00, 0x00} — trailing zero with no sign conflict → not minimal
    std::vector<uint8_t> v{0x00, 0x00};
    BOOST_CHECK(!ScriptNumEncoding::IsMinimallyEncoded(v, 4));
}

BOOST_AUTO_TEST_CASE(is_minimally_encoded_sign_preserved)
{
    // {0xff, 0x00} = +255, the 0x00 is needed because 0xff has MSB set
    // Without the sign byte, 0xff alone would be -127
    std::vector<uint8_t> v{0xff, 0x00};
    BOOST_CHECK(ScriptNumEncoding::IsMinimallyEncoded(v, 4));
}

BOOST_AUTO_TEST_CASE(is_minimally_encoded_negative_sign_preserved)
{
    // {0xff, 0x80} = -255, the 0x80 preserves the negative sign
    std::vector<uint8_t> v{0xff, 0x80};
    BOOST_CHECK(ScriptNumEncoding::IsMinimallyEncoded(v, 4));
}

BOOST_AUTO_TEST_CASE(is_minimally_encoded_two_byte_positive)
{
    // {0x00, 0x01} = 256 in little-endian script number format, minimal
    std::vector<uint8_t> v{0x00, 0x01};
    BOOST_CHECK(ScriptNumEncoding::IsMinimallyEncoded(v, 4));
}

// ============================================================================
// IsMinimallyEncoded — maxIntegerSize boundary
// ============================================================================

BOOST_AUTO_TEST_CASE(is_minimally_encoded_exceeds_max_size)
{
    // 5-byte number with maxIntegerSize=4 → too large
    std::vector<uint8_t> v{0x01, 0x02, 0x03, 0x04, 0x05};
    BOOST_CHECK(!ScriptNumEncoding::IsMinimallyEncoded(v, 4));
}

BOOST_AUTO_TEST_CASE(is_minimally_encoded_at_max_size)
{
    // 4-byte number with maxIntegerSize=4 → allowed
    std::vector<uint8_t> v{0x01, 0x02, 0x03, 0x04};
    BOOST_CHECK(ScriptNumEncoding::IsMinimallyEncoded(v, 4));
}

BOOST_AUTO_TEST_CASE(is_minimally_encoded_different_max_sizes)
{
    // 5-byte number
    std::vector<uint8_t> v{0x01, 0x02, 0x03, 0x04, 0x05};

    // Fails at maxIntegerSize=4
    BOOST_CHECK(!ScriptNumEncoding::IsMinimallyEncoded(v, 4));

    // Succeeds at maxIntegerSize=8 (VM limits active allows larger)
    BOOST_CHECK(ScriptNumEncoding::IsMinimallyEncoded(v, 8));

    // Succeeds at maxIntegerSize=10000 (full VM limits)
    BOOST_CHECK(ScriptNumEncoding::IsMinimallyEncoded(v, 10000));
}

BOOST_AUTO_TEST_CASE(is_minimally_encoded_8byte_boundary)
{
    // 8-byte number with maxIntegerSize=8 → allowed
    std::vector<uint8_t> v8{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    BOOST_CHECK(ScriptNumEncoding::IsMinimallyEncoded(v8, 8));

    // 9-byte number with maxIntegerSize=8 → too large
    std::vector<uint8_t> v9{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
    BOOST_CHECK(!ScriptNumEncoding::IsMinimallyEncoded(v9, 8));
}

BOOST_AUTO_TEST_CASE(is_minimally_encoded_large_vm_limits)
{
    // Large number (100 bytes) with VM limits maxIntegerSize=10000
    std::vector<uint8_t> v(100, 0x42);
    v.back() = 0x01; // Ensure MSB & 0x7f != 0 for minimality
    BOOST_CHECK(ScriptNumEncoding::IsMinimallyEncoded(v, 10000));
}

// ============================================================================
// MinimallyEncode — basic cases
// ============================================================================

BOOST_AUTO_TEST_CASE(minimally_encode_empty_returns_false)
{
    // Empty data → returns false (no change needed, already empty)
    std::vector<uint8_t> v{};
    BOOST_CHECK(!ScriptNumEncoding::MinimallyEncode(v));
    BOOST_CHECK(v.empty());
}

BOOST_AUTO_TEST_CASE(minimally_encode_already_minimal)
{
    // {0x42} is already minimal → returns false (no change)
    std::vector<uint8_t> v{0x42};
    BOOST_CHECK(!ScriptNumEncoding::MinimallyEncode(v));
    BOOST_CHECK_EQUAL(v.size(), 1u);
    BOOST_CHECK_EQUAL(v[0], 0x42);
}

BOOST_AUTO_TEST_CASE(minimally_encode_negative_zero_to_empty)
{
    // {0x80} = negative zero → minimizes to {}
    std::vector<uint8_t> v{0x80};
    BOOST_CHECK(ScriptNumEncoding::MinimallyEncode(v));
    BOOST_CHECK(v.empty());
}

BOOST_AUTO_TEST_CASE(minimally_encode_positive_zero_to_empty)
{
    // {0x00} → minimizes to {}
    std::vector<uint8_t> v{0x00};
    BOOST_CHECK(ScriptNumEncoding::MinimallyEncode(v));
    BOOST_CHECK(v.empty());
}

BOOST_AUTO_TEST_CASE(minimally_encode_removes_trailing_zeros)
{
    // {0x01, 0x00} = +1 with unnecessary sign byte (0x01 MSB is clear)
    // Should minimize to {0x01}
    std::vector<uint8_t> v{0x01, 0x00};
    BOOST_CHECK(ScriptNumEncoding::MinimallyEncode(v));
    BOOST_CHECK_EQUAL(v.size(), 1u);
    BOOST_CHECK_EQUAL(v[0], 0x01);
}

BOOST_AUTO_TEST_CASE(minimally_encode_preserves_needed_sign_byte)
{
    // {0xff, 0x00} = +255 — sign byte IS needed (0xff has MSB set)
    // Should remain unchanged → returns false
    std::vector<uint8_t> v{0xff, 0x00};
    BOOST_CHECK(!ScriptNumEncoding::MinimallyEncode(v));
    BOOST_CHECK_EQUAL(v.size(), 2u);
}

BOOST_AUTO_TEST_CASE(minimally_encode_negative_preserves_sign)
{
    // {0xff, 0x80} = -255 — negative sign byte IS needed
    // Should remain unchanged → returns false
    std::vector<uint8_t> v{0xff, 0x80};
    BOOST_CHECK(!ScriptNumEncoding::MinimallyEncode(v));
    BOOST_CHECK_EQUAL(v.size(), 2u);
}

BOOST_AUTO_TEST_CASE(minimally_encode_multiple_trailing_zeros)
{
    // {0x01, 0x00, 0x00, 0x00} → should minimize to {0x01}
    std::vector<uint8_t> v{0x01, 0x00, 0x00, 0x00};
    BOOST_CHECK(ScriptNumEncoding::MinimallyEncode(v));
    BOOST_CHECK_EQUAL(v.size(), 1u);
    BOOST_CHECK_EQUAL(v[0], 0x01);
}

BOOST_AUTO_TEST_CASE(minimally_encode_all_zeros)
{
    // {0x00, 0x00, 0x00} = zero → minimizes to {}
    std::vector<uint8_t> v{0x00, 0x00, 0x00};
    BOOST_CHECK(ScriptNumEncoding::MinimallyEncode(v));
    BOOST_CHECK(v.empty());
}

BOOST_AUTO_TEST_CASE(minimally_encode_negative_with_trailing_zeros)
{
    // {0x01, 0x00, 0x80} = -1 with extra zero byte
    // Should minimize to {0x81}
    std::vector<uint8_t> v{0x01, 0x00, 0x80};
    BOOST_CHECK(ScriptNumEncoding::MinimallyEncode(v));
    BOOST_CHECK_EQUAL(v.size(), 1u);
    BOOST_CHECK_EQUAL(v[0], 0x81);
}

BOOST_AUTO_TEST_CASE(minimally_encode_sign_bit_conflict)
{
    // {0x80, 0x00, 0x80} = -(128) with extra zero → should minimize to {0x80, 0x80}
    // 0x80 has MSB set, so we need the sign byte
    std::vector<uint8_t> v{0x80, 0x00, 0x80};
    BOOST_CHECK(ScriptNumEncoding::MinimallyEncode(v));
    BOOST_CHECK_EQUAL(v.size(), 2u);
    BOOST_CHECK_EQUAL(v[0], 0x80);
    BOOST_CHECK_EQUAL(v[1], 0x80);
}

// ============================================================================
// MinimallyEncode + IsMinimallyEncoded roundtrip
// ============================================================================

BOOST_AUTO_TEST_CASE(minimally_encode_result_is_minimal)
{
    // Various non-minimal inputs, after MinimallyEncode, should be IsMinimallyEncoded
    std::vector<std::vector<uint8_t>> nonMinimal = {
        {0x00},
        {0x80},
        {0x01, 0x00},
        {0x00, 0x00, 0x00},
        {0x01, 0x00, 0x00, 0x00},
        {0x01, 0x00, 0x80}, // -1 with extra
    };

    for (auto v : nonMinimal) {
        ScriptNumEncoding::MinimallyEncode(v);
        BOOST_CHECK_MESSAGE(ScriptNumEncoding::IsMinimallyEncoded(v, 10000),
            "After MinimallyEncode, result should be IsMinimallyEncoded");
    }
}

BOOST_AUTO_TEST_SUITE_END()
