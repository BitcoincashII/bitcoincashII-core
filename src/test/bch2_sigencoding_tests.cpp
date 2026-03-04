// Copyright (c) 2026 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests for BCH2 signature hash type encoding and classification.
// Covers SigHashType class, GetHashType helper, and flag verification.

#include <script/sigencoding.h>
#include <script/sighashtype.h>
#include <script/container_types.h>
#include <script/script_error.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(bch2_sigencoding_tests)

// ===== SigHashType.isDefined() =====

BOOST_AUTO_TEST_CASE(sighashtype_all_defined)
{
    BOOST_CHECK(SigHashType(SIGHASH_ALL).isDefined());
}

BOOST_AUTO_TEST_CASE(sighashtype_none_defined)
{
    BOOST_CHECK(SigHashType(SIGHASH_NONE).isDefined());
}

BOOST_AUTO_TEST_CASE(sighashtype_single_defined)
{
    BOOST_CHECK(SigHashType(SIGHASH_SINGLE).isDefined());
}

BOOST_AUTO_TEST_CASE(sighashtype_all_forkid_defined)
{
    BOOST_CHECK(SigHashType(SIGHASH_ALL | SIGHASH_FORKID).isDefined());
}

BOOST_AUTO_TEST_CASE(sighashtype_all_anyonecanpay_defined)
{
    BOOST_CHECK(SigHashType(SIGHASH_ALL | SIGHASH_ANYONECANPAY).isDefined());
}

BOOST_AUTO_TEST_CASE(sighashtype_all_forkid_anyonecanpay_defined)
{
    BOOST_CHECK(SigHashType(SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_ANYONECANPAY).isDefined());
}

BOOST_AUTO_TEST_CASE(sighashtype_all_utxos_forkid_defined)
{
    BOOST_CHECK(SigHashType(SIGHASH_ALL | SIGHASH_UTXOS | SIGHASH_FORKID).isDefined());
}

BOOST_AUTO_TEST_CASE(sighashtype_zero_not_defined)
{
    // basetype 0 is UNSUPPORTED
    BOOST_CHECK(!SigHashType(0).isDefined());
}

BOOST_AUTO_TEST_CASE(sighashtype_four_not_defined)
{
    // basetype > SINGLE (3) is not defined
    BOOST_CHECK(!SigHashType(4).isDefined());
}

BOOST_AUTO_TEST_CASE(sighashtype_forkid_only_not_defined)
{
    // 0x40 = FORKID with basetype 0 (UNSUPPORTED)
    BOOST_CHECK(!SigHashType(SIGHASH_FORKID).isDefined());
}

// ===== SigHashType flag accessors =====

BOOST_AUTO_TEST_CASE(sighashtype_has_fork)
{
    BOOST_CHECK(SigHashType(SIGHASH_ALL | SIGHASH_FORKID).hasFork());
    BOOST_CHECK(!SigHashType(SIGHASH_ALL).hasFork());
}

BOOST_AUTO_TEST_CASE(sighashtype_has_anyonecanpay)
{
    BOOST_CHECK(SigHashType(SIGHASH_ALL | SIGHASH_ANYONECANPAY).hasAnyoneCanPay());
    BOOST_CHECK(!SigHashType(SIGHASH_ALL).hasAnyoneCanPay());
}

BOOST_AUTO_TEST_CASE(sighashtype_has_utxos)
{
    BOOST_CHECK(SigHashType(SIGHASH_ALL | SIGHASH_UTXOS).hasUtxos());
    BOOST_CHECK(!SigHashType(SIGHASH_ALL).hasUtxos());
}

BOOST_AUTO_TEST_CASE(sighashtype_get_base_type)
{
    BOOST_CHECK(SigHashType(SIGHASH_ALL | SIGHASH_FORKID).getBaseType() == BaseSigHashType::ALL);
    BOOST_CHECK(SigHashType(SIGHASH_NONE | SIGHASH_FORKID).getBaseType() == BaseSigHashType::NONE);
    BOOST_CHECK(SigHashType(SIGHASH_SINGLE | SIGHASH_FORKID).getBaseType() == BaseSigHashType::SINGLE);
}

BOOST_AUTO_TEST_CASE(sighashtype_all_flags_combined)
{
    SigHashType t(SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_ANYONECANPAY | SIGHASH_UTXOS);
    BOOST_CHECK(t.hasFork());
    BOOST_CHECK(t.hasAnyoneCanPay());
    BOOST_CHECK(t.hasUtxos());
    BOOST_CHECK(t.getBaseType() == BaseSigHashType::ALL);
    BOOST_CHECK(t.isDefined());
}

// ===== SigHashType with* modifiers =====

BOOST_AUTO_TEST_CASE(sighashtype_with_fork)
{
    SigHashType base(SIGHASH_ALL);
    auto forked = base.withFork();
    BOOST_CHECK(forked.hasFork());
    BOOST_CHECK_EQUAL(forked.getRawSigHashType(), static_cast<uint32_t>(SIGHASH_ALL | SIGHASH_FORKID));
}

BOOST_AUTO_TEST_CASE(sighashtype_with_fork_false)
{
    SigHashType base(SIGHASH_ALL | SIGHASH_FORKID);
    auto unforked = base.withFork(false);
    BOOST_CHECK(!unforked.hasFork());
    BOOST_CHECK_EQUAL(unforked.getRawSigHashType(), static_cast<uint32_t>(SIGHASH_ALL));
}

BOOST_AUTO_TEST_CASE(sighashtype_with_utxos)
{
    SigHashType base(SIGHASH_ALL | SIGHASH_FORKID);
    auto withUtxos = base.withUtxos();
    BOOST_CHECK(withUtxos.hasUtxos());
    BOOST_CHECK(withUtxos.hasFork());
    BOOST_CHECK_EQUAL(withUtxos.getRawSigHashType(),
                      static_cast<uint32_t>(SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_UTXOS));
}

BOOST_AUTO_TEST_CASE(sighashtype_with_anyonecanpay)
{
    SigHashType base(SIGHASH_NONE);
    auto withACP = base.withAnyoneCanPay();
    BOOST_CHECK(withACP.hasAnyoneCanPay());
    BOOST_CHECK_EQUAL(withACP.getRawSigHashType(),
                      static_cast<uint32_t>(SIGHASH_NONE | SIGHASH_ANYONECANPAY));
}

BOOST_AUTO_TEST_CASE(sighashtype_with_base_type)
{
    SigHashType base(SIGHASH_ALL | SIGHASH_FORKID);
    auto changed = base.withBaseType(BaseSigHashType::SINGLE);
    BOOST_CHECK(changed.getBaseType() == BaseSigHashType::SINGLE);
    BOOST_CHECK(changed.hasFork());
}

BOOST_AUTO_TEST_CASE(sighashtype_chained_modifiers)
{
    SigHashType result = SigHashType(SIGHASH_ALL)
        .withFork()
        .withUtxos()
        .withAnyoneCanPay();
    BOOST_CHECK(result.hasFork());
    BOOST_CHECK(result.hasUtxos());
    BOOST_CHECK(result.hasAnyoneCanPay());
    BOOST_CHECK(result.getBaseType() == BaseSigHashType::ALL);
}

// ===== SigHashType equality =====

BOOST_AUTO_TEST_CASE(sighashtype_equality)
{
    SigHashType a(SIGHASH_ALL | SIGHASH_FORKID);
    SigHashType b(SIGHASH_ALL | SIGHASH_FORKID);
    BOOST_CHECK(a == b);
    BOOST_CHECK(!(a != b));
}

BOOST_AUTO_TEST_CASE(sighashtype_inequality)
{
    SigHashType a(SIGHASH_ALL | SIGHASH_FORKID);
    SigHashType b(SIGHASH_NONE | SIGHASH_FORKID);
    BOOST_CHECK(a != b);
    BOOST_CHECK(!(a == b));
}

// ===== SigHashType raw value =====

BOOST_AUTO_TEST_CASE(sighashtype_raw_value)
{
    BOOST_CHECK_EQUAL(SigHashType(0x41).getRawSigHashType(), 0x41u);
    BOOST_CHECK_EQUAL(SigHashType(0xE1).getRawSigHashType(), 0xE1u);
}

// ===== SigHashType serialization roundtrip =====

BOOST_AUTO_TEST_CASE(sighashtype_serialization_roundtrip)
{
    SigHashType original(SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_UTXOS);
    DataStream ss{};
    original.Serialize(ss);
    SigHashType deserialized;
    deserialized.Unserialize(ss);
    BOOST_CHECK(original == deserialized);
}

// ===== GetHashType helper =====

BOOST_AUTO_TEST_CASE(get_hash_type_from_sig_bytes)
{
    // Last byte of signature is the hashtype
    std::vector<uint8_t> sig = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x41};
    std::span<const uint8_t> view{sig.data(), sig.size()};
    BOOST_CHECK(GetHashType(view) == SigHashType(0x41));
}

BOOST_AUTO_TEST_CASE(get_hash_type_empty_sig)
{
    std::span<const uint8_t> view{};
    BOOST_CHECK(GetHashType(view) == SigHashType(0));
}

BOOST_AUTO_TEST_CASE(get_hash_type_single_byte)
{
    std::vector<uint8_t> sig = {0xC1}; // SIGHASH_ALL|FORKID|ANYONECANPAY
    std::span<const uint8_t> view{sig.data(), sig.size()};
    BOOST_CHECK(GetHashType(view) == SigHashType(0xC1));
}

// ===== SIGHASH constant values =====

BOOST_AUTO_TEST_CASE(sighash_constant_values)
{
    BOOST_CHECK_EQUAL(SIGHASH_ALL, 1);
    BOOST_CHECK_EQUAL(SIGHASH_NONE, 2);
    BOOST_CHECK_EQUAL(SIGHASH_SINGLE, 3);
    BOOST_CHECK_EQUAL(SIGHASH_UTXOS, 0x20);
    BOOST_CHECK_EQUAL(SIGHASH_FORKID, 0x40);
    BOOST_CHECK_EQUAL(SIGHASH_ANYONECANPAY, 0x80);
}

// ===== BaseSigHashType enum =====

BOOST_AUTO_TEST_CASE(base_sighash_type_values)
{
    BOOST_CHECK(static_cast<uint8_t>(BaseSigHashType::UNSUPPORTED) == 0);
    BOOST_CHECK(static_cast<uint8_t>(BaseSigHashType::ALL) == 1);
    BOOST_CHECK(static_cast<uint8_t>(BaseSigHashType::NONE) == 2);
    BOOST_CHECK(static_cast<uint8_t>(BaseSigHashType::SINGLE) == 3);
}

// ===== SigHashType UTXOS flag combinations =====

BOOST_AUTO_TEST_CASE(sighashtype_utxos_with_forkid_defined)
{
    SigHashType t(SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_UTXOS);
    BOOST_CHECK(t.isDefined());
    BOOST_CHECK(t.hasFork());
    BOOST_CHECK(t.hasUtxos());
    BOOST_CHECK(!t.hasAnyoneCanPay());
}

BOOST_AUTO_TEST_CASE(sighashtype_utxos_without_forkid_defined)
{
    // UTXOS without FORKID: still "defined" per isDefined() — enforcement is in CheckSighashEncoding
    SigHashType t(SIGHASH_ALL | SIGHASH_UTXOS);
    BOOST_CHECK(t.isDefined());
    BOOST_CHECK(t.hasUtxos());
    BOOST_CHECK(!t.hasFork());
}

BOOST_AUTO_TEST_CASE(sighashtype_utxos_with_anyonecanpay_defined)
{
    // UTXOS + ANYONECANPAY: structurally defined but rejected by CheckSighashEncoding
    SigHashType t(SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_UTXOS | SIGHASH_ANYONECANPAY);
    BOOST_CHECK(t.isDefined());
    BOOST_CHECK(t.hasUtxos());
    BOOST_CHECK(t.hasAnyoneCanPay());
    BOOST_CHECK(t.hasFork());
}

BOOST_AUTO_TEST_CASE(sighashtype_none_utxos_forkid_defined)
{
    SigHashType t(SIGHASH_NONE | SIGHASH_FORKID | SIGHASH_UTXOS);
    BOOST_CHECK(t.isDefined());
    BOOST_CHECK(t.getBaseType() == BaseSigHashType::NONE);
    BOOST_CHECK(t.hasUtxos());
}

BOOST_AUTO_TEST_CASE(sighashtype_single_utxos_forkid_defined)
{
    SigHashType t(SIGHASH_SINGLE | SIGHASH_FORKID | SIGHASH_UTXOS);
    BOOST_CHECK(t.isDefined());
    BOOST_CHECK(t.getBaseType() == BaseSigHashType::SINGLE);
    BOOST_CHECK(t.hasUtxos());
}

// ===== SigHashType withUtxos modifier edge cases =====

BOOST_AUTO_TEST_CASE(sighashtype_with_utxos_false)
{
    SigHashType base(SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_UTXOS);
    auto removed = base.withUtxos(false);
    BOOST_CHECK(!removed.hasUtxos());
    BOOST_CHECK(removed.hasFork());
    BOOST_CHECK_EQUAL(removed.getRawSigHashType(),
                      static_cast<uint32_t>(SIGHASH_ALL | SIGHASH_FORKID));
}

BOOST_AUTO_TEST_CASE(sighashtype_with_anyonecanpay_false)
{
    SigHashType base(SIGHASH_ALL | SIGHASH_ANYONECANPAY);
    auto removed = base.withAnyoneCanPay(false);
    BOOST_CHECK(!removed.hasAnyoneCanPay());
    BOOST_CHECK_EQUAL(removed.getRawSigHashType(), static_cast<uint32_t>(SIGHASH_ALL));
}

// ===== SigHashType withBaseType preserves flags =====

BOOST_AUTO_TEST_CASE(sighashtype_with_base_type_preserves_forkid)
{
    SigHashType base(SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_ANYONECANPAY);
    auto changed = base.withBaseType(BaseSigHashType::NONE);
    BOOST_CHECK(changed.getBaseType() == BaseSigHashType::NONE);
    BOOST_CHECK(changed.hasFork());
    BOOST_CHECK(changed.hasAnyoneCanPay());
}

BOOST_AUTO_TEST_CASE(sighashtype_with_base_type_preserves_utxos)
{
    SigHashType base(SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_UTXOS);
    auto changed = base.withBaseType(BaseSigHashType::SINGLE);
    BOOST_CHECK(changed.getBaseType() == BaseSigHashType::SINGLE);
    BOOST_CHECK(changed.hasFork());
    BOOST_CHECK(changed.hasUtxos());
}

// ===== SigHashType isDefined edge cases =====

BOOST_AUTO_TEST_CASE(sighashtype_basetype_5_not_defined)
{
    BOOST_CHECK(!SigHashType(5).isDefined());
}

BOOST_AUTO_TEST_CASE(sighashtype_basetype_0x1f_not_defined)
{
    // 0x1f = all lower 5 bits set, basetype masked = 31 ≠ 1,2,3
    BOOST_CHECK(!SigHashType(0x1f).isDefined());
}

BOOST_AUTO_TEST_CASE(sighashtype_all_flags_set_0xff_not_defined)
{
    // 0xFF: basetype = 0xFF & ~(FORKID|ANYONECANPAY|UTXOS) = 0xFF & ~0xE0 = 0x1F → undefined
    BOOST_CHECK(!SigHashType(0xFF).isDefined());
}

BOOST_AUTO_TEST_CASE(sighashtype_only_anyonecanpay_not_defined)
{
    // 0x80 → basetype = 0 (UNSUPPORTED)
    BOOST_CHECK(!SigHashType(SIGHASH_ANYONECANPAY).isDefined());
}

BOOST_AUTO_TEST_CASE(sighashtype_only_utxos_not_defined)
{
    // 0x20 → basetype = 0 (UNSUPPORTED)
    BOOST_CHECK(!SigHashType(SIGHASH_UTXOS).isDefined());
}

// ===== GetHashType edge cases =====

BOOST_AUTO_TEST_CASE(get_hash_type_two_bytes)
{
    std::vector<uint8_t> sig = {0xFF, 0x42};
    ByteView view{sig};
    // Last byte (0x42) is the hashtype
    BOOST_CHECK(GetHashType(view) == SigHashType(0x42));
}

BOOST_AUTO_TEST_CASE(get_hash_type_max_hashtype)
{
    std::vector<uint8_t> sig = {0x00, 0xFF};
    ByteView view{sig};
    BOOST_CHECK(GetHashType(view) == SigHashType(0xFF));
}

BOOST_AUTO_TEST_CASE(get_hash_type_zero_hashtype)
{
    std::vector<uint8_t> sig = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00};
    ByteView view{sig};
    BOOST_CHECK(GetHashType(view) == SigHashType(0x00));
}

BOOST_AUTO_TEST_CASE(get_hash_type_utxos_forkid_all)
{
    // 0x61 = SIGHASH_ALL | SIGHASH_FORKID | SIGHASH_UTXOS
    std::vector<uint8_t> sig = {0x00, 0x61};
    ByteView view{sig};
    auto ht = GetHashType(view);
    BOOST_CHECK(ht.hasFork());
    BOOST_CHECK(ht.hasUtxos());
    BOOST_CHECK(!ht.hasAnyoneCanPay());
    BOOST_CHECK(ht.getBaseType() == BaseSigHashType::ALL);
}

// ===== SigHashType raw byte values (comprehensive) =====

BOOST_AUTO_TEST_CASE(sighashtype_raw_0x41_is_all_forkid)
{
    SigHashType t(0x41);
    BOOST_CHECK(t.getBaseType() == BaseSigHashType::ALL);
    BOOST_CHECK(t.hasFork());
    BOOST_CHECK(!t.hasAnyoneCanPay());
    BOOST_CHECK(!t.hasUtxos());
    BOOST_CHECK(t.isDefined());
}

BOOST_AUTO_TEST_CASE(sighashtype_raw_0x42_is_none_forkid)
{
    SigHashType t(0x42);
    BOOST_CHECK(t.getBaseType() == BaseSigHashType::NONE);
    BOOST_CHECK(t.hasFork());
    BOOST_CHECK(t.isDefined());
}

BOOST_AUTO_TEST_CASE(sighashtype_raw_0x43_is_single_forkid)
{
    SigHashType t(0x43);
    BOOST_CHECK(t.getBaseType() == BaseSigHashType::SINGLE);
    BOOST_CHECK(t.hasFork());
    BOOST_CHECK(t.isDefined());
}

BOOST_AUTO_TEST_CASE(sighashtype_raw_0xC1_is_all_forkid_anyonecanpay)
{
    SigHashType t(0xC1);
    BOOST_CHECK(t.getBaseType() == BaseSigHashType::ALL);
    BOOST_CHECK(t.hasFork());
    BOOST_CHECK(t.hasAnyoneCanPay());
    BOOST_CHECK(!t.hasUtxos());
    BOOST_CHECK(t.isDefined());
}

BOOST_AUTO_TEST_CASE(sighashtype_raw_0x61_is_all_forkid_utxos)
{
    SigHashType t(0x61);
    BOOST_CHECK(t.getBaseType() == BaseSigHashType::ALL);
    BOOST_CHECK(t.hasFork());
    BOOST_CHECK(t.hasUtxos());
    BOOST_CHECK(!t.hasAnyoneCanPay());
    BOOST_CHECK(t.isDefined());
}

BOOST_AUTO_TEST_CASE(sighashtype_raw_0xE1_is_all_forkid_utxos_anyonecanpay)
{
    SigHashType t(0xE1);
    BOOST_CHECK(t.getBaseType() == BaseSigHashType::ALL);
    BOOST_CHECK(t.hasFork());
    BOOST_CHECK(t.hasUtxos());
    BOOST_CHECK(t.hasAnyoneCanPay());
    BOOST_CHECK(t.isDefined());
}

// ===== SigHashType default constructor =====

BOOST_AUTO_TEST_CASE(sighashtype_default_is_all)
{
    SigHashType t;
    BOOST_CHECK_EQUAL(t.getRawSigHashType(), static_cast<uint32_t>(SIGHASH_ALL));
    BOOST_CHECK(t.getBaseType() == BaseSigHashType::ALL);
    BOOST_CHECK(!t.hasFork());
    BOOST_CHECK(!t.hasAnyoneCanPay());
    BOOST_CHECK(!t.hasUtxos());
}

// ===== SigHashType serialization with all combinations =====

BOOST_AUTO_TEST_CASE(sighashtype_serialization_roundtrip_all_flags)
{
    SigHashType original(SIGHASH_SINGLE | SIGHASH_FORKID | SIGHASH_ANYONECANPAY | SIGHASH_UTXOS);
    DataStream ss{};
    original.Serialize(ss);
    SigHashType deserialized;
    deserialized.Unserialize(ss);
    BOOST_CHECK(original == deserialized);
    BOOST_CHECK(deserialized.getBaseType() == BaseSigHashType::SINGLE);
    BOOST_CHECK(deserialized.hasFork());
    BOOST_CHECK(deserialized.hasAnyoneCanPay());
    BOOST_CHECK(deserialized.hasUtxos());
}

BOOST_AUTO_TEST_CASE(sighashtype_serialization_minimal)
{
    SigHashType original(SIGHASH_ALL);
    DataStream ss{};
    original.Serialize(ss);
    SigHashType deserialized(0xFF); // Start with different value
    deserialized.Unserialize(ss);
    BOOST_CHECK(original == deserialized);
    BOOST_CHECK_EQUAL(deserialized.getRawSigHashType(), static_cast<uint32_t>(SIGHASH_ALL));
}

// ============================================================================
// IsFinalTx: pure function tests (from consensus/tx_verify.h)
// The BCH2 fork doesn't change IsFinalTx behavior, but these tests verify
// the locktime/sequence logic works correctly in our fork.
// ============================================================================

// (IsFinalTx tests are in bch2_consensus_tests.cpp since they need tx_verify.h)

BOOST_AUTO_TEST_SUITE_END()
