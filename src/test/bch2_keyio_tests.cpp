// Copyright (c) 2026 The Bitcoin Cash II developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Tests for BCH2 address encoding/decoding via key_io.cpp.
// Covers CashAddr integration, EncodeDestination, DecodeDestination error paths.

#include <key.h>
#include <key_io.h>
#include <pubkey.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(bch2_keyio_tests, BasicTestingSetup)

// ===== EncodeDestination =====

BOOST_AUTO_TEST_CASE(encode_pkh_uses_cashaddr_prefix)
{
    // P2PKH addresses should use bitcoincashii: prefix
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();
    PKHash pkhash(pubkey);

    std::string addr = EncodeDestination(pkhash);
    BOOST_CHECK(addr.find("bitcoincashii:") == 0);
}

BOOST_AUTO_TEST_CASE(encode_sh_uses_cashaddr_prefix)
{
    // P2SH addresses should use bitcoincashii: prefix
    CScript redeemScript = CScript() << OP_TRUE;
    ScriptHash scripthash(redeemScript);

    std::string addr = EncodeDestination(scripthash);
    BOOST_CHECK(addr.find("bitcoincashii:") == 0);
}

BOOST_AUTO_TEST_CASE(encode_no_destination_returns_empty)
{
    std::string addr = EncodeDestination(CNoDestination());
    BOOST_CHECK(addr.empty());
}

// ===== DecodeDestination =====

BOOST_AUTO_TEST_CASE(decode_valid_p2pkh_roundtrip)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();
    PKHash pkhash(pubkey);

    std::string encoded = EncodeDestination(pkhash);
    CTxDestination decoded = DecodeDestination(encoded);
    BOOST_CHECK(IsValidDestination(decoded));

    // Should decode to PKHash
    auto* result = std::get_if<PKHash>(&decoded);
    BOOST_CHECK(result != nullptr);
    BOOST_CHECK(*result == pkhash);
}

BOOST_AUTO_TEST_CASE(decode_valid_p2sh_roundtrip)
{
    CScript redeemScript = CScript() << OP_DUP << OP_HASH160
                                     << std::vector<uint8_t>(20, 0x42)
                                     << OP_EQUALVERIFY << OP_CHECKSIG;
    ScriptHash scripthash(redeemScript);

    std::string encoded = EncodeDestination(scripthash);
    CTxDestination decoded = DecodeDestination(encoded);
    BOOST_CHECK(IsValidDestination(decoded));

    auto* result = std::get_if<ScriptHash>(&decoded);
    BOOST_CHECK(result != nullptr);
    BOOST_CHECK(*result == scripthash);
}

BOOST_AUTO_TEST_CASE(decode_invalid_cashaddr_returns_error)
{
    std::string error_msg;
    CTxDestination dest = DecodeDestination("bitcoincashii:invalidaddressdata", error_msg);
    BOOST_CHECK(!IsValidDestination(dest));
    // Should have an error message
    BOOST_CHECK(!error_msg.empty());
}

BOOST_AUTO_TEST_CASE(decode_empty_string)
{
    std::string error_msg;
    CTxDestination dest = DecodeDestination("", error_msg);
    BOOST_CHECK(!IsValidDestination(dest));
}

BOOST_AUTO_TEST_CASE(decode_random_string_not_valid)
{
    std::string error_msg;
    CTxDestination dest = DecodeDestination("notanaddress", error_msg);
    BOOST_CHECK(!IsValidDestination(dest));
}

BOOST_AUTO_TEST_CASE(is_valid_destination_string)
{
    CKey key;
    key.MakeNewKey(true);
    CPubKey pubkey = key.GetPubKey();
    PKHash pkhash(pubkey);

    std::string addr = EncodeDestination(pkhash);
    BOOST_CHECK(IsValidDestinationString(addr));
    BOOST_CHECK(!IsValidDestinationString("bitcoincashii:invalid"));
    BOOST_CHECK(!IsValidDestinationString(""));
}

// ===== WIF (DecodeSecret/EncodeSecret) =====

BOOST_AUTO_TEST_CASE(secret_key_roundtrip)
{
    CKey key;
    key.MakeNewKey(true);

    std::string wif = EncodeSecret(key);
    BOOST_CHECK(!wif.empty());

    CKey decoded = DecodeSecret(wif);
    BOOST_CHECK(decoded.IsValid());
    BOOST_CHECK(decoded.IsCompressed());
    BOOST_CHECK(key == decoded);
}

BOOST_AUTO_TEST_CASE(secret_key_uncompressed_roundtrip)
{
    CKey key;
    key.MakeNewKey(false);

    std::string wif = EncodeSecret(key);
    CKey decoded = DecodeSecret(wif);
    BOOST_CHECK(decoded.IsValid());
    BOOST_CHECK(!decoded.IsCompressed());
    BOOST_CHECK(key == decoded);
}

BOOST_AUTO_TEST_CASE(decode_secret_invalid_string)
{
    CKey key = DecodeSecret("notavalidwif");
    BOOST_CHECK(!key.IsValid());
}

BOOST_AUTO_TEST_CASE(decode_secret_empty_string)
{
    CKey key = DecodeSecret("");
    BOOST_CHECK(!key.IsValid());
}

// ===== Multiple encode/decode cycles =====

BOOST_AUTO_TEST_CASE(multiple_p2pkh_addresses_distinct)
{
    CKey key1, key2;
    key1.MakeNewKey(true);
    key2.MakeNewKey(true);

    std::string addr1 = EncodeDestination(PKHash(key1.GetPubKey()));
    std::string addr2 = EncodeDestination(PKHash(key2.GetPubKey()));

    // Different keys should produce different addresses
    BOOST_CHECK(addr1 != addr2);

    // Both should be valid
    BOOST_CHECK(IsValidDestinationString(addr1));
    BOOST_CHECK(IsValidDestinationString(addr2));
}

// ===== CashAddr with all-zeros hash =====

BOOST_AUTO_TEST_CASE(encode_decode_pkh_all_zeros)
{
    std::vector<uint8_t> zeros(20, 0x00);
    PKHash pkhash;
    std::copy(zeros.begin(), zeros.end(), pkhash.begin());

    std::string addr = EncodeDestination(pkhash);
    BOOST_CHECK(addr.find("bitcoincashii:") == 0);

    CTxDestination decoded = DecodeDestination(addr);
    BOOST_CHECK(IsValidDestination(decoded));
    auto* result = std::get_if<PKHash>(&decoded);
    BOOST_CHECK(result != nullptr);
    BOOST_CHECK(*result == pkhash);
}

BOOST_AUTO_TEST_CASE(encode_decode_pkh_all_ff)
{
    std::vector<uint8_t> ffs(20, 0xFF);
    PKHash pkhash;
    std::copy(ffs.begin(), ffs.end(), pkhash.begin());

    std::string addr = EncodeDestination(pkhash);
    BOOST_CHECK(addr.find("bitcoincashii:") == 0);

    CTxDestination decoded = DecodeDestination(addr);
    BOOST_CHECK(IsValidDestination(decoded));
    auto* result = std::get_if<PKHash>(&decoded);
    BOOST_CHECK(result != nullptr);
    BOOST_CHECK(*result == pkhash);
}

BOOST_AUTO_TEST_CASE(encode_decode_sh_all_zeros)
{
    std::vector<uint8_t> zeros(20, 0x00);
    ScriptHash sh;
    std::copy(zeros.begin(), zeros.end(), sh.begin());

    std::string addr = EncodeDestination(sh);
    BOOST_CHECK(addr.find("bitcoincashii:") == 0);

    CTxDestination decoded = DecodeDestination(addr);
    BOOST_CHECK(IsValidDestination(decoded));
    auto* result = std::get_if<ScriptHash>(&decoded);
    BOOST_CHECK(result != nullptr);
    BOOST_CHECK(*result == sh);
}

BOOST_AUTO_TEST_CASE(encode_decode_sh_all_ff)
{
    std::vector<uint8_t> ffs(20, 0xFF);
    ScriptHash sh;
    std::copy(ffs.begin(), ffs.end(), sh.begin());

    std::string addr = EncodeDestination(sh);
    BOOST_CHECK(addr.find("bitcoincashii:") == 0);

    CTxDestination decoded = DecodeDestination(addr);
    BOOST_CHECK(IsValidDestination(decoded));
    auto* result = std::get_if<ScriptHash>(&decoded);
    BOOST_CHECK(result != nullptr);
    BOOST_CHECK(*result == sh);
}

// ===== CashAddr type byte verification =====

BOOST_AUTO_TEST_CASE(p2pkh_cashaddr_has_q_after_prefix)
{
    CKey key;
    key.MakeNewKey(true);
    std::string addr = EncodeDestination(PKHash(key.GetPubKey()));
    // CashAddr type byte 0 (P2PKH) encodes to 'q'
    BOOST_CHECK_EQUAL(addr[14], 'q');
}

BOOST_AUTO_TEST_CASE(p2sh_cashaddr_has_p_after_prefix)
{
    CScript redeemScript = CScript() << OP_TRUE;
    std::string addr = EncodeDestination(ScriptHash(redeemScript));
    // CashAddr type byte for P2SH encodes to 'p'
    BOOST_CHECK_EQUAL(addr[14], 'p');
}

// ===== CashAddr single-bit-flip detection =====

BOOST_AUTO_TEST_CASE(cashaddr_bitflip_detected)
{
    CKey key;
    key.MakeNewKey(true);
    std::string addr = EncodeDestination(PKHash(key.GetPubKey()));

    // Flip a character in the middle of the data portion
    std::string corrupted = addr;
    size_t pos = 20; // well into the data portion
    if (corrupted[pos] == 'q') {
        corrupted[pos] = 'r';
    } else {
        corrupted[pos] = 'q';
    }

    std::string error_msg;
    CTxDestination dest = DecodeDestination(corrupted, error_msg);
    BOOST_CHECK(!IsValidDestination(dest));
}

// ===== WIF edge cases =====

BOOST_AUTO_TEST_CASE(wif_truncated_string_invalid)
{
    CKey key;
    key.MakeNewKey(true);
    std::string wif = EncodeSecret(key);

    // Truncate the WIF string
    std::string truncated = wif.substr(0, wif.size() / 2);
    CKey decoded = DecodeSecret(truncated);
    BOOST_CHECK(!decoded.IsValid());
}

BOOST_AUTO_TEST_CASE(wif_corrupted_checksum_invalid)
{
    CKey key;
    key.MakeNewKey(true);
    std::string wif = EncodeSecret(key);

    // Modify the last character (part of checksum)
    std::string corrupted = wif;
    char& last = corrupted.back();
    last = (last == '1') ? '2' : '1';

    CKey decoded = DecodeSecret(corrupted);
    BOOST_CHECK(!decoded.IsValid());
}

// ===== Encode same key twice produces same address =====

BOOST_AUTO_TEST_CASE(encode_deterministic)
{
    CKey key;
    key.MakeNewKey(true);
    PKHash pkhash(key.GetPubKey());

    std::string addr1 = EncodeDestination(pkhash);
    std::string addr2 = EncodeDestination(pkhash);
    BOOST_CHECK_EQUAL(addr1, addr2);
}

// ===== Multiple WIF roundtrips =====

BOOST_AUTO_TEST_CASE(wif_multiple_keys_roundtrip)
{
    for (int i = 0; i < 5; ++i) {
        CKey key;
        key.MakeNewKey(i % 2 == 0); // alternate compressed/uncompressed
        std::string wif = EncodeSecret(key);
        CKey decoded = DecodeSecret(wif);
        BOOST_CHECK(decoded.IsValid());
        BOOST_CHECK(key == decoded);
        BOOST_CHECK_EQUAL(key.IsCompressed(), decoded.IsCompressed());
    }
}

BOOST_AUTO_TEST_SUITE_END()
