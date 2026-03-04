#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Cash II developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test BCH2 wallet import restrictions for SegWit migration.

Verifies:
1. importaddress with bech32 address rejected
2. importdescriptors with active witness descriptor rejected
3. importdescriptors with inactive witness descriptor allowed (for migration)
4. importprivkey does not import witness scripts post-fork
"""

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.script import hash160
from test_framework.segwit_addr import encode_segwit_address
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class BCH2WalletImportTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-deprecatedrpc=create_bdb"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Mining past fork height + maturity...")
        self.generate(node, 201 + COINBASE_MATURITY)

        # Get the default descriptor wallet handle (before creating other wallets)
        default_wallet = node.listwallets()[0]
        desc_w = node.get_wallet_rpc(default_wallet)

        # Get a pubkey from the descriptor wallet for constructing test addresses
        default_addr = desc_w.getnewaddress()
        pubkey_hex = desc_w.getaddressinfo(default_addr)['pubkey']
        pubkey_bytes = bytes.fromhex(pubkey_hex)
        h160 = hash160(pubkey_bytes)
        bech32_addr = encode_segwit_address("bcrt", 0, h160)
        assert bech32_addr is not None, "Failed to encode bech32 address"

        # Create a legacy wallet for importaddress/importprivkey tests
        node.createwallet("legacy_w", descriptors=False)
        legacy_w = node.get_wallet_rpc("legacy_w")

        self.log.info("Test 1: importaddress with bech32 address rejected")
        assert_raises_rpc_error(
            -5, "Witness/SegWit addresses cannot be imported after BCH2 fork",
            legacy_w.importaddress, bech32_addr
        )
        self.log.info("importaddress correctly rejects bech32 address")

        self.log.info("Test 2: importdescriptors with active witness descriptor rejected")
        # Use a watch-only descriptor wallet to avoid "no private keys" errors
        node.createwallet("desc_watch", descriptors=True, disable_private_keys=True)
        watch_w = node.get_wallet_rpc("desc_watch")
        wpkh_desc_raw = f"wpkh({pubkey_hex})"
        wpkh_desc = desc_w.getdescriptorinfo(wpkh_desc_raw)['descriptor']
        result = watch_w.importdescriptors([{
            "desc": wpkh_desc,
            "timestamp": "now",
            "active": True,
        }])
        assert_equal(result[0]['success'], False)
        assert "Witness/SegWit descriptors cannot be set as active" in result[0]['error']['message'], \
            f"Expected active witness rejection, got: {result[0]['error']['message']}"
        self.log.info("importdescriptors correctly rejects active witness descriptor")

        self.log.info("Test 3: importdescriptors with inactive witness descriptor allowed")
        result = watch_w.importdescriptors([{
            "desc": wpkh_desc,
            "timestamp": "now",
            "active": False,
        }])
        assert_equal(result[0]['success'], True)
        warnings = result[0].get('warnings', [])
        assert any("SegWit descriptor" in w for w in warnings), \
            f"Expected SegWit migration warning, got: {warnings}"
        self.log.info(f"Inactive witness descriptor imported with warning: {warnings[0]}")

        self.log.info("Test 4: importprivkey imports CashAddr P2PKH as primary address")
        # Create a second legacy wallet to import into
        node.createwallet("legacy_target", descriptors=False)
        target_w = node.get_wallet_rpc("legacy_target")

        # Get a private key from the source legacy wallet
        src_addr = legacy_w.getnewaddress()
        privkey = legacy_w.dumpprivkey(src_addr)

        # Import into target wallet
        target_w.importprivkey(privkey, "imported", False)

        # Verify the CashAddr P2PKH address IS imported and is the primary type
        assert src_addr.startswith("bitcoincashii:"), \
            f"Source address should be CashAddr, got: {src_addr}"
        pkh_info = target_w.getaddressinfo(src_addr)
        assert pkh_info.get('ismine', False), \
            "P2PKH address should be mine after importprivkey"
        assert_equal(pkh_info.get('iswitness', False), False)

        # Count address types - CashAddr P2PKH must be present
        addrs = target_w.getaddressesbylabel("imported")
        cashaddr_count = sum(1 for a in addrs if a.startswith("bitcoincashii:"))
        assert cashaddr_count >= 1, \
            f"Expected at least one CashAddr address, got {cashaddr_count}"
        self.log.info(f"importprivkey: {cashaddr_count} CashAddr of {len(addrs)} total addresses imported")

        # Verify NO witness addresses leaked into the address book post-fork
        for a in addrs:
            a_info = target_w.getaddressinfo(a)
            assert not a_info.get('iswitness', False), \
                f"Witness address should not be imported post-fork: {a}"
        self.log.info("Confirmed: no witness addresses in address book")

        self.log.info("All BCH2 wallet import tests passed!")


if __name__ == '__main__':
    BCH2WalletImportTest().main()
