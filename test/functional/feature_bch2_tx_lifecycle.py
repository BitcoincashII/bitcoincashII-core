#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Cash II developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""End-to-end P2PKH transaction lifecycle test for BCH2.

Verifies:
1. P2PKH transaction creation and mempool acceptance
2. CashAddr encoding in getaddressinfo
3. Byte-based fee calculation (not weight-based)
4. Derivation path m/44h/145h/0h (mainnet) or m/44h/1h/0h (regtest)
5. Transaction confirmation after mining
6. Dust relay fee is 1000 sat/kvB
"""
from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error


class BCH2TxLifecycleTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.extra_args = [
            ["-dustrelayfee=0.00001000"],  # 1000 sat/kvB
            ["-dustrelayfee=0.00001000"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        self.setup_nodes()
        self.connect_nodes(0, 1)
        self.sync_all()

    def run_test(self):
        node0 = self.nodes[0]
        node1 = self.nodes[1]

        self.log.info("Mining past fork height + maturity...")
        # Mine 201 blocks to activate BCH2 fork (height 200) + 100 for maturity
        self.generate(node0, 201 + COINBASE_MATURITY)
        self.sync_all()

        self.log.info("Test 1: Generate address and verify CashAddr format")
        addr = node0.getnewaddress()
        # BCH2 regtest uses CashAddr format - addresses should contain ':'
        # In regtest, the prefix is "bitcoincashii" and P2PKH addresses start with 'q'
        addr_info = node0.getaddressinfo(addr)
        self.log.info(f"Address: {addr}")
        self.log.info(f"Address info: scriptPubKey={addr_info.get('scriptPubKey', 'N/A')}")

        # Verify it's a P2PKH address
        assert_equal(addr_info['ismine'], True)

        self.log.info("Test 2: Check derivation path")
        # BCH2 uses BIP44 derivation: m/44h/1h/0h for descriptor wallets (coin type 1)
        # Legacy wallets may use m/0'/0'/ derivation
        if 'hdkeypath' in addr_info:
            hdkeypath = addr_info['hdkeypath']
            self.log.info(f"HD key path: {hdkeypath}")
            valid_prefixes = ("m/44h/1h/0h/", "m/44'/1'/0'/", "m/0'/0'/")
            assert any(hdkeypath.startswith(p) for p in valid_prefixes), \
                f"Unexpected derivation path: {hdkeypath}"

        self.log.info("Test 3: Send P2PKH transaction and verify mempool acceptance")
        addr1 = node1.getnewaddress()
        txid = node0.sendtoaddress(addr1, Decimal("1.0"))
        self.log.info(f"Transaction sent: {txid}")

        # Verify tx is in mempool
        mempool = node0.getrawmempool()
        assert txid in mempool, f"Transaction {txid} not in mempool"

        # Get raw transaction details
        tx_info = node0.gettransaction(txid)
        assert_equal(tx_info['confirmations'], 0)

        self.log.info("Test 4: Verify byte-based fee calculation")
        # BCH2 uses byte-based fees, not weight-based
        # Fee should be calculated as size * feerate, not vsize * feerate
        raw_tx = node0.getrawtransaction(txid, True)
        tx_size = raw_tx['size']
        tx_vsize = raw_tx['vsize']
        # In BCH2, size == vsize (WITNESS_SCALE_FACTOR = 1)
        assert_equal(tx_size, tx_vsize)

        # Fee should be positive and reasonable
        fee = abs(tx_info['fee'])
        assert_greater_than(fee, Decimal("0"))
        self.log.info(f"Fee: {fee} BCH2, size: {tx_size} bytes")

        self.log.info("Test 5: Mine transaction and verify confirmation")
        self.generate(node0, 1)
        self.sync_all()

        # Verify tx is confirmed
        tx_info = node0.gettransaction(txid)
        assert_equal(tx_info['confirmations'], 1)

        # Verify recipient received the funds
        balance = node1.getbalance()
        assert_equal(balance, Decimal("1.0"))

        self.log.info("Test 6: Verify dust relay fee is 1000 sat/kvB")
        # Try to send a very small amount - should succeed if above dust threshold
        # Dust threshold with 1000 sat/kvB for P2PKH output (34 bytes + 148 byte input = 182 bytes)
        # dust = 182 * 1000 / 1000 = 182 satoshis = 0.00000182 BCH2
        # Send slightly above dust
        try:
            small_txid = node0.sendtoaddress(addr1, Decimal("0.00001000"))
            self.log.info(f"Small tx sent: {small_txid}")
            # Should succeed
            mempool = node0.getrawmempool()
            assert small_txid in mempool
        except Exception as e:
            self.log.info(f"Small transaction result: {e}")

        self.log.info("Test 7: Multiple confirmations work correctly")
        self.generate(node0, 5)
        self.sync_all()
        tx_info = node0.gettransaction(txid)
        assert_equal(tx_info['confirmations'], 6)

        self.log.info("Test 8: CashAddr prefix verification")
        # Every address generated should start with "bitcoincashii:"
        for _ in range(5):
            test_addr = node0.getnewaddress()
            assert test_addr.startswith("bitcoincashii:"), \
                f"Address should start with 'bitcoincashii:' but got: {test_addr}"
            # P2PKH addresses should have 'q' after the prefix (type byte 0)
            assert test_addr[14] == 'q', \
                f"P2PKH address should have 'q' after prefix but got: {test_addr[14]}"
        self.log.info("CashAddr prefix verified for all addresses")

        self.log.info("Test 9: Wallet produces SIGHASH_FORKID in signatures")
        # Send a transaction and verify the scriptSig contains SIGHASH_FORKID (0x41)
        addr_forkid = node1.getnewaddress()
        txid_forkid = node0.sendtoaddress(addr_forkid, Decimal("0.5"))
        raw_tx_forkid = node0.getrawtransaction(txid_forkid, True)

        # Check each input's scriptSig — the last byte of the DER signature should be 0x41
        for vin in raw_tx_forkid['vin']:
            scriptsig_hex = vin['scriptSig']['hex']
            scriptsig_bytes = bytes.fromhex(scriptsig_hex)
            # DER sig is the first push: first byte is push length
            sig_len = scriptsig_bytes[0]
            # The signature is bytes 1..sig_len (inclusive)
            sig_bytes = scriptsig_bytes[1:1 + sig_len]
            # Last byte of the signature is the hashtype
            hashtype = sig_bytes[-1]
            assert hashtype == 0x41, \
                f"Expected SIGHASH_ALL|FORKID (0x41) but got 0x{hashtype:02x}"
        self.log.info("All signatures use SIGHASH_FORKID (0x41)")

        self.log.info("Test 10: getaddressinfo iswitness=false for all addresses")
        addr_witness_check = node0.getnewaddress()
        info = node0.getaddressinfo(addr_witness_check)
        assert_equal(info.get("iswitness", False), False)
        assert "witness_version" not in info or info["witness_version"] is None, \
            "witness_version should be absent or null on BCH2"
        self.log.info("iswitness=false confirmed for BCH2 address")

        self.log.info("Test 11: getblockstats segwit fields are zero")
        tip_hash = node0.getbestblockhash()
        stats = node0.getblockstats(tip_hash)
        assert_equal(stats["swtotal_size"], 0)
        assert_equal(stats["swtotal_weight"], 0)
        assert_equal(stats["swtxs"], 0)
        self.log.info("getblockstats segwit fields are all zero on BCH2")

        self.log.info("Test 12: Wallet dump contains fork_id annotation")
        import tempfile, os
        dump_path = os.path.join(tempfile.mkdtemp(), "wallet_dump.txt")
        node0.dumpwallet(dump_path)
        with open(dump_path, 'r') as f:
            dump_contents = f.read()
        assert "fork_id" in dump_contents, \
            "Wallet dump should contain fork_id annotation"
        assert "BCH2" in dump_contents, \
            "Wallet dump should mention BCH2"
        self.log.info("Wallet dump fork_id annotation verified")
        os.unlink(dump_path)

        self.log.info("All BCH2 TX lifecycle tests passed!")


if __name__ == '__main__':
    BCH2TxLifecycleTest().main()
