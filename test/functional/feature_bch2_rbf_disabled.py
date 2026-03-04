#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Cash II developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Tests that RBF (Replace-By-Fee) is disabled in BCH2.

BCH2 uses first-seen-safe policy: once a transaction is accepted into
the mempool, it cannot be replaced by a conflicting transaction paying
a higher fee. Double-spend attempts are detected and reported via DSProof.

Verifies:
1. Spending the same UTXO twice is rejected with "txn-mempool-conflict"
2. bip125-replaceable is always "no" for BCH2 transactions
3. bumpfee RPC is rejected (no RBF means no fee bumping via replacement)
4. Explicit opt-in RBF signaling (nSequence) does not enable replacement
"""
from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class BCH2RBFDisabledTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-mempoolfullrbf=1"]]  # Even with full RBF enabled, BCH2 disables it

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Mining past fork height + maturity...")
        self.generate(node, 201 + COINBASE_MATURITY)

        self.log.info("Test 1: Double-spend rejected with txn-mempool-conflict")
        # Fund a specific UTXO we can double-spend
        addr = node.getnewaddress()
        txid_fund = node.sendtoaddress(addr, Decimal("10.0"))
        self.generate(node, 1)

        # Find the funded UTXO
        utxos = node.listunspent(1, 9999, [addr])
        assert len(utxos) > 0, "Should have at least one UTXO for the funded address"
        utxo = utxos[0]

        # Create tx1 spending the UTXO
        addr1 = node.getnewaddress()
        raw_tx1 = node.createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            {addr1: Decimal("9.999")}
        )
        signed_tx1 = node.signrawtransactionwithwallet(raw_tx1)
        assert signed_tx1["complete"]

        # Create tx2 spending the SAME UTXO to a different address with higher fee
        addr2 = node.getnewaddress()
        raw_tx2 = node.createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            {addr2: Decimal("9.99")}  # Lower output = higher fee
        )
        signed_tx2 = node.signrawtransactionwithwallet(raw_tx2)
        assert signed_tx2["complete"]

        # Send tx1 — should succeed
        txid1 = node.sendrawtransaction(signed_tx1["hex"])
        self.log.info(f"tx1 accepted: {txid1}")
        assert txid1 in node.getrawmempool()

        # Send tx2 — should be rejected with txn-mempool-conflict
        assert_raises_rpc_error(
            -26,
            "txn-mempool-conflict",
            node.sendrawtransaction,
            signed_tx2["hex"]
        )
        self.log.info("Double-spend correctly rejected with txn-mempool-conflict")

        # tx1 should still be in the mempool
        assert txid1 in node.getrawmempool()

        self.log.info("Test 2: bip125-replaceable is always 'no'")
        tx_info = node.gettransaction(txid1)
        assert_equal(tx_info["bip125-replaceable"], "no")

        # Also check a normal wallet transaction
        addr3 = node.getnewaddress()
        txid_normal = node.sendtoaddress(addr3, Decimal("1.0"))
        tx_info_normal = node.gettransaction(txid_normal)
        assert_equal(tx_info_normal["bip125-replaceable"], "no")
        self.log.info("bip125-replaceable is 'no' for all transactions")

        self.log.info("Test 3: bumpfee is rejected")
        # bumpfee is explicitly disabled on BCH2 — RBF is not supported
        assert_raises_rpc_error(
            -8,
            "not supported on BCH2",
            node.bumpfee,
            txid_normal
        )
        self.log.info("bumpfee correctly rejected")

        self.log.info("Test 4: Opt-in RBF signaling does not enable replacement")
        # Mine current mempool to clear it
        self.generate(node, 1)

        # Fund another UTXO
        addr_rbf = node.getnewaddress()
        node.sendtoaddress(addr_rbf, Decimal("5.0"))
        self.generate(node, 1)

        utxos_rbf = node.listunspent(1, 9999, [addr_rbf])
        assert len(utxos_rbf) > 0
        utxo_rbf = utxos_rbf[0]

        # Create tx with explicit RBF signaling (nSequence = 0xfffffffd)
        addr_out1 = node.getnewaddress()
        raw_rbf_tx1 = node.createrawtransaction(
            [{"txid": utxo_rbf["txid"], "vout": utxo_rbf["vout"], "sequence": 0xfffffffd}],
            {addr_out1: Decimal("4.999")}
        )
        signed_rbf_tx1 = node.signrawtransactionwithwallet(raw_rbf_tx1)
        txid_rbf1 = node.sendrawtransaction(signed_rbf_tx1["hex"])
        self.log.info(f"RBF-signaled tx accepted: {txid_rbf1}")

        # Even with RBF signaling, replacement should be rejected in BCH2
        addr_out2 = node.getnewaddress()
        raw_rbf_tx2 = node.createrawtransaction(
            [{"txid": utxo_rbf["txid"], "vout": utxo_rbf["vout"], "sequence": 0xfffffffd}],
            {addr_out2: Decimal("4.99")}
        )
        signed_rbf_tx2 = node.signrawtransactionwithwallet(raw_rbf_tx2)

        assert_raises_rpc_error(
            -26,
            "txn-mempool-conflict",
            node.sendrawtransaction,
            signed_rbf_tx2["hex"]
        )
        self.log.info("RBF-signaled replacement correctly rejected in BCH2")

        # Verify the bip125-replaceable is still "no" even with RBF signaling
        tx_rbf_info = node.gettransaction(txid_rbf1)
        assert_equal(tx_rbf_info["bip125-replaceable"], "no")
        self.log.info("bip125-replaceable remains 'no' even with RBF sequence number")

        self.log.info("All BCH2 RBF disabled tests passed!")


if __name__ == '__main__':
    BCH2RBFDisabledTest().main()
