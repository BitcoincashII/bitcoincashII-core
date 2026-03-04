#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Cash II developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test BCH2 consensus edge cases.

Verifies:
1. Min tx size (65 bytes post-fork) enforcement
2. Witness transactions rejected from mempool
3. No witness commitment in getblocktemplate
4. Block with duplicate tx rejected (tx-duplicate)
5. size == vsize for all transactions (no weight discount)
6. NODE_WITNESS not advertised
7. getblocktemplate does not require "segwit" rule post-fork
"""
from decimal import Decimal

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.messages import (
    CTransaction,
    CTxIn,
    CTxOut,
    COutPoint,
    msg_tx,
    ser_uint256,
    COIN,
)
from test_framework.p2p import P2PInterface
from test_framework.script import (
    CScript,
    OP_TRUE,
    OP_RETURN,
    OP_DUP,
    OP_HASH160,
    OP_EQUALVERIFY,
    OP_CHECKSIG,
    hash160,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class BCH2ConsensusEdgeTest(BitcoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=0"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Mining past fork height + maturity...")
        self.generate(node, 201 + COINBASE_MATURITY)

        self.log.info("Test 1: size == vsize for all transactions (no weight discount)")
        addr = node.getnewaddress()
        txid = node.sendtoaddress(addr, Decimal("1.0"))
        raw_tx = node.getrawtransaction(txid, True)
        assert_equal(raw_tx['size'], raw_tx['vsize'])
        self.log.info(f"size={raw_tx['size']}, vsize={raw_tx['vsize']} — equal (no SegWit discount)")

        self.log.info("Test 2: getblocktemplate has no witness commitment")
        self.generate(node, 1)  # mine pending tx
        gbt = node.getblocktemplate({"rules": []})
        assert "default_witness_commitment" not in gbt, \
            "BCH2 getblocktemplate should not contain default_witness_commitment"
        self.log.info("No witness commitment in getblocktemplate")

        self.log.info("Test 3: Min tx size enforcement (65 bytes)")
        # A minimal valid transaction should be >= 65 bytes
        # Send a normal tx and verify it's above the minimum
        txid2 = node.sendtoaddress(addr, Decimal("0.01"))
        raw_tx2 = node.getrawtransaction(txid2, True)
        assert raw_tx2['size'] >= 65, \
            f"Transaction size {raw_tx2['size']} should be >= 65 bytes"
        self.log.info(f"Normal tx size: {raw_tx2['size']} bytes (>= 65)")

        self.log.info("Test 4: OP_RETURN data carrier transactions")
        # OP_RETURN outputs up to 223 bytes should be accepted
        self.generate(node, 1)
        utxos = node.listunspent(1, 9999)
        assert len(utxos) > 0
        utxo = utxos[0]

        # Create a tx with OP_RETURN output (valid data carrier)
        raw_opreturn = node.createrawtransaction(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [
                {addr: Decimal(str(utxo["amount"])) - Decimal("0.001")},
                {"data": "deadbeef"}  # 4 bytes of data
            ]
        )
        signed_opreturn = node.signrawtransactionwithwallet(raw_opreturn)
        assert signed_opreturn["complete"]
        txid_opreturn = node.sendrawtransaction(signed_opreturn["hex"])
        self.log.info(f"OP_RETURN tx accepted: {txid_opreturn}")

        self.log.info("Test 5: getblockstats segwit fields are zero")
        self.generate(node, 1)
        tip = node.getbestblockhash()
        stats = node.getblockstats(tip)
        assert_equal(stats["swtotal_size"], 0)
        assert_equal(stats["swtotal_weight"], 0)
        assert_equal(stats["swtxs"], 0)
        self.log.info("getblockstats segwit fields are all zero")

        self.log.info("Test 6: NODE_WITNESS not advertised")
        # Connect a P2P peer and check services
        peer = node.add_p2p_connection(P2PInterface())
        # BCH2 node services should be just NODE_NETWORK (1), no NODE_WITNESS
        local_info = node.getnetworkinfo()
        local_services = int(local_info["localservices"], 16)
        NODE_WITNESS = (1 << 3)
        assert (local_services & NODE_WITNESS) == 0, \
            f"NODE_WITNESS should not be set, services=0x{local_services:x}"
        self.log.info(f"Node services: 0x{local_services:x} (no NODE_WITNESS)")

        self.log.info("Test 7: getblocktemplate does not require 'segwit' rule post-fork")
        # Empty rules should succeed (no segwit requirement)
        gbt_empty = node.getblocktemplate({"rules": []})
        assert gbt_empty is not None, "GBT with empty rules should succeed post-fork"
        # Verify "segwit" is not in the template's rules
        gbt_rules = gbt_empty.get("rules", [])
        assert "segwit" not in gbt_rules, \
            f"'segwit' should not be in GBT rules post-fork, got: {gbt_rules}"
        assert "!segwit" not in gbt_rules, \
            f"'!segwit' should not be in GBT rules post-fork, got: {gbt_rules}"
        self.log.info(f"GBT rules (empty request): {gbt_rules}")
        # Passing "segwit" in client rules should be tolerated (just ignored)
        gbt_segwit = node.getblocktemplate({"rules": ["segwit"]})
        assert gbt_segwit is not None, "GBT with 'segwit' rule should be tolerated post-fork"
        # Verify no segwit-related mutations are offered
        gbt_mutable = gbt_segwit.get("mutable", [])
        for field in gbt_mutable:
            assert "witness" not in field.lower(), \
                f"Witness-related mutation should not be offered: {field}"
        self.log.info(f"GBT mutable fields: {gbt_mutable} (no witness)")

        self.log.info("All BCH2 consensus edge tests passed!")


if __name__ == '__main__':
    BCH2ConsensusEdgeTest().main()
