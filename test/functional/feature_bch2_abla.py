#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Cash II developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test BCH2 ABLA (Adaptive Block Limit Algorithm) enforcement.

Verifies:
1. getblocktemplate returns correct sizelimit for post-fork blocks
2. Post-fork blocks within ABLA limit are accepted
3. Block size limit is 32MB at fork activation (initial ABLA limit)
4. ABLA state is tracked through block processing
"""
from test_framework.blocktools import (
    create_block,
    create_coinbase,
)
from test_framework.p2p import P2PDataStore
from test_framework.script import CScript, OP_TRUE, OP_RETURN
from test_framework.messages import CTransaction, CTxIn, CTxOut, COutPoint, COIN
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_greater_than_or_equal


class BCH2ABLATest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-whitelist=noban@127.0.0.1"]]

    def run_test(self):
        node = self.nodes[0]
        peer = node.add_p2p_connection(P2PDataStore())

        self.log.info("Test 1: Pre-fork sizelimit in getblocktemplate")
        # Before fork, the node still has segwit active, so GBT requires segwit rule
        gbt_pre = node.getblocktemplate({"rules": ["segwit"]})
        self.log.info(f"Pre-fork sizelimit: {gbt_pre['sizelimit']}")
        # Pre-fork, block size is the legacy limit (4MB for weight-based with WITNESS_SCALE_FACTOR=1)
        assert gbt_pre['sizelimit'] > 0, "Pre-fork sizelimit should be positive"

        self.log.info("Mining to fork height (200)...")
        self.generatetoaddress(node, 200, node.get_deterministic_priv_key().address)

        self.log.info("Test 2: Post-fork sizelimit in getblocktemplate")
        gbt_post = node.getblocktemplate({"rules": []})
        self.log.info(f"Post-fork sizelimit: {gbt_post['sizelimit']}")
        # Post-fork, block size is 32MB (BCH2_MAX_BLOCK_SIZE)
        assert_equal(gbt_post['sizelimit'], 32000000)

        self.log.info("Test 3: Post-fork block within ABLA limit accepted")
        # Mine a normal block via P2P - should be well within ABLA limit
        best_block = node.getblock(node.getbestblockhash())
        tip = int(node.getbestblockhash(), 16)
        height = best_block["height"] + 1
        block_time = best_block["time"] + 1

        block = create_block(tip, create_coinbase(height), block_time)
        block.solve()
        peer.send_blocks_and_test([block], node, success=True)
        self.log.info("Normal post-fork block accepted")

        self.log.info("Test 4: Verify block height advances correctly")
        assert_equal(node.getblockcount(), 201)

        self.log.info("Test 5: Continued mining maintains ABLA state")
        # Mine several more blocks and verify GBT keeps returning correct limits
        self.generatetoaddress(node, 10, node.get_deterministic_priv_key().address)

        gbt_later = node.getblocktemplate({"rules": []})
        self.log.info(f"Later sizelimit: {gbt_later['sizelimit']}")
        # With empty/small blocks, the ABLA limit should remain at 32MB
        assert_equal(gbt_later['sizelimit'], 32000000)

        self.log.info("Test 6: Block with OP_RETURN data within limits accepted")
        best_block = node.getblock(node.getbestblockhash())
        tip = int(node.getbestblockhash(), 16)
        height = best_block["height"] + 1
        block_time = best_block["time"] + 1

        # Create a block with a coinbase that has OP_RETURN data
        coinbase = create_coinbase(height)
        # Add a small OP_RETURN output
        op_return_script = CScript([OP_RETURN, b"BCH2 ABLA test data"])
        coinbase.vout.append(CTxOut(0, op_return_script))
        coinbase.rehash()

        block_with_data = create_block(tip, coinbase, block_time)
        block_with_data.solve()
        peer.send_blocks_and_test([block_with_data], node, success=True)
        self.log.info("Block with OP_RETURN data accepted")

        self.log.info("Test 7: Verify weightlimit matches sizelimit for BCH2")
        gbt_final = node.getblocktemplate({"rules": []})
        # In BCH2, weightlimit == sizelimit (WITNESS_SCALE_FACTOR = 1)
        assert_equal(gbt_final['weightlimit'], 32000000)
        assert_equal(gbt_final['sizelimit'], gbt_final['weightlimit'])

        self.log.info("Test 8: sigoplimit is correct post-fork")
        # BCH2 sigop limit = 640000
        assert_equal(gbt_final['sigoplimit'], 640000)

        self.log.info("Test 9: default_witness_commitment absent post-fork")
        # BCH2 has no witness commitment in GBT responses after the fork
        assert "default_witness_commitment" not in gbt_final, \
            "default_witness_commitment should NOT be present in post-fork GBT response"
        self.log.info("default_witness_commitment correctly absent from GBT")

        self.log.info("Test 10: GBT with empty rules works post-fork")
        # Post-fork, segwit is not required in rules
        gbt_no_rules = node.getblocktemplate({"rules": []})
        assert gbt_no_rules['sizelimit'] > 0
        self.log.info("GBT with empty rules works post-fork")

        self.log.info("All ABLA enforcement tests passed!")


if __name__ == '__main__':
    BCH2ABLATest().main()
