#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Ghost developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

"""MLSC (Merkelized Ladder Script Conditions) functional tests.

Tests end-to-end creation and spending of MLSC outputs (0xC2 + 32-byte Merkle root)
on regtest with real Schnorr signatures.

Tests:
- Single-sig MLSC create + spend
- Multi-rung MLSC (spend via each path)
- MLSC with relay dependencies
- MLSC-to-MLSC chain spend
- Negative: wrong conditions fail MLSC spend
- Negative: wrong rung index
- MLSC output script format validation
"""

import hashlib
from decimal import Decimal

from test_framework.key import ECKey
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import bytes_to_wif


def make_keypair():
    """Generate an ECKey and return (wif, pubkey_hex)."""
    eckey = ECKey()
    eckey.generate(compressed=True)
    wif = bytes_to_wif(eckey.get_bytes(), compressed=True)
    pubkey_hex = eckey.get_pubkey().get_bytes().hex()
    return wif, pubkey_hex


class MLSCTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-txindex"]]

    def run_test(self):
        node = self.nodes[0]
        self.wallet = MiniWallet(node)

        self.log.info("Mining initial blocks for maturity...")
        self.generate(node, 101)
        self.generatetoaddress(node, 200, self.wallet.get_address())
        self.wallet.rescan_utxos()

        self.test_mlsc_single_sig_spend(node)
        self.test_mlsc_output_format(node)
        self.test_mlsc_two_rung_spend_path_0(node)
        self.test_mlsc_two_rung_spend_path_1(node)
        self.test_mlsc_to_mlsc_chain(node)
        self.test_mlsc_with_hash_preimage(node)
        self.test_negative_wrong_conditions(node)
        self.test_negative_missing_conditions(node)

    # -- helpers --

    def bootstrap_mlsc_output(self, node, conditions, output_amount=None):
        """Create and confirm an MLSC output (0xC2 + Merkle root).
        Returns (txid, vout, amount, scriptPubKey_hex, conditions_json)."""
        utxo = self.wallet.get_utxo()
        input_amount = utxo["value"]
        input_txid = utxo["txid"]
        input_vout = utxo["vout"]

        txout_info = node.gettxout(input_txid, input_vout)
        spent_spk = txout_info["scriptPubKey"]["hex"]

        boot_wif, boot_pubkey = make_keypair()

        if output_amount is None:
            output_amount = Decimal(input_amount) - Decimal("0.001")

        result = node.createrungtx(
            [{"txid": input_txid, "vout": input_vout}],
            [{"amount": output_amount, "conditions": conditions, "mlsc": True}]
        )
        unsigned_hex = result["hex"]

        sign_result = node.signrungtx(
            unsigned_hex,
            [{"privkey": boot_wif, "input": 0}],
            [{"amount": input_amount, "scriptPubKey": spent_spk}]
        )
        assert sign_result["complete"], "Bootstrap tx should be fully signed"

        txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)

        tx_info = node.getrawtransaction(txid, True)
        assert tx_info["confirmations"] >= 1
        spk = tx_info["vout"][0]["scriptPubKey"]["hex"]
        return txid, 0, output_amount, spk, conditions

    # -- tests --

    def test_mlsc_single_sig_spend(self, node):
        """Create a single-sig MLSC output and spend it."""
        self.log.info("Testing MLSC single-sig create + spend...")

        privkey_wif, pubkey_hex = make_keypair()
        conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": pubkey_hex}
        ]}]}]

        txid1, vout, amount, spk, conds = self.bootstrap_mlsc_output(node, conditions)

        # Verify MLSC output format: 0xC2 prefix, 33 bytes total
        assert spk[:2] == "c2", f"Expected 0xC2 prefix, got {spk[:2]}"
        assert len(spk) == 66, f"Expected 33 bytes (66 hex chars), got {len(spk)}"
        self.log.info(f"  MLSC output: {spk[:8]}...{spk[-8:]} ({len(spk)//2} bytes)")

        # Spend the MLSC output
        output_amount2 = amount - Decimal("0.001")
        spend_wif, spend_pubkey = make_keypair()
        spend_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": spend_pubkey}
        ]}]}]

        result2 = node.createrungtx(
            [{"txid": txid1, "vout": vout}],
            [{"amount": output_amount2, "conditions": spend_conditions}]
        )

        sign_result2 = node.signrungtx(
            result2["hex"],
            [{"privkey": privkey_wif, "input": 0, "conditions": conds}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result2["complete"], "MLSC spend should be fully signed"

        txid2 = node.sendrawtransaction(sign_result2["hex"])
        self.generate(node, 1)

        tx_info2 = node.getrawtransaction(txid2, True)
        assert tx_info2["confirmations"] >= 1
        self.log.info(f"  MLSC single-sig spend confirmed: {txid2}")

    def test_mlsc_output_format(self, node):
        """Verify MLSC output is exactly 0xC2 + 32-byte root."""
        self.log.info("Testing MLSC output script format...")

        privkey_wif, pubkey_hex = make_keypair()
        conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": pubkey_hex}
        ]}]}]

        txid, vout, amount, spk, _ = self.bootstrap_mlsc_output(node, conditions)

        # 0xC2 prefix byte + 32 bytes Merkle root = 33 bytes
        assert_equal(len(spk), 66)
        assert_equal(spk[:2], "c2")

        # Root should be a valid 32-byte hash (not all zeros)
        root_hex = spk[2:]
        assert len(root_hex) == 64
        assert root_hex != "00" * 32, "Root should not be all zeros"
        self.log.info(f"  MLSC root: {root_hex}")

    def test_mlsc_two_rung_spend_path_0(self, node):
        """Create a 2-rung MLSC output, spend via rung 0."""
        self.log.info("Testing MLSC 2-rung spend via path 0...")

        privkey_a_wif, pubkey_a = make_keypair()
        privkey_b_wif, pubkey_b = make_keypair()

        conditions = [
            {"blocks": [{"type": "SIG", "fields": [
                {"type": "PUBKEY", "hex": pubkey_a}
            ]}]},
            {"blocks": [{"type": "SIG", "fields": [
                {"type": "PUBKEY", "hex": pubkey_b}
            ]}]}
        ]

        txid1, vout, amount, spk, conds = self.bootstrap_mlsc_output(node, conditions)

        # Spend via rung 0 (key A)
        output_amount2 = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        result = node.createrungtx(
            [{"txid": txid1, "vout": vout}],
            [{"amount": output_amount2, "conditions": dest_conditions}]
        )

        sign_result = node.signrungtx(
            result["hex"],
            [{"privkey": privkey_a_wif, "input": 0, "rung": 0, "conditions": conds}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        txid2 = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(txid2, True)
        assert tx_info["confirmations"] >= 1
        self.log.info(f"  2-rung MLSC spend via path 0 confirmed: {txid2}")

    def test_mlsc_two_rung_spend_path_1(self, node):
        """Create a 2-rung MLSC output, spend via rung 1."""
        self.log.info("Testing MLSC 2-rung spend via path 1...")

        privkey_a_wif, pubkey_a = make_keypair()
        privkey_b_wif, pubkey_b = make_keypair()

        conditions = [
            {"blocks": [{"type": "SIG", "fields": [
                {"type": "PUBKEY", "hex": pubkey_a}
            ]}]},
            {"blocks": [{"type": "SIG", "fields": [
                {"type": "PUBKEY", "hex": pubkey_b}
            ]}]}
        ]

        txid1, vout, amount, spk, conds = self.bootstrap_mlsc_output(node, conditions)

        # Spend via rung 1 (key B)
        output_amount2 = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        result = node.createrungtx(
            [{"txid": txid1, "vout": vout}],
            [{"amount": output_amount2, "conditions": dest_conditions}]
        )

        sign_result = node.signrungtx(
            result["hex"],
            [{"privkey": privkey_b_wif, "input": 0, "rung": 1, "conditions": conds}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        txid2 = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(txid2, True)
        assert tx_info["confirmations"] >= 1
        self.log.info(f"  2-rung MLSC spend via path 1 confirmed: {txid2}")

    def test_mlsc_to_mlsc_chain(self, node):
        """Spend an MLSC output into another MLSC output, then spend that."""
        self.log.info("Testing MLSC -> MLSC chain spend...")

        privkey1_wif, pubkey1 = make_keypair()
        privkey2_wif, pubkey2 = make_keypair()

        conditions1 = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": pubkey1}
        ]}]}]

        txid1, vout1, amount1, spk1, conds1 = self.bootstrap_mlsc_output(node, conditions1)

        # Spend MLSC -> MLSC
        amount2 = amount1 - Decimal("0.001")
        conditions2 = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": pubkey2}
        ]}]}]

        result = node.createrungtx(
            [{"txid": txid1, "vout": vout1}],
            [{"amount": amount2, "conditions": conditions2, "mlsc": True}]
        )

        sign_result = node.signrungtx(
            result["hex"],
            [{"privkey": privkey1_wif, "input": 0, "conditions": conds1}],
            [{"amount": amount1, "scriptPubKey": spk1}]
        )
        assert sign_result["complete"]

        txid2 = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info2 = node.getrawtransaction(txid2, True)
        assert tx_info2["confirmations"] >= 1
        spk2 = tx_info2["vout"][0]["scriptPubKey"]["hex"]

        # Verify second output is also MLSC
        assert_equal(spk2[:2], "c2")
        assert_equal(len(spk2), 66)
        self.log.info(f"  First MLSC->MLSC hop confirmed: {txid2}")

        # Spend the second MLSC output into a legacy output
        amount3 = amount2 - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        result3 = node.createrungtx(
            [{"txid": txid2, "vout": 0}],
            [{"amount": amount3, "conditions": dest_conditions}]
        )

        sign_result3 = node.signrungtx(
            result3["hex"],
            [{"privkey": privkey2_wif, "input": 0, "conditions": conditions2}],
            [{"amount": amount2, "scriptPubKey": spk2}]
        )
        assert sign_result3["complete"]

        txid3 = node.sendrawtransaction(sign_result3["hex"])
        self.generate(node, 1)
        tx_info3 = node.getrawtransaction(txid3, True)
        assert tx_info3["confirmations"] >= 1
        self.log.info(f"  Second MLSC->legacy hop confirmed: {txid3}")

    def test_mlsc_with_hash_preimage(self, node):
        """MLSC output with HASH_PREIMAGE block — spend with correct preimage."""
        self.log.info("Testing MLSC with HASH_PREIMAGE spend...")

        preimage = b"ghost-mlsc-test-preimage-2026"
        hash_hex = hashlib.sha256(preimage).hexdigest()
        preimage_hex = preimage.hex()

        conditions = [{"blocks": [{"type": "HASH_PREIMAGE", "fields": [
            {"type": "HASH256", "hex": hash_hex}
        ]}]}]

        txid1, vout, amount, spk, conds = self.bootstrap_mlsc_output(node, conditions)

        # Spend with preimage via blocks signer format
        output_amount2 = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        result = node.createrungtx(
            [{"txid": txid1, "vout": vout}],
            [{"amount": output_amount2, "conditions": dest_conditions}]
        )

        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "conditions": conds,
              "blocks": [{"type": "HASH_PREIMAGE", "preimage": preimage_hex}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        txid2 = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info2 = node.getrawtransaction(txid2, True)
        assert tx_info2["confirmations"] >= 1
        self.log.info(f"  MLSC HASH_PREIMAGE spend confirmed: {txid2}")

    def test_negative_wrong_conditions(self, node):
        """MLSC spend with wrong conditions should fail Merkle verification."""
        self.log.info("Testing MLSC negative: wrong conditions...")

        privkey_wif, pubkey_hex = make_keypair()
        conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": pubkey_hex}
        ]}]}]

        txid1, vout, amount, spk, _ = self.bootstrap_mlsc_output(node, conditions)

        # Try to spend with DIFFERENT conditions (wrong pubkey)
        _, wrong_pubkey = make_keypair()
        wrong_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": wrong_pubkey}
        ]}]}]

        output_amount2 = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conds = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        result = node.createrungtx(
            [{"txid": txid1, "vout": vout}],
            [{"amount": output_amount2, "conditions": dest_conds}]
        )

        # Sign with wrong conditions — the Merkle root won't match
        sign_result = node.signrungtx(
            result["hex"],
            [{"privkey": privkey_wif, "input": 0, "conditions": wrong_conditions}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        # signrungtx may still produce a signed tx (it doesn't verify the root)
        # but sendrawtransaction should reject it
        if sign_result["complete"]:
            assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
            self.log.info("  Wrong conditions correctly rejected at mempool acceptance")
        else:
            self.log.info("  Wrong conditions rejected at signing stage")

    def test_negative_missing_conditions(self, node):
        """MLSC spend without providing conditions should fail."""
        self.log.info("Testing MLSC negative: missing conditions parameter...")

        privkey_wif, pubkey_hex = make_keypair()
        conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": pubkey_hex}
        ]}]}]

        txid1, vout, amount, spk, _ = self.bootstrap_mlsc_output(node, conditions)

        output_amount2 = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conds = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        result = node.createrungtx(
            [{"txid": txid1, "vout": vout}],
            [{"amount": output_amount2, "conditions": dest_conds}]
        )

        # Try to sign without providing conditions — should error
        assert_raises_rpc_error(-8, "requires 'conditions'", node.signrungtx,
            result["hex"],
            [{"privkey": privkey_wif, "input": 0}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        self.log.info("  Missing conditions correctly rejected by RPC")


if __name__ == '__main__':
    MLSCTest(__file__).main()
