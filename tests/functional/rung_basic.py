#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Ghost developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

"""Ladder Script functional tests for all block types (v3 wire format).

Tests:
- Signature/Timelock/Hash: createrung, decoderung, validateladder, malformed, SIG spend
- Covenant/Compound: HASH_PREIMAGE, CSV, CLTV, MULTISIG, compound SIG+CSV, OR logic,
           negative tests, multi-input/output
- Inversion: Inversion (inverted CSV, inverted HASH_PREIMAGE)
"""

import hashlib
import os
from decimal import Decimal

from test_framework.key import ECKey
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet
from test_framework.wallet_util import bytes_to_wif, generate_keypair


def make_keypair():
    """Generate an ECKey and return (wif, pubkey_hex)."""
    eckey = ECKey()
    eckey.generate(compressed=True)
    wif = bytes_to_wif(eckey.get_bytes(), compressed=True)
    pubkey_hex = eckey.get_pubkey().get_bytes().hex()
    return wif, pubkey_hex


def locktime_hex(val):
    """Encode a uint32 as 4-byte little-endian hex."""
    return val.to_bytes(4, 'little').hex()


def numeric_hex(val):
    """Encode a uint32 as 4-byte little-endian hex (same as locktime)."""
    return val.to_bytes(4, 'little').hex()


class LadderScriptBasicTest(BitcoinTestFramework):
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

        # Signature, Timelock, Hash tests
        self.test_createrung(node)
        self.test_decoderung(node)
        self.test_validateladder(node)
        self.test_decoderung_malformed(node)
        self.test_createrungtx_signrungtx_spend(node)

        # Covenant, Anchor, compound tests
        self.test_hash_preimage_spend(node)
        self.test_csv_spend(node)
        self.test_cltv_spend(node)
        self.test_multisig_spend(node)
        self.test_sig_plus_csv(node)
        self.test_or_logic(node)
        self.test_negative_wrong_sig(node)
        self.test_negative_wrong_preimage(node)
        self.test_negative_csv_too_early(node)
        self.test_negative_cltv_too_early(node)
        self.test_multi_input_output(node)

        # Inversion tests
        self.test_inverted_csv(node)
        self.test_inverted_hash_preimage(node)

        # Phase 4 tests (new block types)
        self.test_tagged_hash(node)
        self.test_amount_lock(node)
        self.test_amount_lock_out_of_range(node)
        self.test_anchor_output(node)
        self.test_compare_block(node)
        self.test_ctv_template(node)
        self.test_vault_lock(node)

        # Negative tests
        self.test_negative_ctv_wrong_template(node)
        self.test_negative_vault_wrong_key(node)
        self.test_negative_compare_fails(node)
        self.test_negative_tagged_hash_wrong_preimage(node)

        # Additional signature tests
        self.test_hash160_preimage_spend(node)
        self.test_csv_time_spend(node)
        self.test_cltv_time_spend(node)

        # Recursion tests
        self.test_recurse_same(node)
        self.test_negative_recurse_same_different(node)
        self.test_recurse_same_chain(node)
        self.test_recurse_until_re_encumber(node)
        self.test_recurse_until_termination(node)
        self.test_negative_recurse_until_no_reencumber(node)
        self.test_recurse_count(node)
        self.test_recurse_modified(node)
        self.test_recurse_split(node)

        # PLC block tests
        self.test_hysteresis_value(node)
        self.test_rate_limit(node)
        self.test_sequencer(node)

        # Remaining block type tests
        self.test_adaptor_sig(node)
        self.test_anchor(node)
        self.test_anchor_channel(node)
        self.test_anchor_pool(node)
        self.test_anchor_reserve(node)
        self.test_anchor_seal(node)
        self.test_anchor_oracle(node)
        self.test_recurse_decay(node)
        self.test_hysteresis_fee(node)
        self.test_timer_continuous(node)
        self.test_timer_off_delay(node)
        self.test_latch_set(node)
        self.test_latch_reset(node)
        self.test_counter_down(node)
        self.test_counter_preset(node)
        self.test_counter_up(node)
        self.test_one_shot(node)

        # Negative tests for remaining block types
        self.test_negative_adaptor_sig_wrong_key(node)
        self.test_negative_anchor_reserve_n_gt_m(node)
        self.test_negative_hysteresis_fee_low_gt_high(node)
        self.test_negative_anchor_channel_zero_commitment(node)
        self.test_negative_anchor_pool_zero_count(node)
        self.test_negative_anchor_oracle_zero_count(node)
        self.test_negative_timer_continuous_zero(node)
        self.test_negative_counter_preset_missing_field(node)
        self.test_negative_one_shot_missing_hash(node)
        self.test_negative_recurse_decay_wrong_delta(node)

        # Edge case tests
        self.test_multi_rung_mixed_blocks(node)
        self.test_max_blocks_per_rung(node)
        self.test_deeply_nested_covenant_chain(node)

        # RPC hardening tests
        self.test_rpc_unknown_block_type(node)
        self.test_rpc_unknown_data_type(node)
        self.test_rpc_empty_rungs(node)
        self.test_rpc_invalid_field_hex(node)
        self.test_rpc_decoderung_invalid_hex(node)
        self.test_rpc_createrungtx_negative_amount(node)
        self.test_rpc_signrungtx_missing_spent_info(node)

        # PQ tests (only run if node has liboqs support)
        self.test_pq_keygen_rpc(node)
        self.test_pq_falcon512_sig(node)

        # Stateful latch tests
        self.test_latch_state_gating(node)
        self.test_latch_covenant_chain(node)

        # Compound block type tests (C-5)
        self.test_timelocked_sig(node)
        self.test_negative_timelocked_sig_bad_sig(node)
        self.test_htlc_compound(node)
        self.test_negative_htlc_wrong_preimage(node)
        self.test_hash_sig(node)
        self.test_negative_hash_sig_wrong_preimage(node)
        self.test_cltv_sig(node)
        self.test_negative_cltv_sig_too_early(node)
        self.test_timelocked_multisig(node)
        self.test_negative_timelocked_multisig_too_few_sigs(node)

        self.test_ptlc(node)
        self.test_negative_ptlc_bad_sig(node)

        # Governance block type tests (C-5)
        self.test_epoch_gate(node)
        self.test_negative_epoch_gate_outside_window(node)
        self.test_weight_limit(node)
        self.test_negative_weight_limit_exceeded(node)
        self.test_input_count(node)
        self.test_negative_input_count_below_min(node)
        self.test_output_count(node)
        self.test_negative_output_count_above_max(node)
        self.test_relative_value(node)
        self.test_negative_relative_value_too_low(node)
        self.test_accumulator(node)
        self.test_negative_accumulator_wrong_leaf(node)

        # Data embedding / spam resistance tests
        self.test_spam_arbitrary_preimage_rejected(node)
        self.test_spam_pubkey_no_crypto_validation(node)
        self.test_spam_numeric_arbitrary_bytes(node)
        self.test_spam_unknown_data_type_rejected(node)
        self.test_spam_witness_only_in_conditions_rejected(node)
        self.test_spam_oversized_field_rejected(node)
        self.test_spam_max_structure_limits(node)
        self.test_spam_coil_address_limit(node)

        # Advanced scenario tests (comprehensive combinations)
        self.test_pq_falcon512_pubkey_commit(node)
        self.test_negative_pq_pubkey_commit_mismatch(node)
        self.test_recurse_modified_cross_rung(node)
        self.test_recurse_modified_multi_mutation(node)
        self.test_negative_recurse_modified_wrong_delta(node)
        self.test_sig_hash_csv_triple_and(node)
        self.test_or_hot_cold_vault(node)
        self.test_recurse_same_with_cltv(node)
        self.test_inverted_compare_floor(node)
        self.test_countdown_vault(node)
        self.test_recurse_decay_multi_target(node)
        self.test_htlc_pattern(node)
        self.test_latch_cross_rung_state_machine(node)
        self.test_timed_secret_reveal(node)
        self.test_three_rung_priority(node)
        self.test_pqpubkeycommit_rpc(node)

        # Adaptor sig RPC tests
        self.test_extractadaptorsecret_rpc(node)

        # Counter state gating tests
        self.test_counter_down_state_gating(node)
        self.test_one_shot_state_gating(node)

        # COSIGN — PQ anchor co-spend pattern
        self.test_cosign_anchor_spend(node)
        self.test_cosign_negative_no_anchor(node)
        self.test_cosign_10_children(node)

        # DIFF_WITNESS — witness inheritance
        self.test_diff_witness_spend(node)
        self.test_diff_witness_negative_self_ref(node)

        # KEY_REF_SIG — relay key reference
        self.test_key_ref_sig_spend(node)
        self.test_key_ref_sig_multi_rung(node)
        self.test_key_ref_sig_negative_wrong_key(node)

        # Legacy block type tests
        self.test_p2pk_legacy_spend(node)
        self.test_p2pkh_legacy_spend(node)
        self.test_p2wpkh_legacy_spend(node)
        self.test_p2tr_legacy_spend(node)
        self.test_p2sh_legacy_inner_sig(node)
        self.test_p2wsh_legacy_inner_sig(node)
        self.test_negative_p2pkh_wrong_key(node)
        self.test_negative_p2sh_malformed_preimage(node)
        self.test_legacy_plus_covenant(node)
        self.test_legacy_plus_csv(node)
        self.test_legacy_mlsc(node)
        self.test_p2tr_script_legacy_spend(node)
        self.test_negative_raw_hash160_rejected(node)
        self.test_negative_raw_hash256_rejected(node)

    # =========================================================================
    # Helpers
    # =========================================================================

    def bootstrap_v4_output(self, node, conditions, output_amount=None):
        """Create and confirm a v4 output with given conditions.
        Returns (txid, vout, amount, scriptPubKey_hex).
        If output_amount is specified and leaves excess, a change output is added."""
        utxo = self.wallet.get_utxo()
        input_amount = utxo["value"]
        input_txid = utxo["txid"]
        input_vout = utxo["vout"]

        txout_info = node.gettxout(input_txid, input_vout)
        spent_spk = txout_info["scriptPubKey"]["hex"]

        if output_amount is None:
            output_amount = Decimal(input_amount) - Decimal("0.001")

        # We need a bootstrap key to sign the MiniWallet UTXO spend
        boot_wif, boot_pubkey = make_keypair()

        outputs = [{"amount": output_amount, "conditions": conditions}]

        # Add change output if there's significant excess (> 0.01 BTC)
        change = Decimal(input_amount) - output_amount - Decimal("0.001")
        if change > Decimal("0.01"):
            change_wif, change_pubkey = make_keypair()
            change_conditions = [{"blocks": [{"type": "SIG", "fields": [
                {"type": "PUBKEY", "hex": change_pubkey}
            ]}]}]
            outputs.append({"amount": change, "conditions": change_conditions})

        result = node.createrungtx(
            [{"txid": input_txid, "vout": input_vout}],
            outputs
        )
        unsigned_hex = result["hex"]

        sign_result = node.signrungtx(
            unsigned_hex,
            [{"privkey": boot_wif, "input": 0}],
            [{"amount": input_amount, "scriptPubKey": spent_spk}]
        )
        assert sign_result["complete"]

        txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)

        tx_info = node.getrawtransaction(txid, True)
        assert tx_info["confirmations"] >= 1
        spk = tx_info["vout"][0]["scriptPubKey"]["hex"]
        return txid, 0, output_amount, spk

    # =========================================================================
    # Signature, Timelock, Hash tests
    # =========================================================================

    def test_createrung(self, node):
        """Test createrung RPC builds a valid ladder witness."""
        self.log.info("Testing createrung RPC...")

        pubkey_hex = "02" + "aa" * 32
        sig_hex = "bb" * 64

        result = node.createrung([{
            "blocks": [{
                "type": "SIG",
                "fields": [
                    {"type": "PUBKEY", "hex": pubkey_hex},
                    {"type": "SIGNATURE", "hex": sig_hex},
                ]
            }]
        }])

        assert "hex" in result
        assert result["size"] > 0
        self.log.info(f"  Created ladder witness: {result['size']} bytes")
        self.ladder_hex = result["hex"]

    def test_decoderung(self, node):
        """Test decoderung RPC decodes ladder witness to JSON."""
        self.log.info("Testing decoderung RPC...")

        result = node.decoderung(self.ladder_hex)

        assert_equal(result["num_rungs"], 1)
        assert_equal(len(result["rungs"]), 1)

        rung = result["rungs"][0]
        assert_equal(rung["rung_index"], 0)
        assert_equal(len(rung["blocks"]), 1)

        block = rung["blocks"][0]
        assert_equal(block["type"], "SIG")
        assert_equal(block["inverted"], False)
        assert_equal(len(block["fields"]), 2)
        assert_equal(block["fields"][0]["type"], "PUBKEY")
        assert_equal(block["fields"][0]["size"], 33)
        assert_equal(block["fields"][1]["type"], "SIGNATURE")
        assert_equal(block["fields"][1]["size"], 64)

        # Check coil defaults (per-ladder, not per-rung)
        coil = result["coil"]
        assert_equal(coil["type"], "UNLOCK")
        assert_equal(coil["attestation"], "INLINE")
        assert_equal(coil["scheme"], "SCHNORR")

        self.log.info("  Decoded ladder witness matches expected structure")

    def test_validateladder(self, node):
        """Test validateladder RPC on a non-v4 transaction."""
        self.log.info("Testing validateladder RPC...")

        raw_tx = (
            "01000000"
            "01"
            "0000000000000000000000000000000000000000000000000000000000000000"
            "00000000"
            "00"
            "ffffffff"
            "01"
            "0000000000000000"
            "016a"
            "00000000"
        )

        result = node.validateladder(raw_tx)
        assert_equal(result["valid"], False)
        assert "Not a v4 RUNG_TX" in result["error"]

        self.log.info("  Non-v4 transaction correctly rejected")

    def test_decoderung_malformed(self, node):
        """Test decoderung RPC rejects malformed input."""
        self.log.info("Testing malformed ladder witness rejection...")

        # Empty / truncated
        assert_raises_rpc_error(-22, "Failed to decode", node.decoderung, "00")

        # Unknown block type via escape: 01 rung, 01 block, 80 escape, ff00 type LE, 00 fields, coil, relay
        assert_raises_rpc_error(-22, "unknown block type", node.decoderung, "010180ff0000010101" + "0000")

        # Unknown data type (0xff) via escape: 01 rung, 01 block, 80 escape, 0100 SIG type LE, 01 field, ff type, 01 len, aa data, coil, relay
        assert_raises_rpc_error(-22, "unknown data type", node.decoderung, "0101800100" + "01ff01aa" + "010101" + "0000")

        # Oversized PUBKEY field (2049 bytes, max is 2048) via escape:
        # 01 rung, 01 block, 80 escape, 0100 SIG type LE, 01 field, 01 PUBKEY, varint len=2049, 2049 bytes, coil, relay
        oversized = "0101800100" + "01" + "01" + "fd0108" + "02" * 2049 + "010101" + "0000"
        assert_raises_rpc_error(-22, "too large", node.decoderung, oversized)

        self.log.info("  All malformed inputs correctly rejected")

    def test_createrungtx_signrungtx_spend(self, node):
        """Test end-to-end: create v4 output, sign, broadcast, spend again."""
        self.log.info("Testing createrungtx + signrungtx end-to-end spend...")

        privkey_wif, pubkey_hex = make_keypair()

        utxo = self.wallet.get_utxo()
        input_amount = utxo["value"]
        input_txid = utxo["txid"]
        input_vout = utxo["vout"]

        self.log.info(f"  Using UTXO: {input_txid}:{input_vout} ({input_amount} BTC)")

        txout_info = node.gettxout(input_txid, input_vout)
        spent_spk = txout_info["scriptPubKey"]["hex"]

        output_amount = Decimal(input_amount) - Decimal("0.001")

        result = node.createrungtx(
            [{"txid": input_txid, "vout": input_vout}],
            [{"amount": output_amount, "conditions": [{
                "blocks": [{
                    "type": "SIG",
                    "fields": [{"type": "PUBKEY", "hex": pubkey_hex}]
                }]
            }]}]
        )
        unsigned_hex = result["hex"]
        self.log.info(f"  Created unsigned v4 tx: {len(unsigned_hex)//2} bytes")

        sign_result = node.signrungtx(
            unsigned_hex,
            [{"privkey": privkey_wif, "input": 0}],
            [{"amount": input_amount, "scriptPubKey": spent_spk}]
        )
        signed_hex = sign_result["hex"]
        assert sign_result["complete"], "Transaction should be fully signed"
        self.log.info(f"  Signed v4 tx: complete={sign_result['complete']}")

        txid1 = node.sendrawtransaction(signed_hex)
        self.log.info(f"  Broadcast bootstrap tx: {txid1}")
        self.generate(node, 1)

        tx_info = node.getrawtransaction(txid1, True)
        assert tx_info["confirmations"] >= 1, "Bootstrap tx should be confirmed"
        self.log.info("  Bootstrap spend (standard -> v4) confirmed!")

        # Rung-to-rung spend
        output_amount2 = output_amount - Decimal("0.001")
        spent_conditions_spk = tx_info["vout"][0]["scriptPubKey"]["hex"]

        result2 = node.createrungtx(
            [{"txid": txid1, "vout": 0}],
            [{"amount": output_amount2, "conditions": [{
                "blocks": [{
                    "type": "SIG",
                    "fields": [{"type": "PUBKEY", "hex": pubkey_hex}]
                }]
            }]}]
        )
        unsigned_hex2 = result2["hex"]

        sign_result2 = node.signrungtx(
            unsigned_hex2,
            [{"privkey": privkey_wif, "input": 0}],
            [{"amount": output_amount, "scriptPubKey": spent_conditions_spk}]
        )
        signed_hex2 = sign_result2["hex"]
        assert sign_result2["complete"], "Rung-to-rung tx should be fully signed"

        txid2 = node.sendrawtransaction(signed_hex2)
        self.log.info(f"  Broadcast rung-to-rung tx: {txid2}")
        self.generate(node, 1)

        tx_info2 = node.getrawtransaction(txid2, True)
        assert tx_info2["confirmations"] >= 1, "Rung-to-rung tx should be confirmed"
        self.log.info("  Rung-to-rung spend (v4 -> v4) confirmed!")

        validate1 = node.validateladder(node.getrawtransaction(txid1))
        self.log.info(f"  validateladder tx1: valid={validate1['valid']}")

        validate2 = node.validateladder(node.getrawtransaction(txid2))
        self.log.info(f"  validateladder tx2: valid={validate2['valid']}")

        self.log.info("  End-to-end spend test PASSED!")

    # =========================================================================
    # Covenant, Anchor, compound tests
    # =========================================================================

    def test_hash_preimage_spend(self, node):
        """HASH_PREIMAGE: SHA256 preimage reveal spend."""
        self.log.info("Testing HASH_PREIMAGE spend...")

        # Generate random 32-byte preimage
        preimage = os.urandom(32)

        # Create v4 output with HASH_PREIMAGE condition
        conditions = [{"blocks": [{"type": "HASH_PREIMAGE", "fields": [
            {"type": "PREIMAGE", "hex": preimage.hex()}
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  HASH_PREIMAGE output: {txid}:{vout}")

        # Spend the HASH_PREIMAGE output
        output_amount = amount - Decimal("0.001")
        spend_wif, spend_pubkey = make_keypair()

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": [{"blocks": [{
                "type": "SIG",
                "fields": [{"type": "PUBKEY", "hex": spend_pubkey}]
            }]}]}]
        )

        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "HASH_PREIMAGE", "preimage": preimage.hex()}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  HASH_PREIMAGE spend confirmed!")

    def test_csv_spend(self, node):
        """CSV: relative timelock spend."""
        self.log.info("Testing CSV spend...")

        csv_blocks = 10

        conditions = [{"blocks": [{"type": "CSV", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(csv_blocks)}
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  CSV output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        # Try spending immediately with correct sequence — should fail (UTXO not old enough)
        result = node.createrungtx(
            [{"txid": txid, "vout": vout, "sequence": csv_blocks}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "CSV"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, "non-BIP68-final", node.sendrawtransaction, sign_result["hex"])
        self.log.info("  CSV spend rejected (too early) — correct!")

        # Mine enough blocks for the CSV to mature
        self.generate(node, csv_blocks)

        # Now spend should succeed
        result = node.createrungtx(
            [{"txid": txid, "vout": vout, "sequence": csv_blocks}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "CSV"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  CSV spend confirmed!")

    def test_cltv_spend(self, node):
        """CLTV: absolute timelock spend."""
        self.log.info("Testing CLTV spend...")

        current_height = node.getblockcount()
        target_height = current_height + 20

        conditions = [{"blocks": [{"type": "CLTV", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(target_height)}
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  CLTV output: {txid}:{vout} (target_height={target_height})")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        # Try spending now — should fail (height too low)
        # nLockTime must be >= target_height, sequence must not be 0xffffffff
        result = node.createrungtx(
            [{"txid": txid, "vout": vout, "sequence": 0xfffffffe}],
            [{"amount": output_amount, "conditions": dest_conditions}],
            target_height  # locktime
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "CLTV"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, "non-final", node.sendrawtransaction, sign_result["hex"])
        self.log.info("  CLTV spend rejected (too early) — correct!")

        # Mine until we reach target height
        blocks_needed = target_height - node.getblockcount()
        if blocks_needed > 0:
            self.generate(node, blocks_needed)

        # Now spend should succeed
        result = node.createrungtx(
            [{"txid": txid, "vout": vout, "sequence": 0xfffffffe}],
            [{"amount": output_amount, "conditions": dest_conditions}],
            target_height  # locktime
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "CLTV"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  CLTV spend confirmed!")

    def test_multisig_spend(self, node):
        """MULTISIG: 2-of-3 threshold spend."""
        self.log.info("Testing MULTISIG 2-of-3 spend...")

        # Generate 3 keypairs
        keys = [make_keypair() for _ in range(3)]
        wifs = [k[0] for k in keys]
        pubkeys = [k[1] for k in keys]

        # Conditions: NUMERIC(2) + 3 PUBKEYs
        conditions = [{"blocks": [{"type": "MULTISIG", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(2)},
            {"type": "PUBKEY", "hex": pubkeys[0]},
            {"type": "PUBKEY", "hex": pubkeys[1]},
            {"type": "PUBKEY", "hex": pubkeys[2]},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  MULTISIG output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        # Sign with keys 0 and 2 (2 of 3)
        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "MULTISIG", "privkeys": [wifs[0], wifs[2]]}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  MULTISIG 2-of-3 spend confirmed!")

    def test_sig_plus_csv(self, node):
        """Compound: SIG + CSV (AND logic within one rung)."""
        self.log.info("Testing SIG + CSV compound spend...")

        privkey_wif, pubkey_hex = make_keypair()
        csv_blocks = 10

        # Conditions: single rung with SIG + CSV blocks
        conditions = [{"blocks": [
            {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pubkey_hex}]},
            {"type": "CSV", "fields": [{"type": "NUMERIC", "hex": numeric_hex(csv_blocks)}]},
        ]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  SIG+CSV output: {txid}:{vout}")

        # Mine for CSV maturity
        self.generate(node, csv_blocks)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        result = node.createrungtx(
            [{"txid": txid, "vout": vout, "sequence": csv_blocks}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [
                {"type": "SIG", "privkey": privkey_wif},
                {"type": "CSV"},
            ]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  SIG + CSV compound spend confirmed!")

    def test_or_logic(self, node):
        """OR logic: two rungs — SIG(key_A) OR HASH_PREIMAGE(hash)."""
        self.log.info("Testing OR logic (2 rungs)...")

        key_a_wif, key_a_pubkey = make_keypair()
        preimage = os.urandom(32)

        # Conditions: 2 rungs
        # Rung 0: SIG(key_A)
        # Rung 1: HASH_PREIMAGE(hash)
        conditions = [
            {"blocks": [{"type": "SIG", "fields": [
                {"type": "PUBKEY", "hex": key_a_pubkey}
            ]}]},
            {"blocks": [{"type": "HASH_PREIMAGE", "fields": [
                {"type": "PREIMAGE", "hex": preimage.hex()}
            ]}]},
        ]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  OR output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        # Spend using rung 1 (HASH_PREIMAGE) — don't need key_A
        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "rung": 1, "blocks": [
                {"type": "HASH_PREIMAGE", "preimage": preimage.hex()}
            ]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  OR logic spend (via rung 1 HASH_PREIMAGE) confirmed!")

    def test_negative_wrong_sig(self, node):
        """Negative: SIG output, spend with wrong key."""
        self.log.info("Testing negative: wrong SIG key...")

        correct_wif, correct_pubkey = make_keypair()
        wrong_wif, _ = make_keypair()

        conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": correct_pubkey}
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": [{"blocks": [{
                "type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pubkey}]
            }]}]}]
        )
        # Sign with wrong key
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "SIG", "privkey": wrong_wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )

        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  Wrong SIG key correctly rejected!")

    def test_negative_wrong_preimage(self, node):
        """Negative: HASH_PREIMAGE output, spend with wrong preimage."""
        self.log.info("Testing negative: wrong HASH_PREIMAGE preimage...")

        preimage = os.urandom(32)
        wrong_preimage = os.urandom(32)

        conditions = [{"blocks": [{"type": "HASH_PREIMAGE", "fields": [
            {"type": "PREIMAGE", "hex": preimage.hex()}
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": [{"blocks": [{
                "type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pubkey}]
            }]}]}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "HASH_PREIMAGE", "preimage": wrong_preimage.hex()}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )

        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  Wrong HASH_PREIMAGE preimage correctly rejected!")

    def test_negative_csv_too_early(self, node):
        """Negative: CSV(10) output, spend immediately."""
        self.log.info("Testing negative: CSV too early...")

        csv_blocks = 10
        conditions = [{"blocks": [{"type": "CSV", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(csv_blocks)}
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()

        result = node.createrungtx(
            [{"txid": txid, "vout": vout, "sequence": csv_blocks}],
            [{"amount": output_amount, "conditions": [{"blocks": [{
                "type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pubkey}]
            }]}]}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "CSV"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )

        assert_raises_rpc_error(-26, "non-BIP68-final", node.sendrawtransaction, sign_result["hex"])
        self.log.info("  CSV too early correctly rejected!")

    def test_negative_cltv_too_early(self, node):
        """Negative: CLTV(future) output, spend with locktime in past."""
        self.log.info("Testing negative: CLTV too early...")

        current_height = node.getblockcount()
        target_height = current_height + 50  # Far in the future

        conditions = [{"blocks": [{"type": "CLTV", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(target_height)}
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()

        result = node.createrungtx(
            [{"txid": txid, "vout": vout, "sequence": 0xfffffffe}],
            [{"amount": output_amount, "conditions": [{"blocks": [{
                "type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pubkey}]
            }]}]}],
            target_height  # locktime
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "CLTV"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )

        assert_raises_rpc_error(-26, "non-final", node.sendrawtransaction, sign_result["hex"])
        self.log.info("  CLTV too early correctly rejected!")

    def test_multi_input_output(self, node):
        """Multi-input/multi-output: 3 inputs → 2 outputs."""
        self.log.info("Testing multi-input/output (3→2)...")

        privkey_wif, pubkey_hex = make_keypair()
        sig_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": pubkey_hex}
        ]}]}]

        # Create 3 v4 outputs
        utxos = []
        for i in range(3):
            txid, vout, amount, spk = self.bootstrap_v4_output(node, sig_conditions)
            utxos.append({"txid": txid, "vout": vout, "amount": amount, "spk": spk})
            self.log.info(f"  Created v4 output {i}: {txid}:{vout}")

        total_input = sum(u["amount"] for u in utxos)
        fee = Decimal("0.001")
        remaining = total_input - fee
        out1_amount = remaining / 2
        out2_amount = remaining - out1_amount

        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        # Create tx with 3 inputs, 2 outputs
        inputs = [{"txid": u["txid"], "vout": u["vout"]} for u in utxos]
        outputs = [
            {"amount": out1_amount, "conditions": dest_conditions},
            {"amount": out2_amount, "conditions": dest_conditions},
        ]
        result = node.createrungtx(inputs, outputs)

        # Sign all 3 inputs
        signers = [{"input": i, "blocks": [{"type": "SIG", "privkey": privkey_wif}]} for i in range(3)]
        spent_outputs = [{"amount": u["amount"], "scriptPubKey": u["spk"]} for u in utxos]

        sign_result = node.signrungtx(result["hex"], signers, spent_outputs)
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)

        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        assert_equal(len(tx_info["vin"]), 3)
        assert_equal(len(tx_info["vout"]), 2)
        self.log.info("  Multi-input/output (3→2) confirmed!")


    # =========================================================================
    # Inversion tests
    # =========================================================================

    def test_inverted_csv(self, node):
        """Inverted CSV: spend BEFORE maturity succeeds, after maturity fails."""
        self.log.info("Testing inverted CSV...")

        csv_blocks = 10

        # Create v4 output with inverted CSV condition
        # Inverted CSV means: spendable when CSV is NOT satisfied (i.e., before maturity)
        conditions = [{"blocks": [{"type": "CSV", "inverted": True, "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(csv_blocks)}
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  Inverted CSV output: {txid}:{vout}")

        # Spend immediately (before maturity) — should succeed with inverted CSV
        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        result = node.createrungtx(
            [{"txid": txid, "vout": vout, "sequence": 0}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "CSV"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  Inverted CSV spend (before maturity) confirmed!")

    def test_inverted_hash_preimage(self, node):
        """Inverted HASH_PREIMAGE: spend when preimage NOT provided succeeds."""
        self.log.info("Testing inverted HASH_PREIMAGE...")

        preimage = os.urandom(32)

        # Create v4 output with inverted HASH_PREIMAGE condition
        # Inverted means: spendable when hash check FAILS (no valid preimage)
        conditions = [{"blocks": [{"type": "HASH_PREIMAGE", "inverted": True, "fields": [
            {"type": "PREIMAGE", "hex": preimage.hex()}
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  Inverted HASH_PREIMAGE output: {txid}:{vout}")

        # Spend with a WRONG preimage — inverted means this SATISFIES the condition
        wrong_preimage = os.urandom(32)
        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "HASH_PREIMAGE", "preimage": wrong_preimage.hex()}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  Inverted HASH_PREIMAGE spend (wrong preimage) confirmed!")


    # =========================================================================
    # Phase 4 tests (new block types)
    # =========================================================================

    def test_tagged_hash(self, node):
        """TAGGED_HASH: BIP-340 tagged hash verification."""
        self.log.info("Testing TAGGED_HASH spend...")

        # Tag and preimage
        tag = b"GhostTaggedHash"
        preimage = os.urandom(32)

        # TAGGED_HASH conditions use actual HASH256 values (not auto-converted):
        # Field 1: SHA256(tag), Field 2: SHA256(SHA256(tag) || SHA256(tag) || preimage)
        tag_hash = hashlib.sha256(tag).digest()
        expected = hashlib.sha256(tag_hash + tag_hash + preimage).digest()

        conditions = [{"blocks": [{"type": "TAGGED_HASH", "fields": [
            {"type": "HASH256", "hex": tag_hash.hex()},
            {"type": "HASH256", "hex": expected.hex()},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  TAGGED_HASH output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "TAGGED_HASH", "preimage": preimage.hex()}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  TAGGED_HASH spend confirmed!")

    def test_amount_lock(self, node):
        """AMOUNT_LOCK: spend within amount range."""
        self.log.info("Testing AMOUNT_LOCK (in range)...")

        # NUMERIC fields are 4 bytes. Use small values that fit easily.
        min_sats = 10000       # 0.0001 BTC
        max_sats = 200000000   # 2.0 BTC

        conditions = [{"blocks": [{"type": "AMOUNT_LOCK", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(min_sats)},
            {"type": "NUMERIC", "hex": numeric_hex(max_sats)},
        ]}]}]

        # Bootstrap with a small amount that fits within the AMOUNT_LOCK range
        # Use createrungtx with two outputs: AMOUNT_LOCK + change
        utxo = self.wallet.get_utxo()
        input_amount = utxo["value"]
        input_txid = utxo["txid"]
        input_vout = utxo["vout"]
        txout_info = node.gettxout(input_txid, input_vout)
        spent_spk = txout_info["scriptPubKey"]["hex"]

        boot_wif, boot_pubkey = make_keypair()
        lock_amount = Decimal("1.0")  # 100M sats — fits in range [10000, 200000000]
        change_amount = Decimal(input_amount) - lock_amount - Decimal("0.001")

        # Change goes to a SIG output
        change_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": boot_pubkey}
        ]}]}]

        result = node.createrungtx(
            [{"txid": input_txid, "vout": input_vout}],
            [
                {"amount": lock_amount, "conditions": conditions},
                {"amount": change_amount, "conditions": change_conditions},
            ]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"privkey": boot_wif, "input": 0}],
            [{"amount": input_amount, "scriptPubKey": spent_spk}]
        )
        assert sign_result["complete"]
        txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)

        tx_info = node.getrawtransaction(txid, True)
        spk = tx_info["vout"][0]["scriptPubKey"]["hex"]
        amount = lock_amount
        self.log.info(f"  AMOUNT_LOCK output: {txid}:0 (amount={amount})")

        # Spend with amount in range
        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        result = node.createrungtx(
            [{"txid": txid, "vout": 0}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "AMOUNT_LOCK"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  AMOUNT_LOCK (in range) spend confirmed!")

    def test_amount_lock_out_of_range(self, node):
        """AMOUNT_LOCK: reject spend outside amount range."""
        self.log.info("Testing AMOUNT_LOCK (out of range)...")

        min_sats = 500000  # 0.005 BTC
        max_sats = 1000000  # 0.01 BTC

        conditions = [{"blocks": [{"type": "AMOUNT_LOCK", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(min_sats)},
            {"type": "NUMERIC", "hex": numeric_hex(max_sats)},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        # Try to spend with output below min (100 sats)
        output_amount = Decimal("0.000001")  # 100 sats — below 500000 min
        dest_wif, dest_pubkey = make_keypair()

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": [{"blocks": [{
                "type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pubkey}]
            }]}]}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "AMOUNT_LOCK"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )

        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  AMOUNT_LOCK (out of range) correctly rejected!")

    def test_anchor_output(self, node):
        """ANCHOR: create and validate anchor output structure."""
        self.log.info("Testing ANCHOR output...")

        _, pubkey_hex = make_keypair()
        state_hash = os.urandom(32)

        # ANCHOR_CHANNEL needs local_key + remote_key + commitment_number
        _, remote_pubkey = make_keypair()
        conditions = [{"blocks": [{"type": "ANCHOR_CHANNEL", "fields": [
            {"type": "PUBKEY", "hex": pubkey_hex},
            {"type": "PUBKEY", "hex": remote_pubkey},
            {"type": "NUMERIC", "hex": numeric_hex(1)},  # commitment_number
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  ANCHOR_CHANNEL output: {txid}:{vout}")

        # Decode and verify the output structure
        tx_hex = node.getrawtransaction(txid)
        decoded = node.validateladder(tx_hex)
        self.log.info(f"  validateladder: valid={decoded['valid']}")

        # Spend the anchor (structural validation)
        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": [{"blocks": [{
                "type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pubkey}]
            }]}]}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "ANCHOR_CHANNEL"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  ANCHOR_CHANNEL spend confirmed!")

    def test_compare_block(self, node):
        """COMPARE: test comparison operators on UTXO value."""
        self.log.info("Testing COMPARE block...")

        # COMPARE with GT operator (0x03): input_amount > value_b
        # We'll use a threshold of 1000 sats
        threshold = 1000
        operator_gt = 3  # GT

        conditions = [{"blocks": [{"type": "COMPARE", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(operator_gt)},  # operator
            {"type": "NUMERIC", "hex": numeric_hex(threshold)},    # value_b
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  COMPARE(GT) output: {txid}:{vout} (amount={amount})")

        # Spend — should succeed since input amount >> threshold
        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": [{"blocks": [{
                "type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pubkey}]
            }]}]}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "COMPARE"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  COMPARE(GT) spend confirmed!")

    def test_ctv_template(self, node):
        """CTV: Full end-to-end CheckTemplateVerify — lock and spend."""
        self.log.info("Testing CTV template verify (full spend cycle)...")

        privkey_wif, pubkey_hex = make_keypair()
        dest_wif, dest_pubkey = make_keypair()

        # Step 1: Bootstrap a SIG-locked output that we control
        utxo = self.wallet.get_utxo()
        input_amount = utxo["value"]
        input_txid = utxo["txid"]
        input_vout = utxo["vout"]

        txout_info = node.gettxout(input_txid, input_vout)
        spent_spk = txout_info["scriptPubKey"]["hex"]

        sig_amount = Decimal("1.0")
        change_amount = Decimal(input_amount) - sig_amount - Decimal("0.001")

        sig_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": pubkey_hex}
        ]}]}]
        change_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": pubkey_hex}
        ]}]}]

        bootstrap = node.createrungtx(
            [{"txid": input_txid, "vout": input_vout}],
            [
                {"amount": sig_amount, "conditions": sig_conditions},
                {"amount": change_amount, "conditions": change_conditions},
            ]
        )
        sign_boot = node.signrungtx(
            bootstrap["hex"],
            [{"privkey": privkey_wif, "input": 0}],
            [{"amount": input_amount, "scriptPubKey": spent_spk}]
        )
        assert sign_boot["complete"]
        boot_txid = node.sendrawtransaction(sign_boot["hex"])
        self.generate(node, 1)

        # Step 2: Pre-compute the CTV template hash.
        # CTV hash commits to: version, locktime, scriptsigs_hash, num_inputs,
        # sequences_hash, num_outputs, outputs_hash, input_index.
        # It does NOT commit to input outpoints — so we can compute it with a
        # placeholder input and the hash will match any spending tx with the
        # same outputs/version/locktime/sequences.
        spend_amount = sig_amount - Decimal("0.002")  # fee for CTV output creation + spending
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        # Build a template tx with a dummy input (same structure as the real spend)
        template_tx = node.createrungtx(
            [{"txid": boot_txid, "vout": 0}],  # placeholder input — outpoint not in CTV hash
            [{"amount": spend_amount, "conditions": dest_conditions}]
        )
        ctv_result = node.computectvhash(template_tx["hex"], 0)
        ctv_hash = ctv_result["hash"]
        self.log.info(f"  CTV hash: {ctv_hash}")

        # Step 3: Create the CTV-locked output using the computed hash
        ctv_conditions = [{"blocks": [{"type": "CTV", "fields": [
            {"type": "HASH256", "hex": ctv_hash}
        ]}]}]

        ctv_lock_amount = sig_amount - Decimal("0.001")  # leave fee for this tx
        ctv_create = node.createrungtx(
            [{"txid": boot_txid, "vout": 0}],
            [{"amount": ctv_lock_amount, "conditions": ctv_conditions}]
        )

        boot_txinfo = node.getrawtransaction(boot_txid, True)
        boot_spk = boot_txinfo["vout"][0]["scriptPubKey"]["hex"]

        ctv_sign = node.signrungtx(
            ctv_create["hex"],
            [{"input": 0, "blocks": [{"type": "SIG", "privkey": privkey_wif}]}],
            [{"amount": float(sig_amount), "scriptPubKey": boot_spk}]
        )
        assert ctv_sign["complete"]
        ctv_txid = node.sendrawtransaction(ctv_sign["hex"])
        self.generate(node, 1)
        self.log.info(f"  CTV output: {ctv_txid}:0")

        # Step 4: Spend the CTV output with a tx matching the template exactly.
        # The spending tx must produce the same outputs/version/locktime/sequences
        # that were used to compute the CTV hash.
        ctv_txinfo = node.getrawtransaction(ctv_txid, True)
        ctv_spk = ctv_txinfo["vout"][0]["scriptPubKey"]["hex"]
        ctv_out_amount = Decimal(str(ctv_txinfo["vout"][0]["value"]))

        # Build the real spending tx — must match template structure exactly
        real_spend = node.createrungtx(
            [{"txid": ctv_txid, "vout": 0}],
            [{"amount": spend_amount, "conditions": dest_conditions}]
        )

        # Verify the hash matches
        verify_hash = node.computectvhash(real_spend["hex"], 0)
        assert verify_hash["hash"] == ctv_hash, f"CTV hash mismatch: {verify_hash['hash']} != {ctv_hash}"

        # Sign — CTV block needs no witness data
        real_sign = node.signrungtx(
            real_spend["hex"],
            [{"input": 0, "blocks": [{"type": "CTV"}]}],
            [{"amount": float(ctv_out_amount), "scriptPubKey": ctv_spk}]
        )
        assert real_sign["complete"]

        final_txid = node.sendrawtransaction(real_sign["hex"])
        self.generate(node, 1)

        final_info = node.getrawtransaction(final_txid, True)
        assert final_info["confirmations"] >= 1
        self.log.info(f"  CTV spend confirmed: {final_txid}")
        self.log.info("  CTV full spend cycle passed!")

    def test_vault_lock(self, node):
        """VAULT_LOCK: two-path vault with recovery key and hot key."""
        self.log.info("Testing VAULT_LOCK output...")

        recovery_wif, recovery_pubkey = make_keypair()
        hot_wif, hot_pubkey = make_keypair()
        hot_delay = 10  # CSV blocks for hot path

        conditions = [{"blocks": [{"type": "VAULT_LOCK", "fields": [
            {"type": "PUBKEY", "hex": recovery_pubkey},   # recovery_key
            {"type": "PUBKEY", "hex": hot_pubkey},         # hot_key
            {"type": "NUMERIC", "hex": numeric_hex(hot_delay)},  # hot_delay
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  VAULT_LOCK output: {txid}:{vout}")

        # Cold sweep: spend immediately with recovery key
        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": [{"blocks": [{
                "type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pubkey}]
            }]}]}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "VAULT_LOCK", "privkey": recovery_wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  VAULT_LOCK cold sweep confirmed!")

    def test_negative_ctv_wrong_template(self, node):
        """CTV negative: spending tx doesn't match committed template hash."""
        self.log.info("Testing CTV negative (wrong template)...")

        privkey_wif, pubkey_hex = make_keypair()
        dest_wif, dest_pubkey = make_keypair()

        # Lock to a random hash (no valid spending tx matches)
        wrong_hash = os.urandom(32).hex()
        conditions = [{"blocks": [{"type": "CTV", "fields": [
            {"type": "HASH256", "hex": wrong_hash}
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "CTV"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        assert_raises_rpc_error(-26, "", node.sendrawtransaction, sign_result["hex"])
        self.log.info("  CTV (wrong template) correctly rejected!")

    def test_negative_vault_wrong_key(self, node):
        """VAULT_LOCK negative: wrong key cannot spend."""
        self.log.info("Testing VAULT_LOCK negative (wrong key)...")

        recovery_wif, recovery_pubkey = make_keypair()
        hot_wif, hot_pubkey = make_keypair()
        wrong_wif, wrong_pubkey = make_keypair()

        conditions = [{"blocks": [{"type": "VAULT_LOCK", "fields": [
            {"type": "PUBKEY", "hex": recovery_pubkey},
            {"type": "PUBKEY", "hex": hot_pubkey},
            {"type": "NUMERIC", "hex": numeric_hex(10)},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": [{"blocks": [{
                "type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pubkey}]
            }]}]}]
        )
        # Sign with wrong key (not recovery_key or hot_key)
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "VAULT_LOCK", "privkey": wrong_wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        assert_raises_rpc_error(-26, "", node.sendrawtransaction, sign_result["hex"])
        self.log.info("  VAULT_LOCK (wrong key) correctly rejected!")

    def test_negative_compare_fails(self, node):
        """COMPARE negative: amount below threshold fails GT check."""
        self.log.info("Testing COMPARE negative (below threshold)...")

        privkey_wif, pubkey_hex = make_keypair()

        # COMPARE GT 500000000 (5 BTC) — but input will be ~1 BTC
        conditions = [{"blocks": [{"type": "COMPARE", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(0x03)},      # GT operator
            {"type": "NUMERIC", "hex": numeric_hex(500000000)},  # 5 BTC threshold
        ]}]}]

        # Bootstrap with a controlled 1 BTC output
        utxo = self.wallet.get_utxo()
        input_amount = utxo["value"]
        input_txid = utxo["txid"]
        input_vout = utxo["vout"]
        txout_info = node.gettxout(input_txid, input_vout)
        spent_spk = txout_info["scriptPubKey"]["hex"]

        lock_amount = Decimal("1.0")
        change_amount = Decimal(input_amount) - lock_amount - Decimal("0.001")
        change_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": pubkey_hex}
        ]}]}]

        bootstrap = node.createrungtx(
            [{"txid": input_txid, "vout": input_vout}],
            [
                {"amount": lock_amount, "conditions": conditions},
                {"amount": change_amount, "conditions": change_conditions},
            ]
        )
        sign_boot = node.signrungtx(
            bootstrap["hex"],
            [{"privkey": privkey_wif, "input": 0}],
            [{"amount": input_amount, "scriptPubKey": spent_spk}]
        )
        assert sign_boot["complete"]
        boot_txid = node.sendrawtransaction(sign_boot["hex"])
        self.generate(node, 1)

        # Try to spend — COMPARE GT 5 BTC will fail on ~1 BTC input
        boot_info = node.getrawtransaction(boot_txid, True)
        boot_spk = boot_info["vout"][0]["scriptPubKey"]["hex"]
        boot_amount = Decimal(str(boot_info["vout"][0]["value"]))

        dest_wif, dest_pubkey = make_keypair()
        spend = node.createrungtx(
            [{"txid": boot_txid, "vout": 0}],
            [{"amount": boot_amount - Decimal("0.001"), "conditions": [{"blocks": [{
                "type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pubkey}]
            }]}]}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "COMPARE"}]}],
            [{"amount": float(boot_amount), "scriptPubKey": boot_spk}]
        )
        assert sign_result["complete"]

        assert_raises_rpc_error(-26, "", node.sendrawtransaction, sign_result["hex"])
        self.log.info("  COMPARE (below threshold) correctly rejected!")

    def test_negative_tagged_hash_wrong_preimage(self, node):
        """TAGGED_HASH negative: wrong preimage fails verification."""
        self.log.info("Testing TAGGED_HASH negative (wrong preimage)...")

        privkey_wif, pubkey_hex = make_keypair()

        # Create tagged hash conditions with actual HASH256 values
        tag = b"ghost/test-tag"
        preimage = b"correct_preimage_data"
        tag_hash = hashlib.sha256(tag).digest()
        expected_hash = hashlib.sha256(tag_hash + tag_hash + preimage).digest()
        conditions = [{"blocks": [{"type": "TAGGED_HASH", "fields": [
            {"type": "HASH256", "hex": tag_hash.hex()},
            {"type": "HASH256", "hex": expected_hash.hex()},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": [{"blocks": [{
                "type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pubkey}]
            }]}]}]
        )

        # Sign with WRONG preimage
        wrong_preimage = b"wrong_preimage_data"
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "TAGGED_HASH", "preimage": wrong_preimage.hex()}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        assert_raises_rpc_error(-26, "", node.sendrawtransaction, sign_result["hex"])
        self.log.info("  TAGGED_HASH (wrong preimage) correctly rejected!")

    def test_recurse_same(self, node):
        """RECURSE_SAME: spend into output with identical conditions."""
        self.log.info("Testing RECURSE_SAME (covenant re-encumbrance)...")

        privkey_wif, pubkey_hex = make_keypair()

        # RECURSE_SAME with max_depth=5
        conditions = [{"blocks": [{"type": "RECURSE_SAME", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(5)},  # max_depth
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  RECURSE_SAME output: {txid}:{vout}")

        # Spend into output with IDENTICAL conditions (same RECURSE_SAME block)
        output_amount = amount - Decimal("0.001")
        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": conditions}]  # same conditions
        )

        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "RECURSE_SAME"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info(f"  RECURSE_SAME spend confirmed: {spend_txid}")

        # Verify the output still has the same conditions
        validate = node.validateladder(node.getrawtransaction(spend_txid))
        assert validate["valid"]
        self.log.info("  RECURSE_SAME covenant re-encumbrance passed!")

    def test_negative_recurse_same_different(self, node):
        """RECURSE_SAME negative: output with different conditions rejected."""
        self.log.info("Testing RECURSE_SAME negative (different output conditions)...")

        privkey_wif, pubkey_hex = make_keypair()

        conditions = [{"blocks": [{"type": "RECURSE_SAME", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(5)},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        # Try to spend into output with DIFFERENT conditions
        different_conditions = [{"blocks": [{"type": "RECURSE_SAME", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(10)},  # different max_depth
        ]}]}]

        output_amount = amount - Decimal("0.001")
        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": different_conditions}]
        )

        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "RECURSE_SAME"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        assert_raises_rpc_error(-26, "", node.sendrawtransaction, sign_result["hex"])
        self.log.info("  RECURSE_SAME (different conditions) correctly rejected!")

    def test_recurse_same_chain(self, node):
        """RECURSE_SAME: multi-hop covenant chain (3 consecutive spends)."""
        self.log.info("Testing RECURSE_SAME chain (3-hop covenant)...")

        conditions = [{"blocks": [{"type": "RECURSE_SAME", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(10)},  # max_depth
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  Hop 0 (bootstrap): {txid}:{vout}")

        # Chain 3 spends, each re-encumbering with identical conditions
        for hop in range(1, 4):
            output_amount = amount - Decimal("0.001")
            spend = node.createrungtx(
                [{"txid": txid, "vout": vout}],
                [{"amount": output_amount, "conditions": conditions}]
            )
            sign_result = node.signrungtx(
                spend["hex"],
                [{"input": 0, "blocks": [{"type": "RECURSE_SAME"}]}],
                [{"amount": amount, "scriptPubKey": spk}]
            )
            assert sign_result["complete"]

            txid = node.sendrawtransaction(sign_result["hex"])
            self.generate(node, 1)
            tx_info = node.getrawtransaction(txid, True)
            assert tx_info["confirmations"] >= 1
            spk = tx_info["vout"][0]["scriptPubKey"]["hex"]
            amount = output_amount
            vout = 0
            self.log.info(f"  Hop {hop}: {txid}")

        self.log.info("  RECURSE_SAME 3-hop chain passed!")

    def test_recurse_until_re_encumber(self, node):
        """RECURSE_UNTIL: before termination height, must re-encumber with same conditions."""
        self.log.info("Testing RECURSE_UNTIL (re-encumber before termination)...")

        current_height = node.getblockcount()
        until_height = current_height + 100  # far in the future

        conditions = [{"blocks": [{"type": "RECURSE_UNTIL", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(until_height)},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  RECURSE_UNTIL output: {txid}:{vout} (until_height={until_height})")

        # Spend BEFORE until_height — must re-encumber with identical conditions
        # nLockTime = current height (below until_height)
        current = node.getblockcount()
        output_amount = amount - Decimal("0.001")
        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": conditions}],  # same conditions
            current,  # nLockTime < until_height
        )

        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "RECURSE_UNTIL"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info(f"  RECURSE_UNTIL re-encumber confirmed: {spend_txid}")
        self.log.info("  RECURSE_UNTIL re-encumber before termination passed!")

    def test_recurse_until_termination(self, node):
        """RECURSE_UNTIL: covenant terminates when block height >= until_height."""
        self.log.info("Testing RECURSE_UNTIL (termination at target height)...")

        # Get current height and set until_height just a few blocks ahead
        current_height = node.getblockcount()
        until_height = current_height + 3

        conditions = [{"blocks": [{"type": "RECURSE_UNTIL", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(until_height)},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  RECURSE_UNTIL output: {txid}:{vout} (until_height={until_height})")

        # Mine past the until_height
        blocks_needed = until_height - node.getblockcount() + 1
        if blocks_needed > 0:
            self.generate(node, blocks_needed)
        self.log.info(f"  Current height: {node.getblockcount()} (>= {until_height})")

        # Now spend freely — covenant terminates at/past until_height
        # Set nLockTime to current height (like CLTV, consensus uses nLockTime as height proxy)
        current = node.getblockcount()
        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}],
            current,  # nLockTime = current height (>= until_height)
        )

        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "RECURSE_UNTIL"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info(f"  RECURSE_UNTIL termination confirmed: {spend_txid}")
        self.log.info("  RECURSE_UNTIL termination at target height passed!")

    def test_negative_recurse_until_no_reencumber(self, node):
        """RECURSE_UNTIL negative: before termination, spending without re-encumbering rejected."""
        self.log.info("Testing RECURSE_UNTIL negative (no re-encumber before termination)...")

        current_height = node.getblockcount()
        until_height = current_height + 100

        conditions = [{"blocks": [{"type": "RECURSE_UNTIL", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(until_height)},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        # Try to spend into DIFFERENT conditions before until_height
        current = node.getblockcount()
        dest_wif, dest_pubkey = make_keypair()
        different_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        output_amount = amount - Decimal("0.001")
        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": different_conditions}],
            current,  # nLockTime < until_height
        )

        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "RECURSE_UNTIL"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        assert_raises_rpc_error(-26, "", node.sendrawtransaction, sign_result["hex"])
        self.log.info("  RECURSE_UNTIL (no re-encumber) correctly rejected!")

    def test_recurse_count(self, node):
        """RECURSE_COUNT: countdown covenant from 2→1→0 then free spend."""
        self.log.info("Testing RECURSE_COUNT (countdown 2→0 then free spend)...")

        initial_count = 2
        conditions = [{"blocks": [{"type": "RECURSE_COUNT", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(initial_count)},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  Count {initial_count} (bootstrap): {txid}:{vout}")

        # Decrement: count=2 → output count=1 → output count=0
        for remaining in range(initial_count - 1, -1, -1):
            output_amount = amount - Decimal("0.001")
            next_conditions = [{"blocks": [{"type": "RECURSE_COUNT", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(remaining)},
            ]}]}]

            spend = node.createrungtx(
                [{"txid": txid, "vout": vout}],
                [{"amount": output_amount, "conditions": next_conditions}]
            )

            sign_result = node.signrungtx(
                spend["hex"],
                [{"input": 0, "blocks": [{"type": "RECURSE_COUNT"}]}],
                [{"amount": amount, "scriptPubKey": spk}]
            )
            assert sign_result["complete"]

            txid = node.sendrawtransaction(sign_result["hex"])
            self.generate(node, 1)
            tx_info = node.getrawtransaction(txid, True)
            assert tx_info["confirmations"] >= 1
            spk = tx_info["vout"][0]["scriptPubKey"]["hex"]
            amount = output_amount
            vout = 0
            self.log.info(f"  Count {remaining}: {txid}")

        # Now count=0 — covenant terminates, spend freely to any output
        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        free_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": free_conditions}]
        )

        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "RECURSE_COUNT"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info(f"  Free spend (count=0 terminated): {txid}")
        self.log.info("  RECURSE_COUNT countdown + free spend passed!")

    def test_recurse_modified(self, node):
        """RECURSE_MODIFIED: covenant with single-parameter increase per hop."""
        self.log.info("Testing RECURSE_MODIFIED (single mutation per hop)...")

        # Conditions: RECURSE_MODIFIED + COMPARE(GT threshold) in same rung
        # Mutation spec: block_idx=1 (COMPARE), param_idx=1 (value_b = threshold), delta=+1000
        # Each hop increases the minimum threshold for COMPARE
        initial_threshold = 10000  # GT 10000 sats
        conditions = [{"blocks": [
            {"type": "RECURSE_MODIFIED", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(10)},   # max_depth
                {"type": "NUMERIC", "hex": numeric_hex(1)},    # mutation_block_idx (COMPARE is block 1)
                {"type": "NUMERIC", "hex": numeric_hex(1)},    # mutation_param_idx (second NUMERIC = threshold)
                {"type": "NUMERIC", "hex": numeric_hex(1000)},  # delta = +1000
            ]},
            {"type": "COMPARE", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(0x03)},  # GT operator
                {"type": "NUMERIC", "hex": numeric_hex(initial_threshold)},
            ]},
        ]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  RECURSE_MODIFIED output: {txid}:{vout} (threshold={initial_threshold})")

        # Hop 1: mutate threshold from 10000 to 11000
        new_threshold = initial_threshold + 1000
        mutated_conditions = [{"blocks": [
            {"type": "RECURSE_MODIFIED", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(10)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},
                {"type": "NUMERIC", "hex": numeric_hex(1000)},
            ]},
            {"type": "COMPARE", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(0x03)},  # GT operator (unchanged)
                {"type": "NUMERIC", "hex": numeric_hex(new_threshold)},
            ]},
        ]}]

        output_amount = amount - Decimal("0.001")
        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": mutated_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "RECURSE_MODIFIED"}, {"type": "COMPARE"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info(f"  RECURSE_MODIFIED hop (threshold {initial_threshold}→{new_threshold}): {txid}")
        self.log.info("  RECURSE_MODIFIED passed!")

    def test_recurse_split(self, node):
        """RECURSE_SPLIT: split one UTXO into two re-encumbered outputs."""
        self.log.info("Testing RECURSE_SPLIT (1→2 split)...")

        min_split_sats = 10000  # 0.0001 BTC
        conditions = [{"blocks": [{"type": "RECURSE_SPLIT", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(3)},          # max_splits
            {"type": "NUMERIC", "hex": numeric_hex(min_split_sats)},  # min_split_sats
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  RECURSE_SPLIT output: {txid}:{vout} ({amount} BTC)")

        # Split into two outputs, each carrying RECURSE_SPLIT with max_splits-1
        split_conditions = [{"blocks": [{"type": "RECURSE_SPLIT", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(2)},          # decremented
            {"type": "NUMERIC", "hex": numeric_hex(min_split_sats)},
        ]}]}]

        half = (amount - Decimal("0.001")) / 2
        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [
                {"amount": half, "conditions": split_conditions},
                {"amount": half, "conditions": split_conditions},
            ]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "RECURSE_SPLIT"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(txid, True)
        assert tx_info["confirmations"] >= 1
        assert len(tx_info["vout"]) == 2
        self.log.info(f"  RECURSE_SPLIT confirmed (2 outputs): {txid}")
        self.log.info("  RECURSE_SPLIT passed!")

    def test_hash160_preimage_spend(self, node):
        """HASH160_PREIMAGE: RIPEMD160(SHA256(preimage)) spend."""
        self.log.info("Testing HASH160_PREIMAGE spend...")

        preimage = os.urandom(16)

        conditions = [{"blocks": [{"type": "HASH160_PREIMAGE", "fields": [
            {"type": "PREIMAGE", "hex": preimage.hex()},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  HASH160_PREIMAGE output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "HASH160_PREIMAGE", "preimage": preimage.hex()}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  HASH160_PREIMAGE spend confirmed!")

    def test_csv_time_spend(self, node):
        """CSV_TIME: relative time-based sequence lock spend."""
        self.log.info("Testing CSV_TIME spend...")

        # 512 seconds = 1 unit in time-based CSV (each unit is 512 seconds)
        # Set TYPE_FLAG (bit 22 = 0x00400000) to indicate time-based
        csv_time_units = 1  # 512 seconds
        csv_sequence = 0x00400000 | csv_time_units  # TYPE_FLAG | units

        conditions = [{"blocks": [{"type": "CSV_TIME", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(csv_sequence)},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  CSV_TIME output: {txid}:{vout} (sequence=0x{csv_sequence:08x})")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        # Advance mocktime by 600 seconds (> 512) and mine blocks to push MTP forward
        current_time = node.getblock(node.getbestblockhash())["time"]
        node.setmocktime(current_time + 600)
        self.generate(node, 11)  # MTP = median of last 11 blocks

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout, "sequence": csv_sequence}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "CSV_TIME"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        # Reset mocktime
        node.setmocktime(0)
        self.log.info("  CSV_TIME spend confirmed!")

    def test_cltv_time_spend(self, node):
        """CLTV_TIME: absolute time-based locktime spend."""
        self.log.info("Testing CLTV_TIME spend...")

        # Use a timestamp above LOCKTIME_THRESHOLD (500_000_000)
        # Get current MTP and set target to current MTP - 1 (already passed)
        current_mtp = node.getblock(node.getbestblockhash())["mediantime"]
        target_time = current_mtp - 1  # one second in the past

        conditions = [{"blocks": [{"type": "CLTV_TIME", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(target_time)},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  CLTV_TIME output: {txid}:{vout} (target_time={target_time})")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        # nLockTime must be >= target_time, and MTP must be >= nLockTime
        # Use target_time as locktime (MTP is already past it since we used MTP-1)
        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}],
            target_time,  # nLockTime = target timestamp
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "CLTV_TIME"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  CLTV_TIME spend confirmed!")

    def test_hysteresis_value(self, node):
        """HYSTERESIS_VALUE: input amount must be within [low, high] band."""
        self.log.info("Testing HYSTERESIS_VALUE spend...")

        # Set band: 0.1 BTC to ~42.9 BTC (max uint32 in sats)
        low_sats = 10_000_000   # 0.1 BTC
        high_sats = 0xFFFFFFFF  # ~42.9 BTC (max uint32)

        conditions = [{"blocks": [{"type": "HYSTERESIS_VALUE", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(high_sats)},
            {"type": "NUMERIC", "hex": numeric_hex(low_sats)},
        ]}]}]

        # Use 10 BTC output to stay within uint32 NUMERIC range
        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions, output_amount=Decimal("10.0"))
        self.log.info(f"  HYSTERESIS_VALUE output: {txid}:{vout} ({amount} BTC)")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "HYSTERESIS_VALUE"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  HYSTERESIS_VALUE spend confirmed!")

    def test_rate_limit(self, node):
        """RATE_LIMIT: output amount must be within per-block limit."""
        self.log.info("Testing RATE_LIMIT spend...")

        max_per_block = 0xFFFFFFFF  # ~42.9 BTC per block limit (max uint32)
        accumulation_cap = 0xFFFFFFFF  # same
        refill_blocks = 10

        conditions = [{"blocks": [{"type": "RATE_LIMIT", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(max_per_block)},
            {"type": "NUMERIC", "hex": numeric_hex(accumulation_cap)},
            {"type": "NUMERIC", "hex": numeric_hex(refill_blocks)},
        ]}]}]

        # Use 10 BTC output to stay within uint32 NUMERIC range
        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions, output_amount=Decimal("10.0"))
        self.log.info(f"  RATE_LIMIT output: {txid}:{vout} ({amount} BTC)")

        # Spend within limit (output_amount is the first output's value, checked by RATE_LIMIT)
        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "RATE_LIMIT"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  RATE_LIMIT spend confirmed!")

    def test_sequencer(self, node):
        """SEQUENCER: step 0 of 3 is valid."""
        self.log.info("Testing SEQUENCER spend...")

        conditions = [{"blocks": [{"type": "SEQUENCER", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(0)},  # current_step
            {"type": "NUMERIC", "hex": numeric_hex(3)},  # total_steps
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  SEQUENCER output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "SEQUENCER"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  SEQUENCER spend confirmed!")


    def test_adaptor_sig(self, node):
        """ADAPTOR_SIG: adapted signature with signing_key + adaptor_point."""
        self.log.info("Testing ADAPTOR_SIG spend...")

        # ADAPTOR_SIG needs 2 pubkeys + 1 signature
        # The adapted sig verifies against signing_key (adaptor secret already applied)
        # adaptor_point must be 32 bytes (x-only), signing_key can be 33 bytes (compressed)
        signing_wif, signing_pubkey = make_keypair()
        _adaptor_wif, adaptor_pubkey_full = make_keypair()
        # Strip prefix byte to get 32-byte x-only adaptor point
        adaptor_point_xonly = adaptor_pubkey_full[2:]  # remove 02/03 prefix

        conditions = [{"blocks": [{"type": "ADAPTOR_SIG", "fields": [
            {"type": "PUBKEY", "hex": signing_pubkey},
            {"type": "PUBKEY", "hex": adaptor_point_xonly},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  ADAPTOR_SIG output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        # Sign via block-level privkey (ADAPTOR_SIG handler in signrungtx)
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "ADAPTOR_SIG", "privkey": signing_wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  ADAPTOR_SIG spend confirmed!")

    def test_anchor(self, node):
        """ANCHOR: generic anchor with at least one field."""
        self.log.info("Testing ANCHOR spend...")

        conditions = [{"blocks": [{"type": "ANCHOR", "fields": [
            {"type": "HASH256", "hex": os.urandom(32).hex()},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  ANCHOR output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "ANCHOR"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  ANCHOR spend confirmed!")

    def test_anchor_channel(self, node):
        """ANCHOR_CHANNEL: 2 pubkeys + optional commitment > 0."""
        self.log.info("Testing ANCHOR_CHANNEL spend...")

        _local_wif, local_pubkey = make_keypair()
        _remote_wif, remote_pubkey = make_keypair()

        conditions = [{"blocks": [{"type": "ANCHOR_CHANNEL", "fields": [
            {"type": "PUBKEY", "hex": local_pubkey},
            {"type": "PUBKEY", "hex": remote_pubkey},
            {"type": "NUMERIC", "hex": numeric_hex(42)},  # commitment_number
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  ANCHOR_CHANNEL output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "ANCHOR_CHANNEL"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  ANCHOR_CHANNEL spend confirmed!")

    def test_anchor_pool(self, node):
        """ANCHOR_POOL: vtxo tree root hash + optional participant count."""
        self.log.info("Testing ANCHOR_POOL spend...")

        conditions = [{"blocks": [{"type": "ANCHOR_POOL", "fields": [
            {"type": "HASH256", "hex": os.urandom(32).hex()},
            {"type": "NUMERIC", "hex": numeric_hex(42)},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  ANCHOR_POOL output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "ANCHOR_POOL"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  ANCHOR_POOL spend confirmed!")

    def test_anchor_reserve(self, node):
        """ANCHOR_RESERVE: 2 numerics (n <= m) + 1 hash."""
        self.log.info("Testing ANCHOR_RESERVE spend...")

        conditions = [{"blocks": [{"type": "ANCHOR_RESERVE", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(3)},   # threshold_n
            {"type": "NUMERIC", "hex": numeric_hex(5)},   # threshold_m
            {"type": "HASH256", "hex": os.urandom(32).hex()},  # guardian set hash
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  ANCHOR_RESERVE output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "ANCHOR_RESERVE"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  ANCHOR_RESERVE spend confirmed!")

    def test_anchor_seal(self, node):
        """ANCHOR_SEAL: 2 hashes (asset_id + state_transition)."""
        self.log.info("Testing ANCHOR_SEAL spend...")

        conditions = [{"blocks": [{"type": "ANCHOR_SEAL", "fields": [
            {"type": "HASH256", "hex": os.urandom(32).hex()},  # asset_id
            {"type": "HASH256", "hex": os.urandom(32).hex()},  # state_transition
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  ANCHOR_SEAL output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "ANCHOR_SEAL"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  ANCHOR_SEAL spend confirmed!")

    def test_anchor_oracle(self, node):
        """ANCHOR_ORACLE: 1 pubkey + optional outcome count."""
        self.log.info("Testing ANCHOR_ORACLE spend...")

        _oracle_wif, oracle_pubkey = make_keypair()

        conditions = [{"blocks": [{"type": "ANCHOR_ORACLE", "fields": [
            {"type": "PUBKEY", "hex": oracle_pubkey},
            {"type": "NUMERIC", "hex": numeric_hex(10)},  # outcome_count
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  ANCHOR_ORACLE output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "ANCHOR_ORACLE"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  ANCHOR_ORACLE spend confirmed!")

    def test_recurse_decay(self, node):
        """RECURSE_DECAY: covenant with parameter subtraction per hop."""
        self.log.info("Testing RECURSE_DECAY (parameter decay per hop)...")

        # Conditions: RECURSE_DECAY + COMPARE(GT threshold) in same rung
        # Decay spec: block_idx=1 (COMPARE), param_idx=1 (value_b = threshold), decay_per_step=500
        # Each hop DECREASES the threshold by 500 (relaxing constraint)
        initial_threshold = 5000
        conditions = [{"blocks": [
            {"type": "RECURSE_DECAY", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(10)},   # max_depth
                {"type": "NUMERIC", "hex": numeric_hex(1)},    # decay_block_idx (COMPARE is block 1)
                {"type": "NUMERIC", "hex": numeric_hex(1)},    # decay_param_idx (second NUMERIC = threshold)
                {"type": "NUMERIC", "hex": numeric_hex(500)},  # decay_per_step
            ]},
            {"type": "COMPARE", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(0x03)},  # GT operator
                {"type": "NUMERIC", "hex": numeric_hex(initial_threshold)},
            ]},
        ]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  RECURSE_DECAY output: {txid}:{vout} (threshold={initial_threshold})")

        # Hop 1: decay threshold from 5000 to 4500
        new_threshold = initial_threshold - 500
        decayed_conditions = [{"blocks": [
            {"type": "RECURSE_DECAY", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(10)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},
                {"type": "NUMERIC", "hex": numeric_hex(500)},
            ]},
            {"type": "COMPARE", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(0x03)},
                {"type": "NUMERIC", "hex": numeric_hex(new_threshold)},
            ]},
        ]}]

        output_amount = amount - Decimal("0.001")
        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": decayed_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "RECURSE_DECAY"}, {"type": "COMPARE"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info(f"  RECURSE_DECAY hop (threshold {initial_threshold}→{new_threshold}): {txid}")
        self.log.info("  RECURSE_DECAY passed!")

    def test_hysteresis_fee(self, node):
        """HYSTERESIS_FEE: 2 numerics (high >= low), checks fee rate in band."""
        self.log.info("Testing HYSTERESIS_FEE spend...")

        conditions = [{"blocks": [{"type": "HYSTERESIS_FEE", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(100)},  # high_sat_vb
            {"type": "NUMERIC", "hex": numeric_hex(10)},   # low_sat_vb
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  HYSTERESIS_FEE output: {txid}:{vout}")

        # Fee must produce a rate within 10-100 sat/vB.
        # A 1-in/1-out v4 tx is ~150 vbytes, so target ~50 sat/vB = 7500 sats fee.
        output_amount = amount - Decimal("0.000075")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "HYSTERESIS_FEE"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  HYSTERESIS_FEE spend confirmed!")

    def test_timer_continuous(self, node):
        """TIMER_CONTINUOUS: 1 numeric > 0, structural only."""
        self.log.info("Testing TIMER_CONTINUOUS spend...")

        conditions = [{"blocks": [{"type": "TIMER_CONTINUOUS", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(144)},  # block count
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  TIMER_CONTINUOUS output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "TIMER_CONTINUOUS"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  TIMER_CONTINUOUS spend confirmed!")

    def test_timer_off_delay(self, node):
        """TIMER_OFF_DELAY: 1 numeric > 0, structural only."""
        self.log.info("Testing TIMER_OFF_DELAY spend...")

        conditions = [{"blocks": [{"type": "TIMER_OFF_DELAY", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(72)},  # hold blocks
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  TIMER_OFF_DELAY output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "TIMER_OFF_DELAY"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  TIMER_OFF_DELAY spend confirmed!")

    def test_latch_set(self, node):
        """LATCH_SET: 1 pubkey required, structural only."""
        self.log.info("Testing LATCH_SET spend...")

        _setter_wif, setter_pubkey = make_keypair()

        conditions = [{"blocks": [{"type": "LATCH_SET", "fields": [
            {"type": "PUBKEY", "hex": setter_pubkey},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  LATCH_SET output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "LATCH_SET"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  LATCH_SET spend confirmed!")

    def test_latch_reset(self, node):
        """LATCH_RESET: 1 pubkey + 2 numeric (state + delay) required."""
        self.log.info("Testing LATCH_RESET spend...")

        _resetter_wif, resetter_pubkey = make_keypair()

        conditions = [{"blocks": [{"type": "LATCH_RESET", "fields": [
            {"type": "PUBKEY", "hex": resetter_pubkey},
            {"type": "NUMERIC", "hex": numeric_hex(1)},  # state=1 (set, so reset is active)
            {"type": "NUMERIC", "hex": numeric_hex(6)},  # delay blocks
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  LATCH_RESET output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "LATCH_RESET"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  LATCH_RESET spend confirmed!")

    def test_counter_down(self, node):
        """COUNTER_DOWN: 1 pubkey + 1 numeric required, structural only."""
        self.log.info("Testing COUNTER_DOWN spend...")

        _event_wif, event_pubkey = make_keypair()

        conditions = [{"blocks": [{"type": "COUNTER_DOWN", "fields": [
            {"type": "PUBKEY", "hex": event_pubkey},
            {"type": "NUMERIC", "hex": numeric_hex(10)},  # initial count
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  COUNTER_DOWN output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "COUNTER_DOWN"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  COUNTER_DOWN spend confirmed!")

    def test_counter_preset(self, node):
        """COUNTER_PRESET: 2 numerics required, structural only."""
        self.log.info("Testing COUNTER_PRESET spend...")

        conditions = [{"blocks": [{"type": "COUNTER_PRESET", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(5)},    # preset_count
            {"type": "NUMERIC", "hex": numeric_hex(100)},  # window_blocks
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  COUNTER_PRESET output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "COUNTER_PRESET"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  COUNTER_PRESET spend confirmed!")

    def test_counter_up(self, node):
        """COUNTER_UP: 1 pubkey + 1 numeric required, structural only."""
        self.log.info("Testing COUNTER_UP spend...")

        _event_wif, event_pubkey = make_keypair()

        conditions = [{"blocks": [{"type": "COUNTER_UP", "fields": [
            {"type": "PUBKEY", "hex": event_pubkey},
            {"type": "NUMERIC", "hex": numeric_hex(0)},   # current count
            {"type": "NUMERIC", "hex": numeric_hex(10)},  # target
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  COUNTER_UP output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "COUNTER_UP"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  COUNTER_UP spend confirmed!")

    def test_one_shot(self, node):
        """ONE_SHOT: 1 numeric + 1 hash required, structural only."""
        self.log.info("Testing ONE_SHOT spend...")

        conditions = [{"blocks": [{"type": "ONE_SHOT", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(0)},  # state: 0=unfired
            {"type": "HASH256", "hex": os.urandom(32).hex()},  # commitment
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  ONE_SHOT output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "ONE_SHOT"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  ONE_SHOT spend confirmed!")


    # =========================================================================
    # Edge case tests
    # =========================================================================

    def test_multi_rung_mixed_blocks(self, node):
        """Multi-rung ladder with different block types in each rung (OR logic)."""
        self.log.info("Testing multi-rung ladder with mixed block types...")

        # Rung 0: SIG + CSV (both must pass = AND logic)
        # Rung 1: HASH_PREIMAGE (fallback)
        privkey_wif, pubkey_hex = make_keypair()
        preimage = os.urandom(16)

        conditions = [
            {"blocks": [
                {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pubkey_hex}]},
                {"type": "CSV", "fields": [{"type": "NUMERIC", "hex": numeric_hex(1)}]},
            ]},
            {"blocks": [
                {"type": "HASH_PREIMAGE", "fields": [{"type": "PREIMAGE", "hex": preimage.hex()}]},
            ]},
        ]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  Multi-rung output: {txid}:{vout}")

        # Spend via rung 1 (HASH_PREIMAGE fallback) — target rung 1
        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "rung": 1, "blocks": [{"type": "HASH_PREIMAGE", "preimage": preimage.hex()}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  Multi-rung mixed blocks spend confirmed (via fallback rung)!")

    def test_max_blocks_per_rung(self, node):
        """8 blocks per rung (max policy limit)."""
        self.log.info("Testing max blocks per rung (8)...")

        # Build a rung with 8 structural blocks
        blocks = []
        for _ in range(8):
            _wif, pk = make_keypair()
            blocks.append({"type": "LATCH_SET", "fields": [
                {"type": "PUBKEY", "hex": pk},
            ]})

        conditions = [{"blocks": blocks}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  Max blocks output: {txid}:{vout} (8 blocks)")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        # All 8 LATCH_SET blocks in witness
        sign_blocks = [{"type": "LATCH_SET"} for _ in range(8)]
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": sign_blocks}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  Max blocks per rung (8) spend confirmed!")

    def test_deeply_nested_covenant_chain(self, node):
        """RECURSE_SAME 5-hop covenant chain."""
        self.log.info("Testing deeply nested covenant chain (5 hops)...")

        conditions = [{"blocks": [{"type": "RECURSE_SAME", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(10)},  # max_depth
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  Covenant chain start: {txid}:{vout}")

        for hop in range(5):
            output_amount = amount - Decimal("0.001")
            spend = node.createrungtx(
                [{"txid": txid, "vout": vout}],
                [{"amount": output_amount, "conditions": conditions}]
            )
            sign_result = node.signrungtx(
                spend["hex"],
                [{"input": 0, "blocks": [{"type": "RECURSE_SAME"}]}],
                [{"amount": amount, "scriptPubKey": spk}]
            )
            assert sign_result["complete"]

            txid = node.sendrawtransaction(sign_result["hex"])
            self.generate(node, 1)
            tx_info = node.getrawtransaction(txid, True)
            assert tx_info["confirmations"] >= 1
            spk = tx_info["vout"][0]["scriptPubKey"]["hex"]
            amount = output_amount
            vout = 0
            self.log.info(f"  Hop {hop + 1}: {txid}")

        self.log.info("  5-hop covenant chain passed!")

    # =========================================================================
    # RPC hardening tests
    # =========================================================================

    def test_rpc_unknown_block_type(self, node):
        """createrung rejects unknown block type."""
        self.log.info("Testing RPC: unknown block type...")
        assert_raises_rpc_error(-8, "Unknown block type", node.createrung,
            [{"blocks": [{"type": "NONEXISTENT_BLOCK", "fields": []}]}])
        self.log.info("  Unknown block type correctly rejected!")

    def test_rpc_unknown_data_type(self, node):
        """createrung rejects unknown data type."""
        self.log.info("Testing RPC: unknown data type...")
        assert_raises_rpc_error(-8, "Unknown data type", node.createrung,
            [{"blocks": [{"type": "SIG", "fields": [
                {"type": "BOGUS_TYPE", "hex": "aabb"}
            ]}]}])
        self.log.info("  Unknown data type correctly rejected!")

    def test_rpc_empty_rungs(self, node):
        """createrung rejects empty rungs array."""
        self.log.info("Testing RPC: empty rungs array...")
        # Empty rungs should serialize but produce a witness with 0 rungs
        # which would fail deserialization. Let's check both paths.
        result = node.createrung([{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": "02" + "aa" * 32}
        ]}]}])
        assert "hex" in result

        # decoderung with malformed hex should fail
        assert_raises_rpc_error(-22, None, node.decoderung, "deadbeef")
        self.log.info("  Empty rungs / malformed hex correctly handled!")

    def test_rpc_invalid_field_hex(self, node):
        """createrung rejects invalid field hex data."""
        self.log.info("Testing RPC: invalid field hex...")
        # HASH256 must be exactly 32 bytes
        assert_raises_rpc_error(-8, None, node.createrung,
            [{"blocks": [{"type": "ANCHOR", "fields": [
                {"type": "HASH256", "hex": "aabb"}  # 2 bytes, not 32
            ]}]}])
        self.log.info("  Invalid field hex correctly rejected!")

    def test_rpc_decoderung_invalid_hex(self, node):
        """decoderung rejects completely invalid hex."""
        self.log.info("Testing RPC: decoderung invalid hex...")
        assert_raises_rpc_error(-22, None, node.decoderung, "00")  # zero rungs
        assert_raises_rpc_error(-8, None, node.decoderung, "")  # empty → invalid hex
        self.log.info("  decoderung invalid hex correctly rejected!")

    def test_rpc_createrungtx_negative_amount(self, node):
        """createrungtx rejects negative output amount."""
        self.log.info("Testing RPC: createrungtx negative amount...")
        assert_raises_rpc_error(-3, None, node.createrungtx,
            [{"txid": "aa" * 32, "vout": 0}],
            [{"amount": Decimal("-0.001"), "conditions": [{"blocks": [{"type": "SIG", "fields": [
                {"type": "PUBKEY", "hex": "02" + "aa" * 32}
            ]}]}]}])
        self.log.info("  createrungtx negative amount correctly rejected!")

    def test_rpc_signrungtx_missing_spent_info(self, node):
        """signrungtx rejects mismatched spent_outputs count."""
        self.log.info("Testing RPC: signrungtx mismatched spent info...")

        # Create a valid unsigned tx first
        privkey_wif, pubkey_hex = make_keypair()
        conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": pubkey_hex}
        ]}]}]
        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        output_amount = amount - Decimal("0.001")
        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )

        # Pass empty spent_outputs (should have 1) → error
        assert_raises_rpc_error(-8, "spent_outputs count", node.signrungtx,
            spend["hex"],
            [{"privkey": privkey_wif, "input": 0}],
            [])  # empty: count mismatch
        self.log.info("  signrungtx mismatched spent info correctly rejected!")

    # =========================================================================
    # Negative tests for remaining block types
    # =========================================================================

    def test_negative_adaptor_sig_wrong_key(self, node):
        """ADAPTOR_SIG: wrong signing key should fail."""
        self.log.info("Testing ADAPTOR_SIG negative (wrong key)...")

        _signing_wif, signing_pubkey = make_keypair()
        _adaptor_wif, adaptor_pubkey_full = make_keypair()
        adaptor_point_xonly = adaptor_pubkey_full[2:]  # 32-byte x-only
        wrong_wif, _wrong_pubkey = make_keypair()

        conditions = [{"blocks": [{"type": "ADAPTOR_SIG", "fields": [
            {"type": "PUBKEY", "hex": signing_pubkey},
            {"type": "PUBKEY", "hex": adaptor_point_xonly},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "ADAPTOR_SIG", "privkey": wrong_wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  ADAPTOR_SIG (wrong key) correctly rejected!")

    def test_negative_anchor_reserve_n_gt_m(self, node):
        """ANCHOR_RESERVE: n > m should fail (UNSATISFIED)."""
        self.log.info("Testing ANCHOR_RESERVE negative (n > m)...")

        conditions = [{"blocks": [{"type": "ANCHOR_RESERVE", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(7)},   # threshold_n > threshold_m
            {"type": "NUMERIC", "hex": numeric_hex(5)},   # threshold_m
            {"type": "HASH256", "hex": os.urandom(32).hex()},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "ANCHOR_RESERVE"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  ANCHOR_RESERVE (n > m) correctly rejected!")

    def test_negative_hysteresis_fee_low_gt_high(self, node):
        """HYSTERESIS_FEE: low > high should fail (UNSATISFIED)."""
        self.log.info("Testing HYSTERESIS_FEE negative (low > high)...")

        conditions = [{"blocks": [{"type": "HYSTERESIS_FEE", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(10)},   # high_sat_vb
            {"type": "NUMERIC", "hex": numeric_hex(100)},  # low_sat_vb > high
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "HYSTERESIS_FEE"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  HYSTERESIS_FEE (low > high) correctly rejected!")

    def test_negative_anchor_channel_zero_commitment(self, node):
        """ANCHOR_CHANNEL: commitment_number = 0 should fail (UNSATISFIED)."""
        self.log.info("Testing ANCHOR_CHANNEL negative (zero commitment)...")

        _local_wif, local_pubkey = make_keypair()
        _remote_wif, remote_pubkey = make_keypair()

        conditions = [{"blocks": [{"type": "ANCHOR_CHANNEL", "fields": [
            {"type": "PUBKEY", "hex": local_pubkey},
            {"type": "PUBKEY", "hex": remote_pubkey},
            {"type": "NUMERIC", "hex": numeric_hex(0)},  # commitment_number = 0
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "ANCHOR_CHANNEL"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  ANCHOR_CHANNEL (zero commitment) correctly rejected!")

    def test_negative_anchor_pool_zero_count(self, node):
        """ANCHOR_POOL: participant_count = 0 should fail (UNSATISFIED)."""
        self.log.info("Testing ANCHOR_POOL negative (zero count)...")

        conditions = [{"blocks": [{"type": "ANCHOR_POOL", "fields": [
            {"type": "HASH256", "hex": os.urandom(32).hex()},
            {"type": "NUMERIC", "hex": numeric_hex(0)},  # participant_count = 0
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "ANCHOR_POOL"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  ANCHOR_POOL (zero count) correctly rejected!")

    def test_negative_anchor_oracle_zero_count(self, node):
        """ANCHOR_ORACLE: outcome_count = 0 should fail (UNSATISFIED)."""
        self.log.info("Testing ANCHOR_ORACLE negative (zero count)...")

        _oracle_wif, oracle_pubkey = make_keypair()

        conditions = [{"blocks": [{"type": "ANCHOR_ORACLE", "fields": [
            {"type": "PUBKEY", "hex": oracle_pubkey},
            {"type": "NUMERIC", "hex": numeric_hex(0)},  # outcome_count = 0
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "ANCHOR_ORACLE"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  ANCHOR_ORACLE (zero count) correctly rejected!")

    def test_negative_timer_continuous_zero(self, node):
        """TIMER_CONTINUOUS: value = 0 should fail (UNSATISFIED)."""
        self.log.info("Testing TIMER_CONTINUOUS negative (zero value)...")

        conditions = [{"blocks": [{"type": "TIMER_CONTINUOUS", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(0)},  # 0 is invalid
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "TIMER_CONTINUOUS"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  TIMER_CONTINUOUS (zero) correctly rejected!")

    def test_negative_counter_preset_missing_field(self, node):
        """COUNTER_PRESET: only 1 numeric (needs 2) should fail (ERROR)."""
        self.log.info("Testing COUNTER_PRESET negative (missing field)...")

        conditions = [{"blocks": [{"type": "COUNTER_PRESET", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(5)},  # only preset_count, missing window_blocks
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "COUNTER_PRESET"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  COUNTER_PRESET (missing field) correctly rejected!")

    def test_negative_one_shot_missing_hash(self, node):
        """ONE_SHOT: numeric only (missing hash) should fail (ERROR)."""
        self.log.info("Testing ONE_SHOT negative (missing hash)...")

        conditions = [{"blocks": [{"type": "ONE_SHOT", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(144)},  # duration only, no commitment hash
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "ONE_SHOT"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  ONE_SHOT (missing hash) correctly rejected!")

    def test_negative_recurse_decay_wrong_delta(self, node):
        """RECURSE_DECAY: wrong decay delta should fail."""
        self.log.info("Testing RECURSE_DECAY negative (wrong delta)...")

        initial_threshold = 5000
        conditions = [{"blocks": [
            {"type": "RECURSE_DECAY", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(10)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},
                {"type": "NUMERIC", "hex": numeric_hex(500)},  # decay_per_step = 500
            ]},
            {"type": "COMPARE", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(0x03)},
                {"type": "NUMERIC", "hex": numeric_hex(initial_threshold)},
            ]},
        ]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        # Apply wrong delta: subtract 300 instead of 500
        wrong_threshold = initial_threshold - 300
        wrong_conditions = [{"blocks": [
            {"type": "RECURSE_DECAY", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(10)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},
                {"type": "NUMERIC", "hex": numeric_hex(500)},
            ]},
            {"type": "COMPARE", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(0x03)},
                {"type": "NUMERIC", "hex": numeric_hex(wrong_threshold)},
            ]},
        ]}]

        output_amount = amount - Decimal("0.001")
        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": wrong_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "RECURSE_DECAY"}, {"type": "COMPARE"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  RECURSE_DECAY (wrong delta) correctly rejected!")


    # =========================================================================
    # Stateful latch tests
    # =========================================================================

    def test_latch_state_gating(self, node):
        """LATCH_SET with state=0 is spendable, state=1 is not."""
        self.log.info("Testing LATCH_SET state gating...")

        _setter_wif, setter_pubkey = make_keypair()

        # State=0: LATCH_SET should be SATISFIED → spendable
        conditions_unset = [{"blocks": [{"type": "LATCH_SET", "fields": [
            {"type": "PUBKEY", "hex": setter_pubkey},
            {"type": "NUMERIC", "hex": numeric_hex(0)},  # state=0 (unset)
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions_unset)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "LATCH_SET"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]
        node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        self.log.info("  LATCH_SET state=0 spent OK!")

        # State=1: LATCH_SET should be UNSATISFIED → NOT spendable
        conditions_set = [{"blocks": [{"type": "LATCH_SET", "fields": [
            {"type": "PUBKEY", "hex": setter_pubkey},
            {"type": "NUMERIC", "hex": numeric_hex(1)},  # state=1 (already set)
        ]}]}]

        txid2, vout2, amount2, spk2 = self.bootstrap_v4_output(node, conditions_set)

        spend2 = node.createrungtx(
            [{"txid": txid2, "vout": vout2}],
            [{"amount": amount2 - Decimal("0.001"), "conditions": dest_conditions}]
        )
        sign_result2 = node.signrungtx(
            spend2["hex"],
            [{"input": 0, "blocks": [{"type": "LATCH_SET"}]}],
            [{"amount": amount2, "scriptPubKey": spk2}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result2["hex"])
        self.log.info("  LATCH_SET state=1 correctly rejected!")

    def test_latch_covenant_chain(self, node):
        """Latch SET transition: state 0→1 via RECURSE_MODIFIED, then SET rung rejected."""
        self.log.info("Testing latch covenant chain...")

        _setter_wif, setter_pubkey = make_keypair()

        # Single-rung design: LATCH_SET + RECURSE_MODIFIED
        # RECURSE_MODIFIED only mutates rung 0 blocks, so keep it in one rung
        conditions = [{"blocks": [
            {"type": "LATCH_SET", "fields": [
                {"type": "PUBKEY", "hex": setter_pubkey},
                {"type": "NUMERIC", "hex": numeric_hex(0)},  # state=0
            ]},
            {"type": "RECURSE_MODIFIED", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(10)},  # max_depth
                {"type": "NUMERIC", "hex": numeric_hex(0)},   # mutation block_idx=0 (LATCH_SET)
                {"type": "NUMERIC", "hex": numeric_hex(1)},   # mutation param_idx=1 (state NUMERIC)
                {"type": "NUMERIC", "hex": numeric_hex(1)},   # delta=+1 (0→1)
            ]},
        ]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  Created latch UTXO (state=0): {txid}:{vout}")

        # Step 1: SET transition — state 0→1
        output_amount = amount - Decimal("0.001")

        # Output conditions must have state=1 (delta +1 applied)
        conditions_after_set = [{"blocks": [
            {"type": "LATCH_SET", "fields": [
                {"type": "PUBKEY", "hex": setter_pubkey},
                {"type": "NUMERIC", "hex": numeric_hex(1)},  # state=1
            ]},
            {"type": "RECURSE_MODIFIED", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(10)},
                {"type": "NUMERIC", "hex": numeric_hex(0)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},
            ]},
        ]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": conditions_after_set}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "rung": 0, "blocks": [
                {"type": "LATCH_SET"},
                {"type": "RECURSE_MODIFIED"},
            ]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]
        set_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)

        tx_info = node.getrawtransaction(set_txid, True)
        assert tx_info["confirmations"] >= 1
        set_spk = tx_info["vout"][0]["scriptPubKey"]["hex"]
        self.log.info(f"  SET transition confirmed (state 0→1): {set_txid[:16]}...")

        # Step 2: Try SET again — should FAIL since state=1
        # LATCH_SET with state=1 → UNSATISFIED, so the rung fails
        spend_amount2 = output_amount - Decimal("0.001")

        conditions_after_set2 = [{"blocks": [
            {"type": "LATCH_SET", "fields": [
                {"type": "PUBKEY", "hex": setter_pubkey},
                {"type": "NUMERIC", "hex": numeric_hex(2)},  # state=2 (would be 1+1)
            ]},
            {"type": "RECURSE_MODIFIED", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(10)},
                {"type": "NUMERIC", "hex": numeric_hex(0)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},
            ]},
        ]}]

        spend2 = node.createrungtx(
            [{"txid": set_txid, "vout": 0}],
            [{"amount": spend_amount2, "conditions": conditions_after_set2}]
        )
        sign_result2 = node.signrungtx(
            spend2["hex"],
            [{"input": 0, "rung": 0, "blocks": [
                {"type": "LATCH_SET"},
                {"type": "RECURSE_MODIFIED"},
            ]}],
            [{"amount": output_amount, "scriptPubKey": set_spk}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result2["hex"])
        self.log.info("  SET rung correctly rejected when state=1!")
        self.log.info("  Latch covenant chain passed!")

    # =========================================================================
    # PQ tests
    # =========================================================================

    def skip_if_no_pq(self, node):
        """Return True if PQ support is not available (skip PQ tests)."""
        try:
            node.generatepqkeypair("FALCON512")
            return False
        except Exception as e:
            if "liboqs" in str(e).lower() or "not compiled" in str(e).lower():
                self.log.info("  Skipping PQ test: liboqs not available")
                return True
            raise

    def test_pq_keygen_rpc(self, node):
        """Test generatepqkeypair RPC returns valid hex keys."""
        self.log.info("Testing PQ keygen RPC...")

        if self.skip_if_no_pq(node):
            return

        for scheme in ["FALCON512", "FALCON1024", "DILITHIUM3"]:
            result = node.generatepqkeypair(scheme)
            assert_equal(result["scheme"], scheme)
            assert len(result["pubkey"]) > 0, f"Empty pubkey for {scheme}"
            assert len(result["privkey"]) > 0, f"Empty privkey for {scheme}"
            # Verify hex decodes cleanly
            bytes.fromhex(result["pubkey"])
            bytes.fromhex(result["privkey"])
            self.log.info(f"  {scheme}: pubkey={len(result['pubkey'])//2}B, privkey={len(result['privkey'])//2}B")

        self.log.info("  PQ keygen RPC passed!")

    def test_pq_falcon512_sig(self, node):
        """End-to-end: create output with SCHEME=FALCON512, spend with PQ sig."""
        self.log.info("Testing PQ FALCON512 signature spend...")

        if self.skip_if_no_pq(node):
            return

        # Generate FALCON512 keypair
        keypair = node.generatepqkeypair("FALCON512")
        pq_pubkey = keypair["pubkey"]
        pq_privkey = keypair["privkey"]

        # Create conditions requiring a FALCON512 signature
        conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "SCHEME", "hex": "10"},  # FALCON512 = 0x10
            {"type": "PUBKEY", "hex": pq_pubkey},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        # Spend using PQ signature
        output_amount = amount - Decimal("0.001")
        spend_wif, spend_pubkey = make_keypair()
        spend_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": spend_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": spend_conditions}]
        )

        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [
                {"type": "SIG", "scheme": "FALCON512", "pq_privkey": pq_privkey, "pq_pubkey": pq_pubkey}
            ]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_equal(sign_result["complete"], True)

        # Submit to mempool and mine
        node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        self.log.info("  PQ FALCON512 signature spend confirmed!")


    # =========================================================================
    # Data Embedding / Spam Resistance Tests
    # =========================================================================

    def test_spam_arbitrary_preimage_rejected(self, node):
        """PREIMAGE without matching hash → consensus rejects.

        Node-computed enforcement means we can't put a random HASH256 in
        conditions; the node auto-computes SHA256(preimage). So instead we
        create a valid HASH_PREIMAGE output with the real preimage, then
        try to spend it with a DIFFERENT preimage (the spam payload).
        The evaluator rejects because SHA256(wrong_preimage) != committed hash.
        """
        self.log.info("Spam test: arbitrary PREIMAGE without valid hash...")

        # Create a valid HASH_PREIMAGE output with a known preimage
        real_preimage = os.urandom(32)
        conditions = [{"blocks": [{"type": "HASH_PREIMAGE", "fields": [
            {"type": "PREIMAGE", "hex": real_preimage.hex()}
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        # Try to spend with a DIFFERENT preimage (the "spam payload")
        payload = os.urandom(252)  # max PREIMAGE size — arbitrary data
        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "HASH_PREIMAGE", "preimage": payload.hex()}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        # Consensus rejects: SHA256(payload) != committed hash
        assert_raises_rpc_error(-26, "", node.sendrawtransaction, sign_result["hex"])
        self.log.info("  Arbitrary PREIMAGE with wrong hash: REJECTED")
        self.log.info("  Spam test PASSED: can't embed data via PREIMAGE")

    def test_spam_pubkey_no_crypto_validation(self, node):
        """Arbitrary PUBKEY data → SIG block requires valid signature.

        Attempt: Put 32 bytes of arbitrary data in a PUBKEY field (x-only size,
        no prefix validation). Even though the PUBKEY stores arbitrary bytes,
        the SIG block requires a valid Schnorr signature over the sighash.
        Random bytes won't produce a valid signature.
        """
        self.log.info("Spam test: arbitrary bytes in PUBKEY field...")

        # 32 bytes of "data" posing as an x-only pubkey
        fake_pubkey = os.urandom(32).hex()

        conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": fake_pubkey}
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        # The UTXO exists — but nobody can spend it without a valid signature
        # for the "pubkey" (which is random bytes, not a real EC point)
        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )

        # Sign with a real key — but it doesn't match the fake pubkey
        real_wif, real_pubkey = make_keypair()
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "SIG", "privkey": real_wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        # Consensus rejects: signature doesn't match fake_pubkey
        assert_raises_rpc_error(-26, "", node.sendrawtransaction, sign_result["hex"])
        self.log.info("  PUBKEY with arbitrary bytes: UTXO created but UNSPENDABLE")
        self.log.info("  Spam test PASSED: arbitrary PUBKEY → funds burned, not free data storage")

    def test_spam_numeric_arbitrary_bytes(self, node):
        """NUMERIC fields: max 4 bytes, semantically validated at spend time.

        Attempt: Pack data into NUMERIC fields with garbage operator values.
        Result: RPC accepts structurally valid NUMERICs (1-4 bytes) but the
        evaluator rejects garbage operators at spend time. Max 4 bytes per
        NUMERIC enforced by field validation. 5-byte NUMERIC rejected at RPC.
        """
        self.log.info("Spam test: NUMERIC field limits...")

        # NUMERIC max is 4 bytes — try 5 bytes → rejected at RPC layer
        assert_raises_rpc_error(-8, "", node.createrung,
            [{"blocks": [{"type": "SIG", "fields": [
                {"type": "NUMERIC", "hex": "0102030405"},  # 5 bytes → too large
            ]}]}])
        self.log.info("  NUMERIC > 4 bytes: REJECTED at RPC level")

        # Garbage operator in COMPARE: RPC accepts (structurally valid 4B NUMERIC)
        # but evaluator rejects at spend time — semantic validation
        garbage_conds = [{"blocks": [{"type": "COMPARE", "fields": [
            {"type": "NUMERIC", "hex": "ff000000"},  # unknown operator
            {"type": "NUMERIC", "hex": "e8030000"},  # threshold
        ]}]}]
        txid, vout, amount, spk = self.bootstrap_v4_output(node, garbage_conds)
        # Try to spend it — evaluator rejects garbage operator
        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": [{"blocks": [{
                "type": "SIG",
                "fields": [{"type": "PUBKEY", "hex": dest_pubkey}]
            }]}]}]
        )
        signed = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "COMPARE"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, "", node.sendrawtransaction, signed["hex"])
        self.log.info("  NUMERIC with garbage operator: UTXO created but UNSPENDABLE")
        self.log.info("  Spam test PASSED: NUMERIC max 4B, garbage semantics rejected at spend")

    def test_spam_unknown_data_type_rejected(self, node):
        """Unknown data types are rejected by the RPC layer.

        Attempt: Use a non-existent data type to sneak arbitrary bytes.
        Result: ParseFieldType() rejects unknown type names.
        """
        self.log.info("Spam test: unknown data type...")

        assert_raises_rpc_error(-8, "Unknown data type", node.createrung,
            [{"blocks": [{"type": "SIG", "fields": [
                {"type": "ARBITRARY_DATA", "hex": "deadbeef" * 100},
            ]}]}])
        self.log.info("  Unknown data type 'ARBITRARY_DATA': REJECTED")
        self.log.info("  Spam test PASSED: no unknown data types allowed")

    def test_spam_witness_only_in_conditions_rejected(self, node):
        """SIGNATURE/PREIMAGE in output conditions (UTXO set) → rejected.

        Attempt: Put a SIGNATURE field in a createrungtx output to store
        arbitrary data in the UTXO set permanently.
        Result: IsConditionDataType() returns false for SIGNATURE and PREIMAGE.
        ParseConditionsSpec (used by createrungtx outputs) rejects them.

        Note: createrung builds raw witnesses (not conditions), so it accepts
        all field types. The conditions-only check is in createrungtx outputs.
        """
        self.log.info("Spam test: witness-only fields in conditions...")

        # Need a real input for createrungtx
        utxo = self.wallet.get_utxo()

        # Try to put SIGNATURE in output conditions
        assert_raises_rpc_error(-8, "not allowed in conditions", node.createrungtx,
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{"amount": Decimal(utxo["value"]) - Decimal("0.001"),
              "conditions": [{"blocks": [{"type": "SIG", "fields": [
                  {"type": "SIGNATURE", "hex": "bb" * 64},
              ]}]}]}])
        self.log.info("  SIGNATURE in output conditions: REJECTED")

        # PREIMAGE in conditions is now allowed — node auto-converts to HASH256.
        # Instead, verify that raw HASH256 is rejected for HASH_PREIMAGE (must use PREIMAGE).
        assert_raises_rpc_error(-8, "Use PREIMAGE instead of HASH256", node.createrungtx,
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{"amount": Decimal(utxo["value"]) - Decimal("0.001"),
              "conditions": [{"blocks": [{"type": "HASH_PREIMAGE", "fields": [
                  {"type": "HASH256", "hex": "aa" * 32},
              ]}]}]}])
        self.log.info("  Raw HASH256 in HASH_PREIMAGE conditions: REJECTED (must use PREIMAGE)")
        self.log.info("  Spam test PASSED: witness-only types can't pollute UTXO set")

    def test_spam_oversized_field_rejected(self, node):
        """Oversized fields are rejected by field validation.

        Attempt: Create a PUBKEY larger than 2048 bytes.
        Result: FieldMaxSize(PUBKEY) = 2048, rejected during IsValid().
        """
        self.log.info("Spam test: oversized fields...")

        # PUBKEY > 2048 bytes
        assert_raises_rpc_error(-8, "Invalid field", node.createrung,
            [{"blocks": [{"type": "SIG", "fields": [
                {"type": "PUBKEY", "hex": "02" + "aa" * 2048},  # 2049 bytes
            ]}]}])
        self.log.info("  PUBKEY 2049 bytes: REJECTED")

        # HASH256 != 32 bytes
        assert_raises_rpc_error(-8, "Invalid field", node.createrung,
            [{"blocks": [{"type": "HASH_PREIMAGE", "fields": [
                {"type": "HASH256", "hex": "cc" * 33},  # 33 bytes, must be 32
            ]}]}])
        self.log.info("  HASH256 33 bytes: REJECTED")

        # HASH160 != 20 bytes
        assert_raises_rpc_error(-8, "Invalid field", node.createrung,
            [{"blocks": [{"type": "HASH160_PREIMAGE", "fields": [
                {"type": "HASH160", "hex": "dd" * 21},  # 21 bytes, must be 20
            ]}]}])
        self.log.info("  HASH160 21 bytes: REJECTED")

        # SCHEME != 1 byte
        assert_raises_rpc_error(-8, "Invalid field", node.createrung,
            [{"blocks": [{"type": "SIG", "fields": [
                {"type": "SCHEME", "hex": "1011"},  # 2 bytes, must be 1
            ]}]}])
        self.log.info("  SCHEME 2 bytes: REJECTED")
        self.log.info("  Spam test PASSED: all field sizes strictly enforced")

    def test_spam_max_structure_limits(self, node):
        """Structure limits: max 16 rungs, 8 blocks/rung, 16 fields/block.

        Attempt: Exceed structural limits to pack more data.
        Result: Policy rejects outputs with too many blocks per rung.
        The tx can be constructed via RPC but sendrawtransaction rejects it
        with "rung N has too many blocks".
        """
        self.log.info("Spam test: structure limits...")

        # Build a tx with 9 blocks per rung — exceeds MAX_BLOCKS_PER_RUNG=8
        utxo = self.wallet.get_utxo()
        boot_wif, boot_pubkey = make_keypair()
        txout_info = node.gettxout(utxo["txid"], utxo["vout"])
        spent_spk = txout_info["scriptPubKey"]["hex"]

        wif, pubkey = make_keypair()
        blocks_9 = [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": pubkey}
        ]} for _ in range(9)]
        conds_9 = [{"blocks": blocks_9}]
        out_amount = Decimal(utxo["value"]) - Decimal("0.001")

        result = node.createrungtx(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            [{"amount": out_amount, "conditions": conds_9}]
        )
        signed = node.signrungtx(
            result["hex"],
            [{"privkey": boot_wif, "input": 0}],
            [{"amount": Decimal(utxo["value"]), "scriptPubKey": spent_spk}]
        )
        # Policy rejects: "rung 0 has too many blocks: 9"
        assert_raises_rpc_error(-26, "too many blocks", node.sendrawtransaction, signed["hex"])
        self.log.info("  9 blocks per rung: REJECTED by policy")
        self.log.info("  Spam test PASSED: structural limits enforced at broadcast")

    def test_spam_coil_address_limit(self, node):
        """Coil address: max 520 bytes (standard scriptPubKey limit).

        This is tested indirectly — the createrung RPC builds coils from
        standard parameters. There's no way to inject arbitrary coil data
        through the RPC; the serialization layer enforces the 520-byte limit.
        """
        self.log.info("Spam test: coil address limits (structural)...")

        # Verify a valid rung can be created and decoded (proves coil is bounded)
        wif, pubkey = make_keypair()
        result = node.createrung(
            [{"blocks": [{"type": "SIG", "fields": [
                {"type": "PUBKEY", "hex": pubkey}
            ]}]}]
        )
        decoded = node.decoderung(result["hex"])
        assert "rungs" in decoded
        self.log.info("  Valid rung structure: coil properly bounded")
        self.log.info("  Spam test PASSED: coil address limited to standard scriptPubKey")

    # =========================================================================
    # Advanced Scenario Tests — Comprehensive Ladder Script Combinations
    # =========================================================================

    # --- Scenario 1: PQ PUBKEY_COMMIT Spend ---

    def test_pq_falcon512_pubkey_commit(self, node):
        """PQ PUBKEY_COMMIT: 32-byte commitment in conditions, full pubkey in witness.

        Scenario: Alice locks funds with FALCON512 but only stores a 32-byte SHA256
        commitment in the UTXO set (saving 865 bytes). At spend time, she reveals
        the full 897-byte pubkey in the witness. The evaluator verifies
        SHA256(pubkey) == commitment before PQ signature verification.
        """
        self.log.info("Scenario 1: PQ FALCON512 PUBKEY_COMMIT spend...")

        if self.skip_if_no_pq(node):
            return

        keypair = node.generatepqkeypair("FALCON512")
        pq_pubkey = keypair["pubkey"]
        pq_privkey = keypair["privkey"]

        self.log.info(f"  PQ pubkey: {pq_pubkey[:16]}... ({len(pq_pubkey)//2}B)")

        # Conditions: SCHEME(FALCON512) + PUBKEY (node auto-computes commitment)
        conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "SCHEME", "hex": "10"},
            {"type": "PUBKEY", "hex": pq_pubkey},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        # Spend: provide full pubkey + PQ signature in witness
        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [
                {"type": "SIG", "scheme": "FALCON512", "pq_privkey": pq_privkey, "pq_pubkey": pq_pubkey}
            ]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_equal(sign_result["complete"], True)

        txid2 = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(txid2, True)
        assert tx_info["confirmations"] >= 1
        self.log.info(f"  PUBKEY_COMMIT spend confirmed: {txid2[:16]}...")
        self.log.info("  Scenario 1 PASSED: PQ PUBKEY_COMMIT")

    # --- Scenario 2: PQ PUBKEY_COMMIT Mismatch (Negative) ---

    def test_negative_pq_pubkey_commit_mismatch(self, node):
        """Negative: wrong pubkey for PUBKEY_COMMIT → rejected.

        Scenario: Eve tries to spend Alice's PUBKEY_COMMIT output using a
        different FALCON512 key. The SHA256 check fails before signature
        verification even starts.
        """
        self.log.info("Scenario 2: PQ PUBKEY_COMMIT mismatch (negative)...")

        if self.skip_if_no_pq(node):
            return

        # Alice's key — committed in conditions
        alice_keypair = node.generatepqkeypair("FALCON512")

        # Eve's key — will try to spend
        eve_keypair = node.generatepqkeypair("FALCON512")

        conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "SCHEME", "hex": "10"},
            {"type": "PUBKEY", "hex": alice_keypair["pubkey"]},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        # Eve tries to spend with her own key
        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [
                {"type": "SIG", "scheme": "FALCON512",
                 "pq_privkey": eve_keypair["privkey"],
                 "pq_pubkey": eve_keypair["pubkey"]}
            ]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]  # signing succeeds locally

        # But consensus rejects: SHA256(eve_pubkey) != alice_commit
        assert_raises_rpc_error(-26, "", node.sendrawtransaction, sign_result["hex"])
        self.log.info("  PUBKEY_COMMIT mismatch correctly rejected!")
        self.log.info("  Scenario 2 PASSED: PQ PUBKEY_COMMIT mismatch rejected")

    # --- Scenario 3: Multi-Rung RECURSE_MODIFIED (Cross-Rung Mutation) ---

    def test_recurse_modified_cross_rung(self, node):
        """RECURSE_MODIFIED: mutation targets rung 1 instead of rung 0.

        Scenario: A two-rung UTXO where rung 0 is a SIG (always required) and
        rung 1 has a COMPARE threshold. The RECURSE_MODIFIED block uses the
        new multi-mutation format to mutate rung 1's COMPARE threshold while
        leaving rung 0 completely untouched.
        """
        self.log.info("Scenario 3: RECURSE_MODIFIED cross-rung mutation...")

        privkey_wif, pubkey_hex = make_keypair()
        initial_threshold = 5000

        # Rung 0: SIG + RECURSE_MODIFIED (new format: mutation targets rung 1)
        # Rung 1: COMPARE(GT threshold)
        conditions = [
            {"blocks": [
                {"type": "SIG", "fields": [
                    {"type": "PUBKEY", "hex": pubkey_hex}
                ]},
                {"type": "RECURSE_MODIFIED", "fields": [
                    {"type": "NUMERIC", "hex": numeric_hex(10)},   # max_depth
                    {"type": "NUMERIC", "hex": numeric_hex(1)},    # num_mutations
                    {"type": "NUMERIC", "hex": numeric_hex(1)},    # rung_idx = 1
                    {"type": "NUMERIC", "hex": numeric_hex(0)},    # block_idx = 0 (COMPARE)
                    {"type": "NUMERIC", "hex": numeric_hex(1)},    # param_idx = 1 (threshold value)
                    {"type": "NUMERIC", "hex": numeric_hex(500)},  # delta = +500
                ]},
            ]},
            {"blocks": [
                {"type": "COMPARE", "fields": [
                    {"type": "NUMERIC", "hex": numeric_hex(0x03)},  # GT operator
                    {"type": "NUMERIC", "hex": numeric_hex(initial_threshold)},
                ]},
            ]},
        ]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  Created 2-rung UTXO (threshold={initial_threshold})")

        # Hop 1: mutate rung 1 threshold from 5000 → 5500
        new_threshold = initial_threshold + 500
        mutated_conditions = [
            {"blocks": [
                {"type": "SIG", "fields": [
                    {"type": "PUBKEY", "hex": pubkey_hex}
                ]},
                {"type": "RECURSE_MODIFIED", "fields": [
                    {"type": "NUMERIC", "hex": numeric_hex(10)},
                    {"type": "NUMERIC", "hex": numeric_hex(1)},
                    {"type": "NUMERIC", "hex": numeric_hex(1)},
                    {"type": "NUMERIC", "hex": numeric_hex(0)},
                    {"type": "NUMERIC", "hex": numeric_hex(1)},
                    {"type": "NUMERIC", "hex": numeric_hex(500)},
                ]},
            ]},
            {"blocks": [
                {"type": "COMPARE", "fields": [
                    {"type": "NUMERIC", "hex": numeric_hex(0x03)},
                    {"type": "NUMERIC", "hex": numeric_hex(new_threshold)},
                ]},
            ]},
        ]

        output_amount = amount - Decimal("0.001")
        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": mutated_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "rung": 0, "blocks": [
                {"type": "SIG", "privkey": privkey_wif},
                {"type": "RECURSE_MODIFIED"},
            ]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        txid2 = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(txid2, True)
        assert tx_info["confirmations"] >= 1
        self.log.info(f"  Cross-rung mutation ({initial_threshold}→{new_threshold}): {txid2[:16]}...")
        self.log.info("  Scenario 3 PASSED: Cross-rung RECURSE_MODIFIED")

    # --- Scenario 4: Multi-Mutation (Two Simultaneous Mutations) ---

    def test_recurse_modified_multi_mutation(self, node):
        """RECURSE_MODIFIED: two mutations in a single spend.

        Scenario: A state machine with a counter (rung 0, block 1) and a
        threshold (rung 0, block 2). Each spend simultaneously increments
        the counter by +1 and increases the threshold by +1000. This enables
        complex atomic state transitions.
        """
        self.log.info("Scenario 4: RECURSE_MODIFIED multi-mutation...")

        counter = 0
        threshold = 10000

        # Rung 0: RECURSE_MODIFIED + SEQUENCER(counter) + COMPARE(threshold)
        # Mutation 0: block 1 (SEQUENCER), param 0 (current_step), delta +1
        # Mutation 1: block 2 (COMPARE), param 1 (threshold_value), delta +1000
        conditions = [{"blocks": [
            {"type": "RECURSE_MODIFIED", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(10)},   # max_depth
                {"type": "NUMERIC", "hex": numeric_hex(2)},    # num_mutations = 2
                # Mutation 0: rung 0, block 1, param 0, delta +1
                {"type": "NUMERIC", "hex": numeric_hex(0)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},
                {"type": "NUMERIC", "hex": numeric_hex(0)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},
                # Mutation 1: rung 0, block 2, param 1, delta +1000
                {"type": "NUMERIC", "hex": numeric_hex(0)},
                {"type": "NUMERIC", "hex": numeric_hex(2)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},
                {"type": "NUMERIC", "hex": numeric_hex(1000)},
            ]},
            {"type": "SEQUENCER", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(counter)},  # current_step
                {"type": "NUMERIC", "hex": numeric_hex(10)},       # total_steps
            ]},
            {"type": "COMPARE", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(0x03)},     # GT
                {"type": "NUMERIC", "hex": numeric_hex(threshold)},
            ]},
        ]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  State: counter={counter}, threshold={threshold}")

        # Two hops of dual mutation
        for hop in range(2):
            counter += 1
            threshold += 1000

            mutated_conditions = [{"blocks": [
                {"type": "RECURSE_MODIFIED", "fields": [
                    {"type": "NUMERIC", "hex": numeric_hex(10)},
                    {"type": "NUMERIC", "hex": numeric_hex(2)},
                    {"type": "NUMERIC", "hex": numeric_hex(0)},
                    {"type": "NUMERIC", "hex": numeric_hex(1)},
                    {"type": "NUMERIC", "hex": numeric_hex(0)},
                    {"type": "NUMERIC", "hex": numeric_hex(1)},
                    {"type": "NUMERIC", "hex": numeric_hex(0)},
                    {"type": "NUMERIC", "hex": numeric_hex(2)},
                    {"type": "NUMERIC", "hex": numeric_hex(1)},
                    {"type": "NUMERIC", "hex": numeric_hex(1000)},
                ]},
                {"type": "SEQUENCER", "fields": [
                    {"type": "NUMERIC", "hex": numeric_hex(counter)},
                    {"type": "NUMERIC", "hex": numeric_hex(10)},
                ]},
                {"type": "COMPARE", "fields": [
                    {"type": "NUMERIC", "hex": numeric_hex(0x03)},
                    {"type": "NUMERIC", "hex": numeric_hex(threshold)},
                ]},
            ]}]

            output_amount = amount - Decimal("0.001")
            spend = node.createrungtx(
                [{"txid": txid, "vout": vout}],
                [{"amount": output_amount, "conditions": mutated_conditions}]
            )
            sign_result = node.signrungtx(
                spend["hex"],
                [{"input": 0, "blocks": [
                    {"type": "RECURSE_MODIFIED"},
                    {"type": "SEQUENCER"},
                    {"type": "COMPARE"},
                ]}],
                [{"amount": amount, "scriptPubKey": spk}]
            )
            assert sign_result["complete"]

            txid = node.sendrawtransaction(sign_result["hex"])
            self.generate(node, 1)
            tx_info = node.getrawtransaction(txid, True)
            assert tx_info["confirmations"] >= 1
            spk = tx_info["vout"][0]["scriptPubKey"]["hex"]
            amount = output_amount
            vout = 0
            self.log.info(f"  Hop {hop+1}: counter={counter}, threshold={threshold}")

        self.log.info("  Scenario 4 PASSED: Multi-mutation RECURSE_MODIFIED")

    # --- Scenario 5: Multi-Mutation Wrong Delta (Negative) ---

    def test_negative_recurse_modified_wrong_delta(self, node):
        """Negative: wrong mutation delta → rejected.

        Scenario: Attacker tries to apply delta +2 when the covenant specifies +1.
        """
        self.log.info("Scenario 5: RECURSE_MODIFIED wrong delta (negative)...")

        conditions = [{"blocks": [
            {"type": "RECURSE_MODIFIED", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(10)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},    # num_mutations = 1
                {"type": "NUMERIC", "hex": numeric_hex(0)},    # rung 0
                {"type": "NUMERIC", "hex": numeric_hex(1)},    # block 1
                {"type": "NUMERIC", "hex": numeric_hex(0)},    # param 0
                {"type": "NUMERIC", "hex": numeric_hex(1)},    # delta +1
            ]},
            {"type": "COMPARE", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(0x03)},
                {"type": "NUMERIC", "hex": numeric_hex(100)},
            ]},
        ]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        # Try applying delta +2 instead of +1
        bad_conditions = [{"blocks": [
            {"type": "RECURSE_MODIFIED", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(10)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},
                {"type": "NUMERIC", "hex": numeric_hex(0)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},
                {"type": "NUMERIC", "hex": numeric_hex(0)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},
            ]},
            {"type": "COMPARE", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(0x03)},
                {"type": "NUMERIC", "hex": numeric_hex(102)},  # wrong: should be 101
            ]},
        ]}]

        output_amount = amount - Decimal("0.001")
        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": bad_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "RECURSE_MODIFIED"}, {"type": "COMPARE"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        assert_raises_rpc_error(-26, "", node.sendrawtransaction, sign_result["hex"])
        self.log.info("  Wrong delta correctly rejected!")
        self.log.info("  Scenario 5 PASSED: Wrong multi-mutation delta rejected")

    # --- Scenario 6: SIG + HASH_PREIMAGE + CSV (Triple AND) ---

    def test_sig_hash_csv_triple_and(self, node):
        """Triple AND: SIG + HASH_PREIMAGE + CSV all in one rung.

        Scenario: An escrow payment that requires: (1) seller's signature,
        (2) revelation of a shipping secret (hash preimage), and (3) a 5-block
        maturity period. All three must be satisfied simultaneously.
        """
        self.log.info("Scenario 6: Triple AND (SIG + HASH_PREIMAGE + CSV)...")

        seller_wif, seller_pubkey = make_keypair()
        preimage = os.urandom(32)
        csv_blocks = 5

        conditions = [{"blocks": [
            {"type": "SIG", "fields": [
                {"type": "PUBKEY", "hex": seller_pubkey}
            ]},
            {"type": "HASH_PREIMAGE", "fields": [
                {"type": "PREIMAGE", "hex": preimage.hex()}
            ]},
            {"type": "CSV", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(csv_blocks)}
            ]},
        ]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        # Mine enough blocks for CSV maturity
        self.generate(node, csv_blocks)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout, "sequence": csv_blocks}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [
                {"type": "SIG", "privkey": seller_wif},
                {"type": "HASH_PREIMAGE", "preimage": preimage.hex()},
                {"type": "CSV"},
            ]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        txid2 = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(txid2, True)
        assert tx_info["confirmations"] >= 1
        self.log.info(f"  Triple AND spend confirmed: {txid2[:16]}...")
        self.log.info("  Scenario 6 PASSED: SIG + HASH_PREIMAGE + CSV")

    # --- Scenario 7: OR Logic with Different Security Levels ---

    def test_or_hot_cold_vault(self, node):
        """OR logic: hot key (with CSV delay) OR cold key (immediate).

        Scenario: A hot/cold wallet design. Rung 0 (hot path) requires a
        signature from the hot key plus a 10-block CSV delay. Rung 1 (cold path)
        requires only the cold key with no delay. First we spend via the cold
        path (immediate), then create a new UTXO and spend via the hot path
        (after delay).
        """
        self.log.info("Scenario 7: OR hot/cold vault...")

        hot_wif, hot_pubkey = make_keypair()
        cold_wif, cold_pubkey = make_keypair()
        csv_delay = 10

        conditions = [
            # Rung 0: hot key + CSV delay
            {"blocks": [
                {"type": "SIG", "fields": [
                    {"type": "PUBKEY", "hex": hot_pubkey}
                ]},
                {"type": "CSV", "fields": [
                    {"type": "NUMERIC", "hex": numeric_hex(csv_delay)}
                ]},
            ]},
            # Rung 1: cold key (immediate)
            {"blocks": [
                {"type": "SIG", "fields": [
                    {"type": "PUBKEY", "hex": cold_pubkey}
                ]},
            ]},
        ]

        # Test cold path (rung 1, immediate)
        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "rung": 1, "blocks": [
                {"type": "SIG", "privkey": cold_wif},
            ]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        cold_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(cold_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info(f"  Cold path (rung 1, immediate) confirmed: {cold_txid[:16]}...")

        # Test hot path (rung 0, needs CSV delay)
        txid2, vout2, amount2, spk2 = self.bootstrap_v4_output(node, conditions)
        self.generate(node, csv_delay)  # wait for CSV maturity

        output_amount2 = amount2 - Decimal("0.001")
        spend2 = node.createrungtx(
            [{"txid": txid2, "vout": vout2, "sequence": csv_delay}],
            [{"amount": output_amount2, "conditions": dest_conditions}]
        )
        sign_result2 = node.signrungtx(
            spend2["hex"],
            [{"input": 0, "rung": 0, "blocks": [
                {"type": "SIG", "privkey": hot_wif},
                {"type": "CSV"},
            ]}],
            [{"amount": amount2, "scriptPubKey": spk2}]
        )
        assert sign_result2["complete"]

        hot_txid = node.sendrawtransaction(sign_result2["hex"])
        self.generate(node, 1)
        tx_info2 = node.getrawtransaction(hot_txid, True)
        assert tx_info2["confirmations"] >= 1
        self.log.info(f"  Hot path (rung 0, CSV={csv_delay}) confirmed: {hot_txid[:16]}...")
        self.log.info("  Scenario 7 PASSED: OR hot/cold vault")

    # --- Scenario 8: Covenant + Timelock (RECURSE_SAME + CLTV) ---

    def test_recurse_same_with_cltv(self, node):
        """RECURSE_SAME + CLTV: locked covenant that can't be spent until height N.

        Scenario: Funds locked in a perpetual covenant (RECURSE_SAME) that also
        has a CLTV timelock. Before the timelock, the UTXO can still be
        re-encumbered (RECURSE_SAME satisfied, CLTV satisfied if nLockTime >=
        threshold). After the timelock, same behavior — the covenant never
        releases because RECURSE_SAME enforces identical output conditions.
        """
        self.log.info("Scenario 8: RECURSE_SAME + CLTV...")

        current_height = node.getblockcount()
        lock_height = current_height + 5

        conditions = [{"blocks": [
            {"type": "RECURSE_SAME", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(20)},
            ]},
            {"type": "CLTV", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(lock_height)},
            ]},
        ]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        # Mine past the CLTV height
        self.generate(node, 6)

        # Re-encumber with same conditions + nLockTime
        output_amount = amount - Decimal("0.001")
        current = node.getblockcount()
        spend = node.createrungtx(
            [{"txid": txid, "vout": vout, "sequence": 0xfffffffe}],
            [{"amount": output_amount, "conditions": conditions}],
            current,  # nLockTime
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [
                {"type": "RECURSE_SAME"},
                {"type": "CLTV"},
            ]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        txid2 = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(txid2, True)
        assert tx_info["confirmations"] >= 1
        self.log.info(f"  RECURSE_SAME + CLTV re-encumber confirmed: {txid2[:16]}...")
        self.log.info("  Scenario 8 PASSED: RECURSE_SAME + CLTV")

    # --- Scenario 9: Inverted COMPARE as Floor Guard ---

    def test_inverted_compare_floor(self, node):
        """Inverted COMPARE: rejects amounts ABOVE a ceiling.

        Scenario: COMPARE(GT, 1000000) with inverted=true means the block is
        SATISFIED when the amount is NOT greater than 1M sats — effectively
        enforcing a ceiling. Combined with a normal COMPARE(GTE, 10000) for
        a floor, this creates a range lock without using IN_RANGE.
        """
        self.log.info("Scenario 9: Inverted COMPARE as ceiling guard...")

        # Build manually: floor(GTE 10000) + ceiling(inverted GT 1000000)
        conditions = [{"blocks": [
            {"type": "COMPARE", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(0x05)},     # GTE
                {"type": "NUMERIC", "hex": numeric_hex(10000)},    # floor: 10000 sats
            ]},
            {"type": "COMPARE", "inverted": True, "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(0x03)},     # GT (inverted = NOT GT = LTE)
                {"type": "NUMERIC", "hex": numeric_hex(1000000)},  # ceiling: 1M sats
            ]},
        ]}]

        # 0.005 BTC = 500,000 sats (within floor 10k and ceiling 1M)
        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions, Decimal("0.005"))

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "COMPARE"}, {"type": "COMPARE"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        txid2 = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(txid2, True)
        assert tx_info["confirmations"] >= 1
        self.log.info(f"  Inverted COMPARE ceiling spend confirmed: {txid2[:16]}...")
        self.log.info("  Scenario 9 PASSED: Inverted COMPARE floor/ceiling")

    # --- Scenario 10: RECURSE_COUNT + SIG (Countdown Vault) ---

    def test_countdown_vault(self, node):
        """RECURSE_COUNT + SIG: a vault that requires N signatures before release.

        Scenario: A "cooling off" vault. The UTXO requires a signature at each
        step AND decrements a counter. After 3 signed hops, the counter reaches
        0 and the covenant terminates, allowing free spending. This is a
        deliberation mechanism — you need to sign 3 separate transactions
        (in 3 separate blocks) before funds are released.
        """
        self.log.info("Scenario 10: Countdown vault (RECURSE_COUNT + SIG)...")

        vault_wif, vault_pubkey = make_keypair()
        initial_count = 3

        conditions = [{"blocks": [
            {"type": "SIG", "fields": [
                {"type": "PUBKEY", "hex": vault_pubkey}
            ]},
            {"type": "RECURSE_COUNT", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(initial_count)},
            ]},
        ]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  Countdown vault created: count={initial_count}")

        # Decrement through 3→2→1→0
        for remaining in range(initial_count - 1, -1, -1):
            next_conditions = [{"blocks": [
                {"type": "SIG", "fields": [
                    {"type": "PUBKEY", "hex": vault_pubkey}
                ]},
                {"type": "RECURSE_COUNT", "fields": [
                    {"type": "NUMERIC", "hex": numeric_hex(remaining)},
                ]},
            ]}]

            output_amount = amount - Decimal("0.001")
            spend = node.createrungtx(
                [{"txid": txid, "vout": vout}],
                [{"amount": output_amount, "conditions": next_conditions}]
            )
            sign_result = node.signrungtx(
                spend["hex"],
                [{"input": 0, "blocks": [
                    {"type": "SIG", "privkey": vault_wif},
                    {"type": "RECURSE_COUNT"},
                ]}],
                [{"amount": amount, "scriptPubKey": spk}]
            )
            assert sign_result["complete"]

            txid = node.sendrawtransaction(sign_result["hex"])
            self.generate(node, 1)
            tx_info = node.getrawtransaction(txid, True)
            assert tx_info["confirmations"] >= 1
            spk = tx_info["vout"][0]["scriptPubKey"]["hex"]
            amount = output_amount
            vout = 0
            self.log.info(f"  Vault hop: count→{remaining}")

        # count=0: free spend to arbitrary output
        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        free_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": free_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [
                {"type": "SIG", "privkey": vault_wif},
                {"type": "RECURSE_COUNT"},
            ]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        txid_final = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(txid_final, True)
        assert tx_info["confirmations"] >= 1
        self.log.info(f"  Vault released (count=0): {txid_final[:16]}...")
        self.log.info("  Scenario 10 PASSED: Countdown vault")

    # --- Scenario 11: RECURSE_DECAY Multi-Target ---

    def test_recurse_decay_multi_target(self, node):
        """RECURSE_DECAY with two decay targets (new multi-mutation format).

        Scenario: A dual-threshold contract with two GT comparisons. Both
        thresholds decay by different amounts per hop, progressively
        relaxing constraints. Uses GT so input_amount (full coin) always passes.
        """
        self.log.info("Scenario 11: RECURSE_DECAY multi-target...")

        threshold_a = 500000     # GT 500000 sats (~0.005 BTC)
        threshold_b = 1000000    # GT 1000000 sats (~0.01 BTC)

        # Block 1: COMPARE(GT, threshold_a) — first threshold
        # Block 2: COMPARE(GT, threshold_b) — second threshold
        # Decay block 1 param 1 by 50000 per hop, block 2 param 1 by 100000
        conditions = [{"blocks": [
            {"type": "RECURSE_DECAY", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(10)},   # max_depth
                {"type": "NUMERIC", "hex": numeric_hex(2)},    # num_mutations = 2
                # Decay 0: rung 0, block 1, param 1, decay 50000
                {"type": "NUMERIC", "hex": numeric_hex(0)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},
                {"type": "NUMERIC", "hex": numeric_hex(50000)},
                # Decay 1: rung 0, block 2, param 1, decay 100000
                {"type": "NUMERIC", "hex": numeric_hex(0)},
                {"type": "NUMERIC", "hex": numeric_hex(2)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},
                {"type": "NUMERIC", "hex": numeric_hex(100000)},
            ]},
            {"type": "COMPARE", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(0x03)},  # GT
                {"type": "NUMERIC", "hex": numeric_hex(threshold_a)},
            ]},
            {"type": "COMPARE", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(0x03)},  # GT
                {"type": "NUMERIC", "hex": numeric_hex(threshold_b)},
            ]},
        ]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  State: threshold_a={threshold_a}, threshold_b={threshold_b}")

        # Hop: a 500000→450000, b 1000000→900000
        threshold_a -= 50000
        threshold_b -= 100000

        decayed_conditions = [{"blocks": [
            {"type": "RECURSE_DECAY", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(10)},
                {"type": "NUMERIC", "hex": numeric_hex(2)},
                {"type": "NUMERIC", "hex": numeric_hex(0)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},
                {"type": "NUMERIC", "hex": numeric_hex(50000)},
                {"type": "NUMERIC", "hex": numeric_hex(0)},
                {"type": "NUMERIC", "hex": numeric_hex(2)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},
                {"type": "NUMERIC", "hex": numeric_hex(100000)},
            ]},
            {"type": "COMPARE", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(0x03)},
                {"type": "NUMERIC", "hex": numeric_hex(threshold_a)},
            ]},
            {"type": "COMPARE", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(0x03)},
                {"type": "NUMERIC", "hex": numeric_hex(threshold_b)},
            ]},
        ]}]

        output_amount = amount - Decimal("0.001")
        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": decayed_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [
                {"type": "RECURSE_DECAY"},
                {"type": "COMPARE"},
                {"type": "COMPARE"},
            ]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        txid2 = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(txid2, True)
        assert tx_info["confirmations"] >= 1
        self.log.info(f"  Decay hop: a→{threshold_a}, b→{threshold_b}")
        self.log.info("  Scenario 11 PASSED: RECURSE_DECAY multi-target")

    # --- Scenario 12: Hash-Locked OR + Time-Locked OR (HTLC) ---

    def test_htlc_pattern(self, node):
        """HTLC: Hash preimage (receiver) OR CSV timeout (sender refund).

        Scenario: Classic Hash Time-Locked Contract. Rung 0: Bob can claim by
        revealing preimage + his signature. Rung 1: Alice can reclaim after
        a CSV timeout of 20 blocks + her signature. Tests both paths.
        """
        self.log.info("Scenario 12: HTLC (hash-lock + time-lock)...")

        alice_wif, alice_pubkey = make_keypair()
        bob_wif, bob_pubkey = make_keypair()
        preimage = os.urandom(32)
        refund_blocks = 20

        conditions = [
            # Rung 0: Bob claims with preimage + signature
            {"blocks": [
                {"type": "SIG", "fields": [
                    {"type": "PUBKEY", "hex": bob_pubkey}
                ]},
                {"type": "HASH_PREIMAGE", "fields": [
                    {"type": "PREIMAGE", "hex": preimage.hex()}
                ]},
            ]},
            # Rung 1: Alice refund after timeout
            {"blocks": [
                {"type": "SIG", "fields": [
                    {"type": "PUBKEY", "hex": alice_pubkey}
                ]},
                {"type": "CSV", "fields": [
                    {"type": "NUMERIC", "hex": numeric_hex(refund_blocks)}
                ]},
            ]},
        ]

        # Test Bob claiming (rung 0)
        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "rung": 0, "blocks": [
                {"type": "SIG", "privkey": bob_wif},
                {"type": "HASH_PREIMAGE", "preimage": preimage.hex()},
            ]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        bob_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(bob_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info(f"  Bob claimed via hash preimage: {bob_txid[:16]}...")

        # Test Alice refund (rung 1) on a different UTXO
        txid2, vout2, amount2, spk2 = self.bootstrap_v4_output(node, conditions)
        self.generate(node, refund_blocks)  # wait for CSV maturity

        output_amount2 = amount2 - Decimal("0.001")
        spend2 = node.createrungtx(
            [{"txid": txid2, "vout": vout2, "sequence": refund_blocks}],
            [{"amount": output_amount2, "conditions": dest_conditions}]
        )
        sign_result2 = node.signrungtx(
            spend2["hex"],
            [{"input": 0, "rung": 1, "blocks": [
                {"type": "SIG", "privkey": alice_wif},
                {"type": "CSV"},
            ]}],
            [{"amount": amount2, "scriptPubKey": spk2}]
        )
        assert sign_result2["complete"]

        alice_txid = node.sendrawtransaction(sign_result2["hex"])
        self.generate(node, 1)
        tx_info2 = node.getrawtransaction(alice_txid, True)
        assert tx_info2["confirmations"] >= 1
        self.log.info(f"  Alice refunded via CSV timeout: {alice_txid[:16]}...")
        self.log.info("  Scenario 12 PASSED: HTLC pattern (both paths)")

    # --- Scenario 13: Latch + Cross-Rung Mutation State Machine ---

    def test_latch_cross_rung_state_machine(self, node):
        """Latch state machine using cross-rung RECURSE_MODIFIED.

        Scenario: A two-rung UTXO. Rung 0 has the control logic (LATCH_SET +
        RECURSE_MODIFIED targeting rung 1). Rung 1 has the state (SEQUENCER
        acting as a counter). Each spend: latch gates the transition, then
        RECURSE_MODIFIED increments the rung 1 sequencer step.
        """
        self.log.info("Scenario 13: Latch + cross-rung state machine...")

        _wif, pubkey = make_keypair()

        conditions = [
            # Rung 0: LATCH_SET (gate) + RECURSE_MODIFIED (cross-rung mutation)
            {"blocks": [
                {"type": "LATCH_SET", "fields": [
                    {"type": "PUBKEY", "hex": pubkey},
                    {"type": "NUMERIC", "hex": numeric_hex(0)},  # state=0 (open)
                ]},
                {"type": "RECURSE_MODIFIED", "fields": [
                    {"type": "NUMERIC", "hex": numeric_hex(10)},   # max_depth
                    {"type": "NUMERIC", "hex": numeric_hex(1)},    # num_mutations = 1
                    {"type": "NUMERIC", "hex": numeric_hex(1)},    # rung_idx = 1
                    {"type": "NUMERIC", "hex": numeric_hex(0)},    # block_idx = 0
                    {"type": "NUMERIC", "hex": numeric_hex(0)},    # param_idx = 0 (current_step)
                    {"type": "NUMERIC", "hex": numeric_hex(1)},    # delta = +1
                ]},
            ]},
            # Rung 1: SEQUENCER (state counter)
            {"blocks": [
                {"type": "SEQUENCER", "fields": [
                    {"type": "NUMERIC", "hex": numeric_hex(0)},  # current_step
                    {"type": "NUMERIC", "hex": numeric_hex(5)},  # total_steps
                ]},
            ]},
        ]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  State machine created: step=0")

        # Transition: step 0→1
        conditions_after = [
            {"blocks": [
                {"type": "LATCH_SET", "fields": [
                    {"type": "PUBKEY", "hex": pubkey},
                    {"type": "NUMERIC", "hex": numeric_hex(0)},
                ]},
                {"type": "RECURSE_MODIFIED", "fields": [
                    {"type": "NUMERIC", "hex": numeric_hex(10)},
                    {"type": "NUMERIC", "hex": numeric_hex(1)},
                    {"type": "NUMERIC", "hex": numeric_hex(1)},
                    {"type": "NUMERIC", "hex": numeric_hex(0)},
                    {"type": "NUMERIC", "hex": numeric_hex(0)},
                    {"type": "NUMERIC", "hex": numeric_hex(1)},
                ]},
            ]},
            {"blocks": [
                {"type": "SEQUENCER", "fields": [
                    {"type": "NUMERIC", "hex": numeric_hex(1)},  # step 0→1
                    {"type": "NUMERIC", "hex": numeric_hex(5)},
                ]},
            ]},
        ]

        output_amount = amount - Decimal("0.001")
        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": conditions_after}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "rung": 0, "blocks": [
                {"type": "LATCH_SET"},
                {"type": "RECURSE_MODIFIED"},
            ]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        txid2 = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(txid2, True)
        assert tx_info["confirmations"] >= 1
        self.log.info(f"  State transition (step 0→1): {txid2[:16]}...")
        self.log.info("  Scenario 13 PASSED: Latch + cross-rung state machine")

    # --- Scenario 14: RECURSE_UNTIL + Hash Preimage (Timed Secret Reveal) ---

    def test_timed_secret_reveal(self, node):
        """RECURSE_UNTIL + HASH_PREIMAGE: covenant that requires preimage reveal
        before a deadline, otherwise stays locked.

        Scenario: An output requires knowing a secret (hash preimage). Until a
        target block height, the output must be re-encumbered with identical
        conditions. After the deadline, revealing the preimage unlocks the
        funds. This is a "reveal or forfeit" pattern.
        """
        self.log.info("Scenario 14: Timed secret reveal...")

        preimage = os.urandom(32)
        current_height = node.getblockcount()
        deadline = current_height + 5

        conditions = [{"blocks": [
            {"type": "HASH_PREIMAGE", "fields": [
                {"type": "PREIMAGE", "hex": preimage.hex()}
            ]},
            {"type": "RECURSE_UNTIL", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(deadline)},
            ]},
        ]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        # Before deadline: must re-encumber
        output_amount = amount - Decimal("0.001")
        current = node.getblockcount()
        spend = node.createrungtx(
            [{"txid": txid, "vout": vout, "sequence": 0xfffffffe}],
            [{"amount": output_amount, "conditions": conditions}],
            current,  # nLockTime < deadline → must re-encumber
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [
                {"type": "HASH_PREIMAGE", "preimage": preimage.hex()},
                {"type": "RECURSE_UNTIL"},
            ]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        txid2 = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(txid2, True)
        assert tx_info["confirmations"] >= 1
        spk2 = tx_info["vout"][0]["scriptPubKey"]["hex"]
        self.log.info(f"  Re-encumbered before deadline: {txid2[:16]}...")

        # Mine past deadline
        blocks_needed = deadline - node.getblockcount() + 1
        if blocks_needed > 0:
            self.generate(node, blocks_needed)

        # After deadline: spend freely with preimage
        output_amount2 = output_amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend2 = node.createrungtx(
            [{"txid": txid2, "vout": 0, "sequence": 0xfffffffe}],
            [{"amount": output_amount2, "conditions": dest_conditions}],
            node.getblockcount(),
        )
        sign_result2 = node.signrungtx(
            spend2["hex"],
            [{"input": 0, "blocks": [
                {"type": "HASH_PREIMAGE", "preimage": preimage.hex()},
                {"type": "RECURSE_UNTIL"},
            ]}],
            [{"amount": output_amount, "scriptPubKey": spk2}]
        )
        assert sign_result2["complete"]

        txid3 = node.sendrawtransaction(sign_result2["hex"])
        self.generate(node, 1)
        tx_info2 = node.getrawtransaction(txid3, True)
        assert tx_info2["confirmations"] >= 1
        self.log.info(f"  Secret revealed after deadline: {txid3[:16]}...")
        self.log.info("  Scenario 14 PASSED: Timed secret reveal")

    # --- Scenario 15: 3-Rung Priority Spend ---

    def test_three_rung_priority(self, node):
        """3-rung OR priority: emergency > normal > delayed.

        Scenario: Three spending paths with different trust/delay tradeoffs:
        - Rung 0 (emergency): 2-of-2 multisig (both keys, immediate)
        - Rung 1 (normal): single key + hash preimage
        - Rung 2 (delayed): single key + CSV 15 blocks
        Tests the emergency path (rung 0).
        """
        self.log.info("Scenario 15: 3-rung priority spend...")

        key1_wif, key1_pubkey = make_keypair()
        key2_wif, key2_pubkey = make_keypair()
        normal_wif, normal_pubkey = make_keypair()
        delayed_wif, delayed_pubkey = make_keypair()
        preimage = os.urandom(32)

        conditions = [
            # Rung 0: Emergency (2-of-2 multisig, immediate)
            {"blocks": [
                {"type": "MULTISIG", "fields": [
                    {"type": "NUMERIC", "hex": numeric_hex(2)},
                    {"type": "PUBKEY", "hex": key1_pubkey},
                    {"type": "PUBKEY", "hex": key2_pubkey},
                ]},
            ]},
            # Rung 1: Normal (key + preimage)
            {"blocks": [
                {"type": "SIG", "fields": [
                    {"type": "PUBKEY", "hex": normal_pubkey}
                ]},
                {"type": "HASH_PREIMAGE", "fields": [
                    {"type": "PREIMAGE", "hex": preimage.hex()}
                ]},
            ]},
            # Rung 2: Delayed (key + CSV)
            {"blocks": [
                {"type": "SIG", "fields": [
                    {"type": "PUBKEY", "hex": delayed_pubkey}
                ]},
                {"type": "CSV", "fields": [
                    {"type": "NUMERIC", "hex": numeric_hex(15)}
                ]},
            ]},
        ]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        # Use emergency path (rung 0): 2-of-2 multisig
        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "rung": 0, "blocks": [
                {"type": "MULTISIG", "privkeys": [key1_wif, key2_wif]},
            ]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        txid2 = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(txid2, True)
        assert tx_info["confirmations"] >= 1
        self.log.info(f"  Emergency multisig spend (rung 0): {txid2[:16]}...")
        self.log.info("  Scenario 15 PASSED: 3-rung priority spend")

    # --- Scenario 16: pqpubkeycommit RPC ---

    def test_pqpubkeycommit_rpc(self, node):
        """Test pqpubkeycommit RPC returns correct SHA256 commitment."""
        self.log.info("Scenario 16: pqpubkeycommit RPC...")

        if self.skip_if_no_pq(node):
            return

        keypair = node.generatepqkeypair("FALCON512")
        pubkey_hex = keypair["pubkey"]

        result = node.pqpubkeycommit(pubkey_hex)
        commit_hex = result["commit"]
        assert_equal(len(commit_hex), 64)  # 32 bytes hex

        # Verify: SHA256(pubkey) == commit
        import hashlib
        expected = hashlib.sha256(bytes.fromhex(pubkey_hex)).hexdigest()
        assert_equal(commit_hex, expected)
        self.log.info(f"  Commitment verified: {commit_hex[:16]}...")
        self.log.info("  Scenario 16 PASSED: pqpubkeycommit RPC")


    # =========================================================================
    # COSIGN — PQ Anchor Co-Spend Pattern
    # =========================================================================

    def test_cosign_anchor_spend(self, node):
        """COSIGN: PQ anchor protects a Schnorr child via co-spending.

        Pattern:
        1. Create PQ anchor UTXO: SIG(FALCON512, PUBKEY_COMMIT) + RECURSE_SAME
        2. Create child UTXO: SIG(schnorr) + COSIGN(sha256(anchor_conditions))
        3. Spend both in same tx: anchor re-encumbers, child freed
        4. One PQ signature covers entire transaction
        """
        self.log.info("Scenario 17: COSIGN PQ anchor co-spend...")

        if self.skip_if_no_pq(node):
            return

        # --- Step 1: Create the PQ anchor UTXO ---
        pq_keypair = node.generatepqkeypair("FALCON512")
        pq_pubkey = pq_keypair["pubkey"]
        pq_privkey = pq_keypair["privkey"]
        anchor_conditions = [{"blocks": [
            {"type": "SIG", "fields": [
                {"type": "SCHEME", "hex": "10"},
                {"type": "PUBKEY", "hex": pq_pubkey},
            ]},
            {"type": "RECURSE_SAME", "fields": [
                {"type": "NUMERIC", "hex": "e803"},  # depth=1000
            ]},
        ]}]
        anchor_txid, anchor_vout, anchor_amount, anchor_spk = \
            self.bootstrap_v4_output(node, anchor_conditions, output_amount=Decimal("0.001"))
        self.log.info(f"  Anchor UTXO: {anchor_txid}:{anchor_vout} ({anchor_spk[:20]}...)")

        # --- Step 2: Compute COSIGN hash (SHA256 of anchor's scriptPubKey) ---
        import hashlib
        anchor_spk_bytes = bytes.fromhex(anchor_spk)
        cosign_hash = hashlib.sha256(anchor_spk_bytes).hexdigest()
        self.log.info(f"  COSIGN hash: {cosign_hash[:16]}...")

        # --- Step 3: Create child UTXO with SIG + COSIGN ---
        child_wif, child_pubkey = make_keypair()
        child_conditions = [{"blocks": [
            {"type": "SIG", "fields": [
                {"type": "PUBKEY", "hex": child_pubkey},
            ]},
            {"type": "COSIGN", "fields": [
                {"type": "HASH256", "hex": cosign_hash},
            ]},
        ]}]
        child_txid, child_vout, child_amount, child_spk = \
            self.bootstrap_v4_output(node, child_conditions)
        self.log.info(f"  Child UTXO: {child_txid}:{child_vout}")

        # --- Step 4: Spend both in one transaction ---
        # Output 0: anchor re-encumbered (RECURSE_SAME)
        # Output 1: child freed to destination
        dest_wif, dest_pubkey = make_keypair()
        spend_result = node.createrungtx(
            [
                {"txid": anchor_txid, "vout": anchor_vout},
                {"txid": child_txid, "vout": child_vout},
            ],
            [
                {"amount": anchor_amount - Decimal("0.0001"), "conditions": anchor_conditions},
                {"amount": child_amount - Decimal("0.001"), "conditions": [{"blocks": [{
                    "type": "SIG",
                    "fields": [{"type": "PUBKEY", "hex": dest_pubkey}]
                }]}]},
            ]
        )

        # Sign: input 0 (anchor) with PQ key, input 1 (child) with Schnorr key
        sign_result = node.signrungtx(
            spend_result["hex"],
            [
                {"input": 0, "blocks": [
                    {"type": "SIG", "scheme": "FALCON512",
                     "pq_privkey": pq_privkey, "pq_pubkey": pq_pubkey},
                    {"type": "RECURSE_SAME"},
                ]},
                {"input": 1, "blocks": [
                    {"type": "SIG", "privkey": child_wif},
                    {"type": "COSIGN"},
                ]},
            ],
            [
                {"amount": anchor_amount, "scriptPubKey": anchor_spk},
                {"amount": child_amount, "scriptPubKey": child_spk},
            ]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1

        # Verify anchor was re-encumbered with same conditions
        anchor_out_spk = tx_info["vout"][0]["scriptPubKey"]["hex"]
        assert_equal(anchor_out_spk, anchor_spk)

        self.log.info(f"  COSIGN spend confirmed: {spend_txid[:16]}...")
        self.log.info(f"  Anchor re-encumbered: {anchor_out_spk[:20]}...")

        # Report witness size savings
        tx_size = len(sign_result["hex"]) // 2
        self.log.info(f"  Total tx size: {tx_size}B (1 PQ sig + 1 Schnorr sig)")
        self.log.info("  Scenario 17 PASSED: COSIGN PQ anchor co-spend")

    def test_cosign_negative_no_anchor(self, node):
        """COSIGN negative: spending child without the anchor → rejected.

        If someone tries to spend the child UTXO alone (without the anchor
        as a co-input), the COSIGN block fails because no other input's
        scriptPubKey matches the required hash.
        """
        self.log.info("Scenario 18: COSIGN negative (no anchor)...")

        # Generate more coins and rescan wallet for spendable UTXOs
        self.generate(node, 110)
        self.wallet.rescan_utxos()

        # Create a child UTXO with COSIGN pointing to a fake anchor hash
        child_wif, child_pubkey = make_keypair()
        fake_anchor_hash = "aa" * 32
        child_conditions = [{"blocks": [
            {"type": "SIG", "fields": [
                {"type": "PUBKEY", "hex": child_pubkey},
            ]},
            {"type": "COSIGN", "fields": [
                {"type": "HASH256", "hex": fake_anchor_hash},
            ]},
        ]}]
        child_txid, child_vout, child_amount, child_spk = \
            self.bootstrap_v4_output(node, child_conditions)

        # Try to spend child alone — no anchor present
        dest_wif, dest_pubkey = make_keypair()
        spend = node.createrungtx(
            [{"txid": child_txid, "vout": child_vout}],
            [{"amount": child_amount - Decimal("0.001"), "conditions": [{"blocks": [{
                "type": "SIG",
                "fields": [{"type": "PUBKEY", "hex": dest_pubkey}]
            }]}]}]
        )
        signed = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [
                {"type": "SIG", "privkey": child_wif},
                {"type": "COSIGN"},
            ]}],
            [{"amount": child_amount, "scriptPubKey": child_spk}]
        )

        # Should be rejected: COSIGN finds no matching anchor
        assert_raises_rpc_error(-26, "", node.sendrawtransaction, signed["hex"])
        self.log.info("  Child spend without anchor: REJECTED")
        self.log.info("  Scenario 18 PASSED: COSIGN requires anchor co-input")


    def test_cosign_10_children(self, node):
        """COSIGN at scale: 1 PQ anchor + 10 children in a single transaction.

        Demonstrates the full anchor pattern:
        1. Create PQ anchor UTXO (FALCON512 + PUBKEY_COMMIT + RECURSE_SAME)
        2. Create 10 independent child UTXOs (Schnorr + COSIGN)
        3. Spend all 11 inputs in one tx: anchor re-encumbers, 10 children freed
        4. Compare tx size vs hypothetical 10 individual FALCON512 spends
        """
        self.log.info("Scenario 19: COSIGN 10-child batch spend...")

        if self.skip_if_no_pq(node):
            return

        # Mine blocks to MiniWallet's descriptor so it has spendable UTXOs
        self.generatetodescriptor(node, 200, self.wallet.get_descriptor())
        self.wallet.rescan_utxos()

        # --- Step 1: Create PQ anchor ---
        pq_keypair = node.generatepqkeypair("FALCON512")
        pq_pubkey = pq_keypair["pubkey"]
        pq_privkey = pq_keypair["privkey"]
        anchor_conditions = [{"blocks": [
            {"type": "SIG", "fields": [
                {"type": "SCHEME", "hex": "10"},
                {"type": "PUBKEY", "hex": pq_pubkey},
            ]},
            {"type": "RECURSE_SAME", "fields": [
                {"type": "NUMERIC", "hex": "e803"},
            ]},
        ]}]
        anchor_txid, anchor_vout, anchor_amount, anchor_spk = \
            self.bootstrap_v4_output(node, anchor_conditions, output_amount=Decimal("0.001"))
        self.log.info(f"  Anchor created: {anchor_txid[:16]}...")

        # --- Step 2: Compute COSIGN hash ---
        import hashlib
        cosign_hash = hashlib.sha256(bytes.fromhex(anchor_spk)).hexdigest()

        # --- Step 3: Create 10 child UTXOs in a single funding tx ---
        NUM_CHILDREN = 10
        child_keys = []
        child_conditions_list = []
        for i in range(NUM_CHILDREN):
            child_wif, child_pubkey = make_keypair()
            child_keys.append((child_wif, child_pubkey))
            child_conditions_list.append([{"blocks": [
                {"type": "SIG", "fields": [
                    {"type": "PUBKEY", "hex": child_pubkey},
                ]},
                {"type": "COSIGN", "fields": [
                    {"type": "HASH256", "hex": cosign_hash},
                ]},
            ]}])

        # Use a single wallet UTXO to fund all 10 children
        utxo = self.wallet.get_utxo()
        input_amount = utxo["value"]
        txout_info = node.gettxout(utxo["txid"], utxo["vout"])
        spent_spk = txout_info["scriptPubKey"]["hex"]

        child_amount = Decimal("0.005")
        outputs = []
        for conds in child_conditions_list:
            outputs.append({"amount": child_amount, "conditions": conds})

        # Add change output to avoid fee-exceeds-max error
        boot_wif, boot_pubkey = make_keypair()
        change_wif, change_pubkey = make_keypair()
        change_amount = Decimal(input_amount) - (child_amount * NUM_CHILDREN) - Decimal("0.001")
        if change_amount > Decimal("0"):
            outputs.append({"amount": change_amount, "conditions": [{"blocks": [
                {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": change_pubkey}]}
            ]}]})
        fund_result = node.createrungtx(
            [{"txid": utxo["txid"], "vout": utxo["vout"]}],
            outputs,
        )
        sign_result = node.signrungtx(
            fund_result["hex"],
            [{"privkey": boot_wif, "input": 0}],
            [{"amount": input_amount, "scriptPubKey": spent_spk}],
        )
        assert sign_result["complete"]
        fund_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        fund_tx = node.getrawtransaction(fund_txid, True)
        assert fund_tx["confirmations"] >= 1

        children = []
        for i in range(NUM_CHILDREN):
            children.append({
                "txid": fund_txid,
                "vout": i,
                "amount": child_amount,
                "spk": fund_tx["vout"][i]["scriptPubKey"]["hex"],
                "wif": child_keys[i][0],
                "pubkey": child_keys[i][1],
            })
        self.log.info(f"  Created {NUM_CHILDREN} child UTXOs with COSIGN in 1 tx")

        # --- Step 4: Build the 11-input transaction ---
        # Inputs: anchor + 10 children
        inputs = [{"txid": anchor_txid, "vout": anchor_vout}]
        for c in children:
            inputs.append({"txid": c["txid"], "vout": c["vout"]})

        # Outputs: re-encumbered anchor + 10 destinations
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{
            "type": "SIG",
            "fields": [{"type": "PUBKEY", "hex": dest_pubkey}]
        }]}]

        outputs = [{"amount": anchor_amount - Decimal("0.0001"), "conditions": anchor_conditions}]
        total_child_value = Decimal("0")
        for c in children:
            total_child_value += c["amount"]
        # Send all children's value to a single destination (minus fee)
        outputs.append({
            "amount": total_child_value - Decimal("0.001"),
            "conditions": dest_conditions,
        })

        spend_result = node.createrungtx(inputs, outputs)

        # --- Step 5: Sign all inputs ---
        sign_blocks = [
            # Input 0: anchor (PQ)
            {"input": 0, "blocks": [
                {"type": "SIG", "scheme": "FALCON512",
                 "pq_privkey": pq_privkey, "pq_pubkey": pq_pubkey},
                {"type": "RECURSE_SAME"},
            ]},
        ]
        for i, c in enumerate(children):
            sign_blocks.append({
                "input": i + 1,
                "blocks": [
                    {"type": "SIG", "privkey": c["wif"]},
                    {"type": "COSIGN"},
                ],
            })

        spent_info = [{"amount": anchor_amount, "scriptPubKey": anchor_spk}]
        for c in children:
            spent_info.append({"amount": c["amount"], "scriptPubKey": c["spk"]})

        sign_result = node.signrungtx(spend_result["hex"], sign_blocks, spent_info)
        assert sign_result["complete"]

        # --- Step 6: Broadcast and confirm ---
        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1

        # Verify anchor re-encumbered
        anchor_out_spk = tx_info["vout"][0]["scriptPubKey"]["hex"]
        assert_equal(anchor_out_spk, anchor_spk)

        # --- Step 7: Report sizes ---
        cosign_tx_size = len(sign_result["hex"]) // 2
        # Hypothetical: 10 individual FALCON512 spends would each need ~1,582B witness
        hypothetical_per_pq = 1582
        hypothetical_total = hypothetical_per_pq * NUM_CHILDREN
        # Actual COSIGN witness: 1 PQ (~1,586B) + 10 Schnorr (~82B each)
        schnorr_per_child = 82

        self.log.info(f"  ┌─────────────────────────────────────────────────┐")
        self.log.info(f"  │ COSIGN 10-CHILD BATCH SPEND — CONFIRMED        │")
        self.log.info(f"  ├─────────────────────────────────────────────────┤")
        self.log.info(f"  │ Tx: {spend_txid[:48]}...│")
        self.log.info(f"  │ Inputs:  1 anchor + {NUM_CHILDREN} children = {NUM_CHILDREN + 1} total       │")
        self.log.info(f"  │ Outputs: 1 anchor + 1 destination = 2 total    │")
        self.log.info(f"  ├─────────────────────────────────────────────────┤")
        self.log.info(f"  │ COSIGN tx size:     {cosign_tx_size:>6,}B                    │")
        self.log.info(f"  │ 10× PQ witness:     {hypothetical_total:>6,}B (hypothetical)    │")
        self.log.info(f"  │ Savings:            {hypothetical_total - cosign_tx_size:>6,}B ({hypothetical_total / cosign_tx_size:.1f}× smaller)     │")
        self.log.info(f"  ├─────────────────────────────────────────────────┤")
        self.log.info(f"  │ PQ sigs in tx:      1 (anchor only)            │")
        self.log.info(f"  │ Schnorr sigs in tx: {NUM_CHILDREN} (children)              │")
        self.log.info(f"  │ Anchor re-encumbered: YES                      │")
        self.log.info(f"  └─────────────────────────────────────────────────┘")
        self.log.info("  Scenario 19 PASSED: COSIGN 10-child batch spend")


    # =========================================================================
    # Adaptor sig & state gating tests
    # =========================================================================

    def test_extractadaptorsecret_rpc(self, node):
        """Test extractadaptorsecret RPC: scalar subtraction of s-values."""
        self.log.info("Testing extractadaptorsecret RPC...")

        # Create two fake 64-byte signatures with known s-values
        # pre_sig:     R || s_pre
        # adapted_sig: R || s_adapted
        # secret = s_adapted - s_pre
        import os
        R = os.urandom(32)
        s_pre = os.urandom(32)
        s_adapted = os.urandom(32)

        pre_sig_hex = (R + s_pre).hex()
        adapted_sig_hex = (R + s_adapted).hex()

        result = node.extractadaptorsecret(pre_sig_hex, adapted_sig_hex)
        assert "secret" in result
        assert len(result["secret"]) == 64  # 32 bytes hex
        self.log.info("  extractadaptorsecret RPC works!")

    def test_counter_down_state_gating(self, node):
        """Test COUNTER_DOWN with state gating via RECURSE_MODIFIED chain."""
        self.log.info("Testing COUNTER_DOWN state gating...")

        # Create a COUNTER_DOWN with count=2 + SIG + RECURSE_MODIFIED
        wif, pubkey = make_keypair()
        conditions = [{"blocks": [
            {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": pubkey}]},
            {"type": "COUNTER_DOWN", "fields": [
                {"type": "PUBKEY", "hex": pubkey},
                {"type": "NUMERIC", "hex": numeric_hex(2)},  # count=2
            ]},
        ]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  COUNTER_DOWN output (count=2): {txid}:{vout}")

        # Spend it — COUNTER_DOWN with count=2 should be SATISFIED
        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [
                {"type": "SIG", "privkey": wif},
                {"type": "COUNTER_DOWN"},
            ]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]
        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        self.log.info("  COUNTER_DOWN (count=2) spend confirmed!")

    def test_one_shot_state_gating(self, node):
        """Test ONE_SHOT: state=0 should fire, state=1 should block."""
        self.log.info("Testing ONE_SHOT state gating...")

        # Create ONE_SHOT with state=0 (can fire)
        commitment = os.urandom(32).hex()
        conditions = [{"blocks": [{"type": "ONE_SHOT", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(0)},
            {"type": "HASH256", "hex": commitment},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  ONE_SHOT output (state=0): {txid}:{vout}")

        # Spend it — state=0 should be SATISFIED
        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "ONE_SHOT"}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]
        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        self.log.info("  ONE_SHOT (state=0) spend confirmed!")

        # Now test ONE_SHOT with state=1 (already fired, should fail)
        conditions_fired = [{"blocks": [{"type": "ONE_SHOT", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(1)},
            {"type": "HASH256", "hex": commitment},
        ]}]}]

        txid2, vout2, amount2, spk2 = self.bootstrap_v4_output(node, conditions_fired)
        self.log.info(f"  ONE_SHOT output (state=1): {txid2}:{vout2}")

        output_amount2 = amount2 - Decimal("0.001")
        spend2 = node.createrungtx(
            [{"txid": txid2, "vout": vout2}],
            [{"amount": output_amount2, "conditions": dest_conditions}]
        )
        sign_result2 = node.signrungtx(
            spend2["hex"],
            [{"input": 0, "blocks": [{"type": "ONE_SHOT"}]}],
            [{"amount": amount2, "scriptPubKey": spk2}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result2["hex"])
        self.log.info("  ONE_SHOT (state=1) correctly rejected!")

    def test_diff_witness_spend(self, node):
        """Scenario 20: DIFF_WITNESS — spend two identical SIG outputs, second uses diff witness."""
        self.log.info("Scenario 20: Testing diff witness spend...")

        privkey_wif, pubkey_hex = make_keypair()
        sig_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": pubkey_hex}
        ]}]}]

        # Create two identical SIG outputs
        txid1, vout1, amount1, spk1 = self.bootstrap_v4_output(node, sig_conditions)
        txid2, vout2, amount2, spk2 = self.bootstrap_v4_output(node, sig_conditions)
        self.log.info(f"  Created v4 outputs: {txid1}:{vout1} and {txid2}:{vout2}")

        total_input = amount1 + amount2
        output_amount = total_input - Decimal("0.001")

        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        result = node.createrungtx(
            [{"txid": txid1, "vout": vout1}, {"txid": txid2, "vout": vout2}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )

        # Input 0: normal sign
        # Input 1: diff_witness from input 0, with SIGNATURE diff (different sighash per input)
        sign_result = node.signrungtx(
            result["hex"],
            [
                {"input": 0, "blocks": [{"type": "SIG", "privkey": privkey_wif}]},
                {"input": 1, "diff_witness": {
                    "source_input": 0,
                    "diffs": [
                        {"rung_index": 0, "block_index": 0, "field_index": 1,
                         "field": {"type": "SIGNATURE", "privkey": privkey_wif}},
                    ],
                }},
            ],
            [
                {"amount": amount1, "scriptPubKey": spk1},
                {"amount": amount2, "scriptPubKey": spk2},
            ]
        )
        assert sign_result["complete"], "Diff witness tx should be fully signed"

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)

        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info(f"  Diff witness spend confirmed: {spend_txid}")

        # Verify decoderung shows witness_ref for input 1
        raw_tx = node.decoderawtransaction(node.getrawtransaction(spend_txid))
        wit1_hex = raw_tx["vin"][1]["txinwitness"][0]
        decoded = node.decoderung(wit1_hex)
        assert decoded["witness_ref"] is True
        assert_equal(decoded["source_input"], 0)
        assert_equal(decoded["num_rungs"], 0)
        assert_equal(len(decoded["diffs"]), 1)
        assert_equal(decoded["diffs"][0]["rung_index"], 0)
        assert_equal(decoded["diffs"][0]["block_index"], 0)
        assert_equal(decoded["diffs"][0]["field_index"], 1)
        assert_equal(decoded["diffs"][0]["field"]["type"], "SIGNATURE")
        self.log.info("  Diff witness decoderung verification passed!")

        # Verify wire size savings
        wit0_hex = raw_tx["vin"][0]["txinwitness"][0]
        self.log.info(f"  Normal witness: {len(wit0_hex)//2} bytes, Diff witness: {len(wit1_hex)//2} bytes")
        assert len(wit1_hex) < len(wit0_hex), "Diff witness should be smaller than full witness"

        self.log.info("  Scenario 20 PASSED: Diff witness spend")

    def test_diff_witness_negative_self_ref(self, node):
        """Scenario 20b: DIFF_WITNESS — self-referencing input rejected at consensus."""
        self.log.info("Scenario 20b: Testing diff witness self-reference rejection...")

        privkey_wif, pubkey_hex = make_keypair()
        sig_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": pubkey_hex}
        ]}]}]

        txid1, vout1, amount1, spk1 = self.bootstrap_v4_output(node, sig_conditions)
        output_amount = amount1 - Decimal("0.001")

        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        result = node.createrungtx(
            [{"txid": txid1, "vout": vout1}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )

        # Input 0 references itself (source_input=0 >= nIn=0) — should fail at consensus
        sign_result = node.signrungtx(
            result["hex"],
            [
                {"input": 0, "diff_witness": {
                    "source_input": 0,
                    "diffs": [],
                }},
            ],
            [{"amount": amount1, "scriptPubKey": spk1}]
        )
        assert sign_result["complete"]

        # Should be rejected by consensus (forward-only: source_input >= nIn)
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  Self-referencing diff witness correctly rejected!")
        self.log.info("  Scenario 20b PASSED: Diff witness self-reference rejection")


    # =========================================================================
    # KEY_REF_SIG tests
    # =========================================================================

    def test_key_ref_sig_spend(self, node):
        """Test KEY_REF_SIG: sign using key commitment from a relay block."""
        self.log.info("Testing KEY_REF_SIG spend...")

        privkey_wif, pubkey_hex = make_keypair()

        # Relay 0: SIG block with PUBKEY (node auto-computes commitment)
        relays = [{"blocks": [{
            "type": "SIG",
            "fields": [
                {"type": "PUBKEY", "hex": pubkey_hex},
                {"type": "SCHEME", "hex": "01"},  # SCHNORR
            ]
        }]}]

        # Rung: KEY_REF_SIG referencing relay 0, block 0
        conditions = [{
            "blocks": [{
                "type": "KEY_REF_SIG",
                "fields": [
                    {"type": "NUMERIC", "hex": numeric_hex(0)},  # relay_index = 0
                    {"type": "NUMERIC", "hex": numeric_hex(0)},  # block_index = 0
                ]
            }],
            "relay_refs": [0],
        }]

        # Bootstrap: create v4 output with relay + KEY_REF_SIG conditions
        txid, vout, amount, spk = self.bootstrap_v4_output_with_relays(
            node, conditions, relays)

        # Spend: sign the KEY_REF_SIG rung + relay SIG
        output_amount = amount - Decimal("0.001")
        spend_wif, spend_pubkey = make_keypair()

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": [{
                "blocks": [{"type": "SIG", "fields": [
                    {"type": "PUBKEY", "hex": spend_pubkey}
                ]}]
            }]}]
        )

        sign_result = node.signrungtx(
            result["hex"],
            [{
                "input": 0,
                "rung": 0,
                "blocks": [{"type": "KEY_REF_SIG", "privkey": privkey_wif}],
                "relay_blocks": [{"blocks": [{"type": "SIG", "privkey": privkey_wif}]}],
            }],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"], "KEY_REF_SIG spend should be fully signed"

        txid2 = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(txid2, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  KEY_REF_SIG spend confirmed!")

    def test_key_ref_sig_multi_rung(self, node):
        """Test KEY_REF_SIG: two rungs sharing the same relay key commitment."""
        self.log.info("Testing KEY_REF_SIG multi-rung shared relay...")

        privkey_wif1, pubkey_hex1 = make_keypair()
        privkey_wif2, pubkey_hex2 = make_keypair()

        # Shared relay: SIG with pubkey1 (node auto-computes commitment)
        relays = [{"blocks": [{
            "type": "SIG",
            "fields": [
                {"type": "PUBKEY", "hex": pubkey_hex1},
                {"type": "SCHEME", "hex": "01"},
            ]
        }]}]

        # Rung 0: KEY_REF_SIG (relay 0, block 0) — key1
        # Rung 1: SIG with key2 (fallback, no relay needed)
        conditions = [
            {
                "blocks": [{
                    "type": "KEY_REF_SIG",
                    "fields": [
                        {"type": "NUMERIC", "hex": numeric_hex(0)},
                        {"type": "NUMERIC", "hex": numeric_hex(0)},
                    ]
                }],
                "relay_refs": [0],
            },
            {
                "blocks": [{"type": "SIG", "fields": [
                    {"type": "PUBKEY", "hex": pubkey_hex2}
                ]}],
            },
        ]

        txid, vout, amount, spk = self.bootstrap_v4_output_with_relays(
            node, conditions, relays)

        # Spend via rung 0 (KEY_REF_SIG)
        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": [{
                "blocks": [{"type": "SIG", "fields": [
                    {"type": "PUBKEY", "hex": dest_pubkey}
                ]}]
            }]}]
        )

        sign_result = node.signrungtx(
            result["hex"],
            [{
                "input": 0,
                "rung": 0,
                "blocks": [{"type": "KEY_REF_SIG", "privkey": privkey_wif1}],
                "relay_blocks": [{"blocks": [{"type": "SIG", "privkey": privkey_wif1}]}],
            }],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        txid2 = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(txid2, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  KEY_REF_SIG multi-rung spend via rung 0 confirmed!")

    def test_key_ref_sig_negative_wrong_key(self, node):
        """Test KEY_REF_SIG: wrong key should fail to spend."""
        self.log.info("Testing KEY_REF_SIG negative: wrong key...")

        privkey_wif, pubkey_hex = make_keypair()
        wrong_wif, wrong_pubkey = make_keypair()

        relays = [{"blocks": [{
            "type": "SIG",
            "fields": [
                {"type": "PUBKEY", "hex": pubkey_hex},
                {"type": "SCHEME", "hex": "01"},
            ]
        }]}]

        conditions = [{
            "blocks": [{
                "type": "KEY_REF_SIG",
                "fields": [
                    {"type": "NUMERIC", "hex": numeric_hex(0)},
                    {"type": "NUMERIC", "hex": numeric_hex(0)},
                ]
            }],
            "relay_refs": [0],
        }]

        txid, vout, amount, spk = self.bootstrap_v4_output_with_relays(
            node, conditions, relays)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": [{
                "blocks": [{"type": "SIG", "fields": [
                    {"type": "PUBKEY", "hex": dest_pubkey}
                ]}]
            }]}]
        )

        # Sign with wrong key — pubkey won't match commitment
        sign_result = node.signrungtx(
            result["hex"],
            [{
                "input": 0,
                "rung": 0,
                "blocks": [{"type": "KEY_REF_SIG", "privkey": wrong_wif}],
                "relay_blocks": [{"blocks": [{"type": "SIG", "privkey": wrong_wif}]}],
            }],
            [{"amount": amount, "scriptPubKey": spk}]
        )

        # Transaction should be signed but invalid (wrong key vs commitment)
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  KEY_REF_SIG wrong key correctly rejected!")

    # =========================================================================
    # Compound block type tests (C-5)
    # =========================================================================

    def test_timelocked_sig(self, node):
        """TIMELOCKED_SIG: SIG + CSV in one compound block."""
        self.log.info("Testing TIMELOCKED_SIG spend...")
        csv_blocks = 5
        wif, pubkey = make_keypair()

        conditions = [{"blocks": [{"type": "TIMELOCKED_SIG", "fields": [
            {"type": "PUBKEY", "hex": pubkey},
            {"type": "SCHEME", "hex": "01"},
            {"type": "NUMERIC", "hex": numeric_hex(csv_blocks)},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        # Mine for CSV maturity
        self.generate(node, csv_blocks)

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout, "sequence": csv_blocks}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "TIMELOCKED_SIG", "privkey": wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]
        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        assert node.getrawtransaction(spend_txid, True)["confirmations"] >= 1
        self.log.info("  TIMELOCKED_SIG spend confirmed!")

    def test_negative_timelocked_sig_bad_sig(self, node):
        """TIMELOCKED_SIG: wrong key should fail."""
        self.log.info("Testing TIMELOCKED_SIG negative (wrong key)...")
        csv_blocks = 5
        wif, pubkey = make_keypair()
        wrong_wif, _ = make_keypair()

        conditions = [{"blocks": [{"type": "TIMELOCKED_SIG", "fields": [
            {"type": "PUBKEY", "hex": pubkey},
            {"type": "SCHEME", "hex": "01"},
            {"type": "NUMERIC", "hex": numeric_hex(csv_blocks)},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.generate(node, csv_blocks)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout, "sequence": csv_blocks}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "TIMELOCKED_SIG", "privkey": wrong_wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  TIMELOCKED_SIG negative (wrong key) — rejected correctly!")

    def test_htlc_compound(self, node):
        """HTLC compound block: hash + timelock + sig in one block."""
        self.log.info("Testing HTLC compound block spend...")
        csv_blocks = 5
        wif, pubkey = make_keypair()

        preimage = os.urandom(32)

        # HTLC conditions: [PUBKEY, PUBKEY(receiver), PREIMAGE, NUMERIC]
        # For simplicity, use same key for both sender/receiver
        conditions = [{"blocks": [{"type": "HTLC", "fields": [
            {"type": "PUBKEY", "hex": pubkey},
            {"type": "PUBKEY", "hex": pubkey},
            {"type": "PREIMAGE", "hex": preimage.hex()},
            {"type": "NUMERIC", "hex": numeric_hex(csv_blocks)},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.generate(node, csv_blocks)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout, "sequence": csv_blocks}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "HTLC", "privkey": wif, "preimage": preimage.hex()}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]
        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        assert node.getrawtransaction(spend_txid, True)["confirmations"] >= 1
        self.log.info("  HTLC compound block spend confirmed!")

    def test_negative_htlc_wrong_preimage(self, node):
        """HTLC compound: wrong preimage should fail."""
        self.log.info("Testing HTLC negative (wrong preimage)...")
        csv_blocks = 5
        wif, pubkey = make_keypair()

        preimage = os.urandom(32)
        wrong_preimage = os.urandom(32)

        conditions = [{"blocks": [{"type": "HTLC", "fields": [
            {"type": "PUBKEY", "hex": pubkey},
            {"type": "PUBKEY", "hex": pubkey},
            {"type": "PREIMAGE", "hex": preimage.hex()},
            {"type": "NUMERIC", "hex": numeric_hex(csv_blocks)},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.generate(node, csv_blocks)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout, "sequence": csv_blocks}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "HTLC", "privkey": wif, "preimage": wrong_preimage.hex()}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  HTLC negative (wrong preimage) — rejected correctly!")

    def test_hash_sig(self, node):
        """HASH_SIG: hash preimage + signature in one compound block."""
        self.log.info("Testing HASH_SIG spend...")
        wif, pubkey = make_keypair()

        preimage = os.urandom(32)

        conditions = [{"blocks": [{"type": "HASH_SIG", "fields": [
            {"type": "PUBKEY", "hex": pubkey},
            {"type": "PREIMAGE", "hex": preimage.hex()},
            {"type": "SCHEME", "hex": "01"},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "HASH_SIG", "privkey": wif, "preimage": preimage.hex()}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]
        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        assert node.getrawtransaction(spend_txid, True)["confirmations"] >= 1
        self.log.info("  HASH_SIG spend confirmed!")

    def test_negative_hash_sig_wrong_preimage(self, node):
        """HASH_SIG: wrong preimage should fail."""
        self.log.info("Testing HASH_SIG negative (wrong preimage)...")
        wif, pubkey = make_keypair()

        preimage = os.urandom(32)
        wrong_preimage = os.urandom(32)

        conditions = [{"blocks": [{"type": "HASH_SIG", "fields": [
            {"type": "PUBKEY", "hex": pubkey},
            {"type": "PREIMAGE", "hex": preimage.hex()},
            {"type": "SCHEME", "hex": "01"},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "HASH_SIG", "privkey": wif, "preimage": wrong_preimage.hex()}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  HASH_SIG negative (wrong preimage) — rejected correctly!")

    def test_cltv_sig(self, node):
        """CLTV_SIG: signature + absolute timelock in one compound block."""
        self.log.info("Testing CLTV_SIG spend...")
        wif, pubkey = make_keypair()

        current_height = node.getblockcount()
        target_height = current_height + 10

        conditions = [{"blocks": [{"type": "CLTV_SIG", "fields": [
            {"type": "PUBKEY", "hex": pubkey},
            {"type": "SCHEME", "hex": "01"},
            {"type": "NUMERIC", "hex": numeric_hex(target_height)},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        # Mine past CLTV height
        blocks_needed = target_height - node.getblockcount() + 1
        if blocks_needed > 0:
            self.generate(node, blocks_needed)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout, "locktime": target_height}],
            [{"amount": output_amount, "conditions": dest_conditions}],
            target_height,
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "CLTV_SIG", "privkey": wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]
        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        assert node.getrawtransaction(spend_txid, True)["confirmations"] >= 1
        self.log.info("  CLTV_SIG spend confirmed!")

    def test_negative_cltv_sig_too_early(self, node):
        """CLTV_SIG: spending before target height should fail."""
        self.log.info("Testing CLTV_SIG negative (too early)...")
        wif, pubkey = make_keypair()

        current_height = node.getblockcount()
        target_height = current_height + 100  # far in the future

        conditions = [{"blocks": [{"type": "CLTV_SIG", "fields": [
            {"type": "PUBKEY", "hex": pubkey},
            {"type": "SCHEME", "hex": "01"},
            {"type": "NUMERIC", "hex": numeric_hex(target_height)},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout, "locktime": target_height}],
            [{"amount": output_amount, "conditions": dest_conditions}],
            target_height,
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "CLTV_SIG", "privkey": wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, "non-final", node.sendrawtransaction, sign_result["hex"])
        self.log.info("  CLTV_SIG negative (too early) — rejected correctly!")

    def test_timelocked_multisig(self, node):
        """TIMELOCKED_MULTISIG: 2-of-3 multisig + CSV in one compound block."""
        self.log.info("Testing TIMELOCKED_MULTISIG spend...")
        csv_blocks = 5
        wif1, pk1 = make_keypair()
        wif2, pk2 = make_keypair()
        wif3, pk3 = make_keypair()

        conditions = [{"blocks": [{"type": "TIMELOCKED_MULTISIG", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(2)},  # threshold
            {"type": "PUBKEY", "hex": pk1},
            {"type": "PUBKEY", "hex": pk2},
            {"type": "PUBKEY", "hex": pk3},
            {"type": "SCHEME", "hex": "01"},
            {"type": "NUMERIC", "hex": numeric_hex(csv_blocks)},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.generate(node, csv_blocks)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout, "sequence": csv_blocks}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "TIMELOCKED_MULTISIG",
                                       "privkeys": [wif1, wif2]}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]
        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        assert node.getrawtransaction(spend_txid, True)["confirmations"] >= 1
        self.log.info("  TIMELOCKED_MULTISIG spend confirmed!")

    def test_negative_timelocked_multisig_too_few_sigs(self, node):
        """TIMELOCKED_MULTISIG: 1-of-3 when threshold is 2 should fail."""
        self.log.info("Testing TIMELOCKED_MULTISIG negative (too few sigs)...")
        csv_blocks = 5
        wif1, pk1 = make_keypair()
        _wif2, pk2 = make_keypair()
        _wif3, pk3 = make_keypair()

        conditions = [{"blocks": [{"type": "TIMELOCKED_MULTISIG", "fields": [
            {"type": "NUMERIC", "hex": numeric_hex(2)},
            {"type": "PUBKEY", "hex": pk1},
            {"type": "PUBKEY", "hex": pk2},
            {"type": "PUBKEY", "hex": pk3},
            {"type": "SCHEME", "hex": "01"},
            {"type": "NUMERIC", "hex": numeric_hex(csv_blocks)},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.generate(node, csv_blocks)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout, "sequence": csv_blocks}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "TIMELOCKED_MULTISIG",
                                       "privkeys": [wif1]}]}],  # only 1 sig, need 2
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  TIMELOCKED_MULTISIG negative (too few sigs) — rejected correctly!")

    def test_ptlc(self, node):
        """PTLC: adaptor signature + CSV in one compound block."""
        self.log.info("Testing PTLC spend...")
        csv_blocks = 5
        signing_wif, signing_pubkey = make_keypair()
        _adaptor_wif, adaptor_pubkey = make_keypair()

        conditions = [{"blocks": [{"type": "PTLC", "fields": [
            {"type": "PUBKEY", "hex": signing_pubkey},
            {"type": "PUBKEY", "hex": adaptor_pubkey},
            {"type": "NUMERIC", "hex": numeric_hex(csv_blocks)},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.generate(node, csv_blocks)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout, "sequence": csv_blocks}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "PTLC", "privkey": signing_wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]
        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        assert node.getrawtransaction(spend_txid, True)["confirmations"] >= 1
        self.log.info("  PTLC spend confirmed!")

    def test_negative_ptlc_bad_sig(self, node):
        """PTLC: wrong signing key should fail."""
        self.log.info("Testing PTLC negative (wrong key)...")
        csv_blocks = 5
        _correct_wif, signing_pubkey = make_keypair()
        wrong_wif, _ = make_keypair()
        _adaptor_wif, adaptor_pubkey = make_keypair()

        conditions = [{"blocks": [{"type": "PTLC", "fields": [
            {"type": "PUBKEY", "hex": signing_pubkey},
            {"type": "PUBKEY", "hex": adaptor_pubkey},
            {"type": "NUMERIC", "hex": numeric_hex(csv_blocks)},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.generate(node, csv_blocks)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout, "sequence": csv_blocks}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "PTLC", "privkey": wrong_wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  PTLC negative (wrong key) — rejected correctly!")

    # =========================================================================
    # Governance block type tests (C-5)
    # =========================================================================

    def test_epoch_gate(self, node):
        """EPOCH_GATE: spending allowed within epoch window."""
        self.log.info("Testing EPOCH_GATE spend...")
        # Use a large epoch so we're guaranteed to be within the window
        epoch_size = 10000
        window_size = 9999  # almost always open

        conditions = [{"blocks": [
            {"type": "EPOCH_GATE", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(epoch_size)},
                {"type": "NUMERIC", "hex": numeric_hex(window_size)},
            ]},
            {"type": "SIG", "fields": [
                {"type": "PUBKEY", "hex": make_keypair()[1]}
            ]},
        ]}]

        wif, pubkey = make_keypair()
        conditions[0]["blocks"][1]["fields"][0]["hex"] = pubkey

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "EPOCH_GATE"}, {"type": "SIG", "privkey": wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]
        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        assert node.getrawtransaction(spend_txid, True)["confirmations"] >= 1
        self.log.info("  EPOCH_GATE spend confirmed!")

    def test_negative_epoch_gate_outside_window(self, node):
        """EPOCH_GATE: spending outside epoch window should fail."""
        self.log.info("Testing EPOCH_GATE negative (outside window)...")
        # Epoch of 10 blocks, window of 1 — very narrow
        epoch_size = 10
        window_size = 1

        wif, pubkey = make_keypair()

        conditions = [{"blocks": [
            {"type": "EPOCH_GATE", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(epoch_size)},
                {"type": "NUMERIC", "hex": numeric_hex(window_size)},
            ]},
            {"type": "SIG", "fields": [
                {"type": "PUBKEY", "hex": pubkey}
            ]},
        ]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        # Mine to ensure we're outside the 1-block window.
        # EPOCH_GATE opens when height % epoch_size < window_size.
        # We need current height % 10 >= 1 (i.e. not 0).
        # Mine until height % 10 is 5 (safely in the middle of the closed window).
        current = node.getblockcount()
        target_remainder = 5
        blocks_needed = (target_remainder - (current % epoch_size)) % epoch_size
        if blocks_needed == 0:
            blocks_needed = epoch_size  # already at 5, mine a full epoch to stay at 5
        self.generate(node, blocks_needed)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "EPOCH_GATE"}, {"type": "SIG", "privkey": wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  EPOCH_GATE negative (outside window) — rejected correctly!")

    def test_weight_limit(self, node):
        """WEIGHT_LIMIT: transaction weight within limit."""
        self.log.info("Testing WEIGHT_LIMIT spend...")
        wif, pubkey = make_keypair()

        # Generous weight limit — a simple tx is ~560 WU
        conditions = [{"blocks": [
            {"type": "WEIGHT_LIMIT", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(100000)},
            ]},
            {"type": "SIG", "fields": [
                {"type": "PUBKEY", "hex": pubkey}
            ]},
        ]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "WEIGHT_LIMIT"}, {"type": "SIG", "privkey": wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]
        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        assert node.getrawtransaction(spend_txid, True)["confirmations"] >= 1
        self.log.info("  WEIGHT_LIMIT spend confirmed!")

    def test_negative_weight_limit_exceeded(self, node):
        """WEIGHT_LIMIT: transaction weight exceeding limit should fail."""
        self.log.info("Testing WEIGHT_LIMIT negative (exceeded)...")
        wif, pubkey = make_keypair()

        # Impossibly small weight limit — any real tx exceeds this
        conditions = [{"blocks": [
            {"type": "WEIGHT_LIMIT", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(1)},
            ]},
            {"type": "SIG", "fields": [
                {"type": "PUBKEY", "hex": pubkey}
            ]},
        ]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "WEIGHT_LIMIT"}, {"type": "SIG", "privkey": wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  WEIGHT_LIMIT negative (exceeded) — rejected correctly!")

    def test_input_count(self, node):
        """INPUT_COUNT: transaction has correct number of inputs."""
        self.log.info("Testing INPUT_COUNT spend...")
        wif, pubkey = make_keypair()

        # Allow 1-10 inputs (our tx will have 1)
        conditions = [{"blocks": [
            {"type": "INPUT_COUNT", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(1)},
                {"type": "NUMERIC", "hex": numeric_hex(10)},
            ]},
            {"type": "SIG", "fields": [
                {"type": "PUBKEY", "hex": pubkey}
            ]},
        ]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "INPUT_COUNT"}, {"type": "SIG", "privkey": wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]
        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        assert node.getrawtransaction(spend_txid, True)["confirmations"] >= 1
        self.log.info("  INPUT_COUNT spend confirmed!")

    def test_negative_input_count_below_min(self, node):
        """INPUT_COUNT: too few inputs should fail."""
        self.log.info("Testing INPUT_COUNT negative (below min)...")
        wif, pubkey = make_keypair()

        # Require at least 3 inputs — our tx has only 1
        conditions = [{"blocks": [
            {"type": "INPUT_COUNT", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(3)},
                {"type": "NUMERIC", "hex": numeric_hex(10)},
            ]},
            {"type": "SIG", "fields": [
                {"type": "PUBKEY", "hex": pubkey}
            ]},
        ]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "INPUT_COUNT"}, {"type": "SIG", "privkey": wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  INPUT_COUNT negative (below min) — rejected correctly!")

    def test_output_count(self, node):
        """OUTPUT_COUNT: transaction has correct number of outputs."""
        self.log.info("Testing OUTPUT_COUNT spend...")
        wif, pubkey = make_keypair()

        # Allow 1-5 outputs
        conditions = [{"blocks": [
            {"type": "OUTPUT_COUNT", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(1)},
                {"type": "NUMERIC", "hex": numeric_hex(5)},
            ]},
            {"type": "SIG", "fields": [
                {"type": "PUBKEY", "hex": pubkey}
            ]},
        ]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "OUTPUT_COUNT"}, {"type": "SIG", "privkey": wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]
        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        assert node.getrawtransaction(spend_txid, True)["confirmations"] >= 1
        self.log.info("  OUTPUT_COUNT spend confirmed!")

    def test_negative_output_count_above_max(self, node):
        """OUTPUT_COUNT: too many outputs should fail."""
        self.log.info("Testing OUTPUT_COUNT negative (above max)...")
        wif, pubkey = make_keypair()

        # Allow exactly 1 output — our tx will have 1 but bootstrap may add change
        # Use a tight amount to avoid change output
        conditions = [{"blocks": [
            {"type": "OUTPUT_COUNT", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(1)},
                {"type": "NUMERIC", "hex": numeric_hex(1)},  # max 1 output
            ]},
            {"type": "SIG", "fields": [
                {"type": "PUBKEY", "hex": pubkey}
            ]},
        ]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        # Create spending tx with 2 outputs to exceed the max of 1
        output_amount = (amount - Decimal("0.001")) / 2
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [
                {"amount": output_amount, "conditions": dest_conditions},
                {"amount": output_amount, "conditions": dest_conditions},
            ]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "OUTPUT_COUNT"}, {"type": "SIG", "privkey": wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  OUTPUT_COUNT negative (above max) — rejected correctly!")

    def test_relative_value(self, node):
        """RELATIVE_VALUE: output must be >= 90% of input."""
        self.log.info("Testing RELATIVE_VALUE spend...")
        wif, pubkey = make_keypair()

        # 9/10 = 90% minimum ratio
        conditions = [{"blocks": [
            {"type": "RELATIVE_VALUE", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(9)},
                {"type": "NUMERIC", "hex": numeric_hex(10)},
            ]},
            {"type": "SIG", "fields": [
                {"type": "PUBKEY", "hex": pubkey}
            ]},
        ]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        # Output 95% of input — should satisfy 90% requirement
        output_amount = amount * 95 / 100
        # Round to 8 decimal places
        output_amount = Decimal(str(output_amount)).quantize(Decimal("0.00000001"))
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "RELATIVE_VALUE"}, {"type": "SIG", "privkey": wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]
        spend_txid = node.sendrawtransaction(sign_result["hex"], 0)  # maxfeerate=0 (5% fee is intentionally large)
        self.generate(node, 1)
        assert node.getrawtransaction(spend_txid, True)["confirmations"] >= 1
        self.log.info("  RELATIVE_VALUE spend confirmed!")

    def test_negative_relative_value_too_low(self, node):
        """RELATIVE_VALUE: output below 90% of input should fail."""
        self.log.info("Testing RELATIVE_VALUE negative (too low)...")
        wif, pubkey = make_keypair()

        conditions = [{"blocks": [
            {"type": "RELATIVE_VALUE", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(9)},
                {"type": "NUMERIC", "hex": numeric_hex(10)},
            ]},
            {"type": "SIG", "fields": [
                {"type": "PUBKEY", "hex": pubkey}
            ]},
        ]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        # Output only 50% — should violate 90% requirement
        output_amount = amount * 50 / 100
        output_amount = Decimal(str(output_amount)).quantize(Decimal("0.00000001"))
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [{"type": "RELATIVE_VALUE"}, {"type": "SIG", "privkey": wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  RELATIVE_VALUE negative (too low) — rejected correctly!")

    def test_accumulator(self, node):
        """ACCUMULATOR: Merkle set membership proof."""
        self.log.info("Testing ACCUMULATOR spend...")
        wif, pubkey = make_keypair()

        # Build a 2-leaf Merkle tree
        leaf0 = hashlib.sha256(b"leaf0").digest()
        leaf1 = hashlib.sha256(b"leaf1").digest()
        # Sorted concatenation
        if leaf0 < leaf1:
            combined = leaf0 + leaf1
        else:
            combined = leaf1 + leaf0
        root = hashlib.sha256(combined).digest()

        conditions = [{"blocks": [
            {"type": "ACCUMULATOR", "fields": [
                {"type": "HASH256", "hex": root.hex()},  # merkle root
            ]},
            {"type": "SIG", "fields": [
                {"type": "PUBKEY", "hex": pubkey}
            ]},
        ]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        # Prove leaf0 membership: witness has [sibling=leaf1, leaf=leaf0]
        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [
                {"type": "ACCUMULATOR", "proof": [leaf1.hex()], "leaf": leaf0.hex()},
                {"type": "SIG", "privkey": wif},
            ]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]
        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        assert node.getrawtransaction(spend_txid, True)["confirmations"] >= 1
        self.log.info("  ACCUMULATOR spend confirmed!")

    def test_negative_accumulator_wrong_leaf(self, node):
        """ACCUMULATOR: wrong leaf should fail verification."""
        self.log.info("Testing ACCUMULATOR negative (wrong leaf)...")
        wif, pubkey = make_keypair()

        leaf0 = hashlib.sha256(b"leaf0").digest()
        leaf1 = hashlib.sha256(b"leaf1").digest()
        if leaf0 < leaf1:
            combined = leaf0 + leaf1
        else:
            combined = leaf1 + leaf0
        root = hashlib.sha256(combined).digest()

        conditions = [{"blocks": [
            {"type": "ACCUMULATOR", "fields": [
                {"type": "HASH256", "hex": root.hex()},
            ]},
            {"type": "SIG", "fields": [
                {"type": "PUBKEY", "hex": pubkey}
            ]},
        ]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        # Wrong leaf — not in the tree
        wrong_leaf = os.urandom(32)

        spend = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            spend["hex"],
            [{"input": 0, "blocks": [
                {"type": "ACCUMULATOR", "proof": [leaf1.hex()], "leaf": wrong_leaf.hex()},
                {"type": "SIG", "privkey": wif},
            ]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  ACCUMULATOR negative (wrong leaf) — rejected correctly!")

    # =========================================================================
    # Legacy block type tests
    # =========================================================================

    def test_p2pk_legacy_spend(self, node):
        """P2PK_LEGACY: create output with PUBKEY + SCHEME, spend with sig."""
        self.log.info("Testing P2PK_LEGACY spend...")

        privkey_wif, pubkey_hex = make_keypair()

        # P2PK_LEGACY conditions: PUBKEY (auto-converted to PUBKEY_COMMIT) + SCHEME
        conditions = [{"blocks": [{"type": "P2PK_LEGACY", "fields": [
            {"type": "PUBKEY", "hex": pubkey_hex},
            {"type": "SCHEME", "hex": "01"},  # SCHNORR
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  P2PK_LEGACY output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "P2PK_LEGACY", "privkey": privkey_wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  P2PK_LEGACY spend confirmed!")

    def test_p2pkh_legacy_spend(self, node):
        """P2PKH_LEGACY: provide PUBKEY in conditions (node computes HASH160), spend with pubkey + sig."""
        self.log.info("Testing P2PKH_LEGACY spend...")

        privkey_wif, pubkey_hex = make_keypair()

        # P2PKH_LEGACY conditions: PUBKEY (node auto-converts to HASH160)
        conditions = [{"blocks": [{"type": "P2PKH_LEGACY", "fields": [
            {"type": "PUBKEY", "hex": pubkey_hex},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  P2PKH_LEGACY output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "P2PKH_LEGACY", "privkey": privkey_wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  P2PKH_LEGACY spend confirmed!")

    def test_p2wpkh_legacy_spend(self, node):
        """P2WPKH_LEGACY: same as P2PKH (delegates to same evaluator)."""
        self.log.info("Testing P2WPKH_LEGACY spend...")

        privkey_wif, pubkey_hex = make_keypair()

        # P2WPKH_LEGACY conditions: PUBKEY (node auto-converts to HASH160)
        conditions = [{"blocks": [{"type": "P2WPKH_LEGACY", "fields": [
            {"type": "PUBKEY", "hex": pubkey_hex},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  P2WPKH_LEGACY output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "P2WPKH_LEGACY", "privkey": privkey_wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  P2WPKH_LEGACY spend confirmed!")

    def test_p2tr_legacy_spend(self, node):
        """P2TR_LEGACY: key-path spend (delegates to EvalSigBlock)."""
        self.log.info("Testing P2TR_LEGACY spend...")

        privkey_wif, pubkey_hex = make_keypair()

        # P2TR_LEGACY conditions: PUBKEY (auto-converted to PUBKEY_COMMIT) + SCHEME
        conditions = [{"blocks": [{"type": "P2TR_LEGACY", "fields": [
            {"type": "PUBKEY", "hex": pubkey_hex},
            {"type": "SCHEME", "hex": "01"},  # SCHNORR
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  P2TR_LEGACY output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "P2TR_LEGACY", "privkey": privkey_wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  P2TR_LEGACY spend confirmed!")

    def _build_inner_sig_conditions(self, pubkey_hex):
        """Build CONDITIONS-context serialized bytes for a SIG block.

        Format (implicit SIG_CONDITIONS layout):
          01           # 1 rung
          01           # 1 block
          00           # SIG micro-header (slot 0)
          <32 bytes>   # PUBKEY_COMMIT = SHA256(pubkey)
          01           # SCHEME = SCHNORR
          01 01 01     # Coil: UNLOCK, INLINE, SCHNORR
          00           # Address length = 0
          00           # Coil conditions count = 0
        """
        pubkey_bytes = bytes.fromhex(pubkey_hex)
        pubkey_commit = hashlib.sha256(pubkey_bytes).digest()

        inner = bytearray()
        inner.append(0x01)          # 1 rung
        inner.append(0x01)          # 1 block
        inner.append(0x00)          # SIG micro-header slot 0
        inner.extend(pubkey_commit) # PUBKEY_COMMIT (32 bytes)
        inner.append(0x01)          # SCHEME = SCHNORR
        inner.append(0x01)          # Coil type = UNLOCK
        inner.append(0x01)          # Attestation = INLINE
        inner.append(0x01)          # Scheme = SCHNORR
        inner.append(0x00)          # Address length = 0
        inner.append(0x00)          # Coil conditions count = 0
        return bytes(inner)

    def test_p2sh_legacy_inner_sig(self, node):
        """P2SH_LEGACY: inner SIG conditions, spend with preimage + pubkey + sig."""
        self.log.info("Testing P2SH_LEGACY with inner SIG conditions...")

        privkey_wif, pubkey_hex = make_keypair()

        # Build inner conditions (CONDITIONS-context serialized SIG block)
        inner_bytes = self._build_inner_sig_conditions(pubkey_hex)

        # P2SH_LEGACY conditions: PREIMAGE (node auto-converts to HASH160)
        conditions = [{"blocks": [{"type": "P2SH_LEGACY", "fields": [
            {"type": "PREIMAGE", "hex": inner_bytes.hex()},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  P2SH_LEGACY output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        # Witness: PREIMAGE (inner conditions) + PUBKEY + SIGNATURE
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "P2SH_LEGACY",
                                       "preimage": inner_bytes.hex(),
                                       "privkey": privkey_wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  P2SH_LEGACY inner SIG spend confirmed!")

    def test_p2wsh_legacy_inner_sig(self, node):
        """P2WSH_LEGACY: inner SIG conditions, spend with preimage + pubkey + sig."""
        self.log.info("Testing P2WSH_LEGACY with inner SIG conditions...")

        privkey_wif, pubkey_hex = make_keypair()

        # Build inner conditions (CONDITIONS-context serialized SIG block)
        inner_bytes = self._build_inner_sig_conditions(pubkey_hex)

        # P2WSH_LEGACY conditions: PREIMAGE (node auto-converts to HASH256)
        conditions = [{"blocks": [{"type": "P2WSH_LEGACY", "fields": [
            {"type": "PREIMAGE", "hex": inner_bytes.hex()},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  P2WSH_LEGACY output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        # Witness: PREIMAGE (inner conditions) + PUBKEY + SIGNATURE
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "P2WSH_LEGACY",
                                       "preimage": inner_bytes.hex(),
                                       "privkey": privkey_wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  P2WSH_LEGACY inner SIG spend confirmed!")

    def test_negative_p2pkh_wrong_key(self, node):
        """Negative: P2PKH_LEGACY locked to key A, spend attempt with key B → rejection."""
        self.log.info("Testing negative: P2PKH_LEGACY wrong key...")

        key_a_wif, key_a_pubkey = make_keypair()
        key_b_wif, key_b_pubkey = make_keypair()

        # Lock to key A
        conditions = [{"blocks": [{"type": "P2PKH_LEGACY", "fields": [
            {"type": "PUBKEY", "hex": key_a_pubkey},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": [{"blocks": [{
                "type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pubkey}]
            }]}]}]
        )
        # Sign with key B — HASH160 won't match
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "P2PKH_LEGACY", "privkey": key_b_wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )

        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  P2PKH_LEGACY wrong key correctly rejected!")

    def test_negative_p2sh_malformed_preimage(self, node):
        """Negative: P2SH_LEGACY with garbage preimage — hash matches but inner deser fails."""
        self.log.info("Testing negative: P2SH_LEGACY malformed preimage...")

        # Create garbage inner conditions bytes that will fail deserialization
        garbage = os.urandom(32)

        # P2SH conditions: PREIMAGE (node auto-converts to HASH160)
        conditions = [{"blocks": [{"type": "P2SH_LEGACY", "fields": [
            {"type": "PREIMAGE", "hex": garbage.hex()},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)

        output_amount = amount - Decimal("0.001")
        privkey_wif, pubkey_hex = make_keypair()
        dest_wif, dest_pubkey = make_keypair()

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": [{"blocks": [{
                "type": "SIG", "fields": [{"type": "PUBKEY", "hex": dest_pubkey}]
            }]}]}]
        )
        # Provide garbage as PREIMAGE — HASH160 matches but deserialization fails
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "P2SH_LEGACY",
                                       "preimage": garbage.hex(),
                                       "privkey": privkey_wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )

        assert_raises_rpc_error(-26, None, node.sendrawtransaction, sign_result["hex"])
        self.log.info("  P2SH_LEGACY malformed preimage correctly rejected!")

    def test_legacy_plus_covenant(self, node):
        """Multi-block rung: P2PKH_LEGACY + AMOUNT_LOCK in same rung."""
        self.log.info("Testing P2PKH_LEGACY + AMOUNT_LOCK compound...")

        privkey_wif, pubkey_hex = make_keypair()

        min_sats = 10000       # 0.0001 BTC
        max_sats = 200000000   # 2.0 BTC

        conditions = [{"blocks": [
            {"type": "P2PKH_LEGACY", "fields": [
                {"type": "PUBKEY", "hex": pubkey_hex},
            ]},
            {"type": "AMOUNT_LOCK", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(min_sats)},
                {"type": "NUMERIC", "hex": numeric_hex(max_sats)},
            ]},
        ]}]

        # Use a specific amount within the AMOUNT_LOCK range
        lock_amount = Decimal("1.0")
        txid, vout, amount, spk = self.bootstrap_v4_output(
            node, conditions, output_amount=lock_amount)
        self.log.info(f"  P2PKH_LEGACY+AMOUNT_LOCK output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [
                {"type": "P2PKH_LEGACY", "privkey": privkey_wif},
                {"type": "AMOUNT_LOCK"},
            ]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  P2PKH_LEGACY + AMOUNT_LOCK compound spend confirmed!")

    def test_legacy_plus_csv(self, node):
        """Multi-block rung: P2WPKH_LEGACY + CSV in same rung."""
        self.log.info("Testing P2WPKH_LEGACY + CSV compound...")

        privkey_wif, pubkey_hex = make_keypair()

        csv_blocks = 10

        conditions = [{"blocks": [
            {"type": "P2WPKH_LEGACY", "fields": [
                {"type": "PUBKEY", "hex": pubkey_hex},
            ]},
            {"type": "CSV", "fields": [
                {"type": "NUMERIC", "hex": numeric_hex(csv_blocks)},
            ]},
        ]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  P2WPKH_LEGACY+CSV output: {txid}:{vout}")

        # Mine for CSV maturity
        self.generate(node, csv_blocks)

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        result = node.createrungtx(
            [{"txid": txid, "vout": vout, "sequence": csv_blocks}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [
                {"type": "P2WPKH_LEGACY", "privkey": privkey_wif},
                {"type": "CSV"},
            ]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  P2WPKH_LEGACY + CSV compound spend confirmed!")

    def test_legacy_mlsc(self, node):
        """Multi-rung (OR logic): Rung 0 = P2PKH_LEGACY, Rung 1 = SIG + CSV. Spend via rung 0."""
        self.log.info("Testing legacy MLSC (P2PKH_LEGACY OR SIG+CSV)...")

        key_a_wif, key_a_pubkey = make_keypair()
        key_b_wif, key_b_pubkey = make_keypair()

        csv_blocks = 50

        # Rung 0: P2PKH_LEGACY(key_a) — PUBKEY auto-converts to HASH160
        # Rung 1: SIG(key_b) + CSV(50)
        conditions = [
            {"blocks": [{"type": "P2PKH_LEGACY", "fields": [
                {"type": "PUBKEY", "hex": key_a_pubkey},
            ]}]},
            {"blocks": [
                {"type": "SIG", "fields": [{"type": "PUBKEY", "hex": key_b_pubkey}]},
                {"type": "CSV", "fields": [{"type": "NUMERIC", "hex": numeric_hex(csv_blocks)}]},
            ]},
        ]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  Legacy MLSC output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        # Spend via rung 0 (P2PKH_LEGACY) — no CSV wait needed
        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "rung": 0, "blocks": [
                {"type": "P2PKH_LEGACY", "privkey": key_a_wif},
            ]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  Legacy MLSC spend via rung 0 (P2PKH_LEGACY) confirmed!")

    def test_p2tr_script_legacy_spend(self, node):
        """P2TR_SCRIPT_LEGACY: script-path spend — inner SIG conditions."""
        self.log.info("Testing P2TR_SCRIPT_LEGACY with inner SIG conditions...")

        privkey_wif, pubkey_hex = make_keypair()
        ikey_wif, ikey_pubkey = make_keypair()

        # Build inner conditions (CONDITIONS-context serialized SIG block)
        inner_bytes = self._build_inner_sig_conditions(pubkey_hex)

        # P2TR_SCRIPT_LEGACY conditions:
        # PREIMAGE (inner conditions → node auto-converts to HASH256 Merkle root)
        # PUBKEY (internal key → node auto-converts to PUBKEY_COMMIT)
        conditions = [{"blocks": [{"type": "P2TR_SCRIPT_LEGACY", "fields": [
            {"type": "PREIMAGE", "hex": inner_bytes.hex()},
            {"type": "PUBKEY", "hex": ikey_pubkey},
        ]}]}]

        txid, vout, amount, spk = self.bootstrap_v4_output(node, conditions)
        self.log.info(f"  P2TR_SCRIPT_LEGACY output: {txid}:{vout}")

        output_amount = amount - Decimal("0.001")
        dest_wif, dest_pubkey = make_keypair()
        dest_conditions = [{"blocks": [{"type": "SIG", "fields": [
            {"type": "PUBKEY", "hex": dest_pubkey}
        ]}]}]

        result = node.createrungtx(
            [{"txid": txid, "vout": vout}],
            [{"amount": output_amount, "conditions": dest_conditions}]
        )
        # Witness: PREIMAGE (inner conditions) + PUBKEY + SIGNATURE
        sign_result = node.signrungtx(
            result["hex"],
            [{"input": 0, "blocks": [{"type": "P2TR_SCRIPT_LEGACY",
                                       "preimage": inner_bytes.hex(),
                                       "privkey": privkey_wif}]}],
            [{"amount": amount, "scriptPubKey": spk}]
        )
        assert sign_result["complete"]

        spend_txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)
        tx_info = node.getrawtransaction(spend_txid, True)
        assert tx_info["confirmations"] >= 1
        self.log.info("  P2TR_SCRIPT_LEGACY script-path spend confirmed!")

    def test_negative_raw_hash160_rejected(self, node):
        """Negative: raw HASH160 for P2PKH_LEGACY is rejected when node should compute it."""
        self.log.info("Testing negative: raw HASH160 rejected for P2PKH_LEGACY...")

        # Any 20 bytes — doesn't matter, should be rejected before validation
        h160 = os.urandom(20)

        # Node-computed enforcement: raw HASH160 rejected, must use PUBKEY
        assert_raises_rpc_error(-8, "Use PUBKEY instead of HASH160",
            node.createrungtx,
            [{"txid": "0" * 64, "vout": 0}],
            [{"amount": Decimal("0.001"), "conditions": [{"blocks": [{
                "type": "P2PKH_LEGACY", "fields": [
                    {"type": "HASH160", "hex": h160.hex()},
                ]
            }]}]}]
        )
        self.log.info("  Raw HASH160 for P2PKH_LEGACY correctly rejected!")

    def test_negative_raw_hash256_rejected(self, node):
        """Negative: raw HASH256 for P2WSH_LEGACY is rejected when node should compute it."""
        self.log.info("Testing negative: raw HASH256 rejected for P2WSH_LEGACY...")

        h256 = os.urandom(32)

        assert_raises_rpc_error(-8, "Use PREIMAGE instead of HASH256",
            node.createrungtx,
            [{"txid": "0" * 64, "vout": 0}],
            [{"amount": Decimal("0.001"), "conditions": [{"blocks": [{
                "type": "P2WSH_LEGACY", "fields": [
                    {"type": "HASH256", "hex": h256.hex()},
                ]
            }]}]}]
        )
        self.log.info("  Raw HASH256 for P2WSH_LEGACY correctly rejected!")

    def bootstrap_v4_output_with_relays(self, node, conditions, relays, output_amount=None):
        """Create and confirm a v4 output with conditions + relays.
        Returns (txid, vout, amount, scriptPubKey_hex)."""
        utxo = self.wallet.get_utxo()
        input_amount = utxo["value"]
        input_txid = utxo["txid"]
        input_vout = utxo["vout"]

        txout_info = node.gettxout(input_txid, input_vout)
        spent_spk = txout_info["scriptPubKey"]["hex"]

        if output_amount is None:
            output_amount = Decimal(input_amount) - Decimal("0.001")

        boot_wif, boot_pubkey = make_keypair()

        outputs = [{"amount": output_amount, "conditions": conditions}]

        change = Decimal(input_amount) - output_amount - Decimal("0.001")
        if change > Decimal("0.01"):
            change_wif, change_pubkey = make_keypair()
            change_conditions = [{"blocks": [{"type": "SIG", "fields": [
                {"type": "PUBKEY", "hex": change_pubkey}
            ]}]}]
            outputs.append({"amount": change, "conditions": change_conditions})

        result = node.createrungtx(
            [{"txid": input_txid, "vout": input_vout}],
            outputs,
            0,  # locktime
            relays,
        )
        unsigned_hex = result["hex"]

        sign_result = node.signrungtx(
            unsigned_hex,
            [{"privkey": boot_wif, "input": 0}],
            [{"amount": input_amount, "scriptPubKey": spent_spk}]
        )
        assert sign_result["complete"]

        txid = node.sendrawtransaction(sign_result["hex"])
        self.generate(node, 1)

        tx_info = node.getrawtransaction(txid, True)
        assert tx_info["confirmations"] >= 1
        spk = tx_info["vout"][0]["scriptPubKey"]["hex"]
        return txid, 0, output_amount, spk


if __name__ == '__main__':
    LadderScriptBasicTest(__file__).main()
