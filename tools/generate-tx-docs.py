#!/usr/bin/env python3
"""
Generate transaction example documentation pages from test-results-full.json.
Reads preset definitions + decoded TX JSON, produces one HTML doc per preset.

Usage: python3 generate-tx-docs.py [--results PATH] [--outdir PATH] [--preset NAME] [--force]
"""

import json, sys, os, argparse, html, re, copy

RESULTS_PATH = "/home/defenwycke/dev/projects/ghost-labs-ladder-script/tools/test-results-full.json"
OUT_DIR = "/home/defenwycke/dev/projects/ghost-labs-ladder-script/tools/docs/txs"

# ═══════════════════════════════════════════════════════════════
# BLOCK FAMILY COLORS (matches ladder-engine)
# ═══════════════════════════════════════════════════════════════

BLOCK_FAMILY = {
    "SIG": "sig", "MULTISIG": "sig", "COMPACT_SIG": "sig",
    "MUSIG_THRESHOLD": "sig", "TIMELOCKED_SIG": "sig",
    "TIMELOCKED_MULTISIG": "sig", "CLTV_SIG": "sig",
    "ADAPTOR_SIG": "adaptor", "PTLC": "adaptor",
    "HASH_PREIMAGE": "hash", "HASH160_PREIMAGE": "hash",
    "TAGGED_HASH": "hash", "CTV": "hash", "COSIGN": "hash",
    "HTLC": "hash", "HASH_SIG": "hash",
    "CSV": "time", "CSV_TIME": "time", "CLTV": "time", "CLTV_TIME": "time",
    "COMPARE": "plc", "SEQUENCER": "plc", "ONE_SHOT": "plc",
    "LATCH_SET": "plc", "LATCH_RESET": "plc",
    "COUNTER_DOWN": "plc", "COUNTER_UP": "plc", "COUNTER_PRESET": "plc",
    "TIMER_CONTINUOUS": "plc", "TIMER_OFF_DELAY": "plc",
    "RATE_LIMIT": "plc", "EPOCH_GATE": "plc",
    "HYSTERESIS_FEE": "plc", "HYSTERESIS_VALUE": "plc",
    "AMOUNT_LOCK": "cov", "VAULT_LOCK": "cov",
    "RECURSE_SAME": "rec", "RECURSE_MODIFIED": "rec",
    "RECURSE_UNTIL": "rec", "RECURSE_COUNT": "rec",
    "RECURSE_SPLIT": "rec", "RECURSE_DECAY": "rec",
    "ANCHOR": "anchor", "ANCHOR_CHANNEL": "anchor",
    "ANCHOR_POOL": "anchor", "ANCHOR_RESERVE": "anchor",
    "ANCHOR_SEAL": "anchor", "ANCHOR_ORACLE": "anchor",
    "WEIGHT_LIMIT": "val", "INPUT_COUNT": "val",
    "OUTPUT_COUNT": "val", "RELATIVE_VALUE": "val",
    "ACCUMULATOR": "val", "KEY_REF_SIG": "val",
}

FAMILY_COLORS = {
    "sig":     ("#e6a817", "rgba(230, 168, 23, 0.08)", "rgba(230, 168, 23, 0.2)"),
    "adaptor": ("#ff6b9d", "rgba(255, 107, 157, 0.08)", "rgba(255, 107, 157, 0.2)"),
    "hash":    ("#00d4ff", "rgba(0, 212, 255, 0.08)", "rgba(0, 212, 255, 0.2)"),
    "time":    ("#f7931a", "rgba(247, 147, 26, 0.08)", "rgba(247, 147, 26, 0.2)"),
    "plc":     ("#a855f7", "rgba(168, 85, 247, 0.08)", "rgba(168, 85, 247, 0.2)"),
    "cov":     ("#00d4ff", "rgba(0, 212, 255, 0.08)", "rgba(0, 212, 255, 0.2)"),
    "rec":     ("#e6a817", "rgba(230, 168, 23, 0.08)", "rgba(230, 168, 23, 0.2)"),
    "anchor":  ("#00ff88", "rgba(0, 255, 136, 0.08)", "rgba(0, 255, 136, 0.2)"),
    "val":     ("#888888", "rgba(136, 136, 136, 0.08)", "rgba(136, 136, 136, 0.2)"),
}

FAMILY_WITNESS_COLOR = {
    "sig": ("w-sig", "#00ff88"), "adaptor": ("w-adaptor", "#ff6b9d"),
    "hash": ("w-hash", "#00d4ff"), "time": ("w-time", "#f7931a"),
    "plc": ("w-plc", "#a855f7"), "cov": ("w-cov", "#00d4ff"),
    "rec": ("w-rec", "#e6a817"), "anchor": ("w-anchor", "#00ff88"),
    "val": ("w-val", "#888"), "overhead": ("w-overhead", "#4a4a4a"),
    "pubkey": ("w-pubkey", "#f7931a"), "signature": ("w-sig", "#00ff88"),
}

BLOCK_SHORT = {
    "TIMER_CONTINUOUS": "TMR_CONT", "TIMER_OFF_DELAY": "TMR_OFF",
    "COUNTER_UP": "CTR_UP", "COUNTER_DOWN": "CTR_DOWN", "COUNTER_PRESET": "CTR_PRE",
    "HYSTERESIS_FEE": "HYST_FEE", "HYSTERESIS_VALUE": "HYST_VAL",
    "RECURSE_SAME": "REC_SAME", "RECURSE_MODIFIED": "REC_MOD",
    "RECURSE_UNTIL": "REC_UNTIL", "RECURSE_COUNT": "REC_CNT",
    "RECURSE_SPLIT": "REC_SPLIT", "RECURSE_DECAY": "REC_DECAY",
    "HASH_PREIMAGE": "HASH_PRE", "HASH160_PREIMAGE": "H160_PRE",
    "TIMELOCKED_SIG": "TL_SIG", "TIMELOCKED_MULTISIG": "TL_MSIG",
    "ANCHOR_CHANNEL": "A_CHAN", "ANCHOR_POOL": "A_POOL",
    "ANCHOR_RESERVE": "A_RSRV", "ANCHOR_SEAL": "A_SEAL",
    "ANCHOR_ORACLE": "A_ORACLE", "MUSIG_THRESHOLD": "MUSIG_THR",
    "ADAPTOR_SIG": "ADAPTOR", "AMOUNT_LOCK": "AMT_LOCK",
    "VAULT_LOCK": "VAULT", "EPOCH_GATE": "EPOCH",
    "WEIGHT_LIMIT": "WT_LIM", "INPUT_COUNT": "IN_CNT",
    "OUTPUT_COUNT": "OUT_CNT", "RELATIVE_VALUE": "REL_VAL",
    "RATE_LIMIT": "RATE_LIM", "KEY_REF_SIG": "KEY_REF",
    "TAGGED_HASH": "TAG_HASH", "CLTV_SIG": "CLTV_SIG",
    "CLTV_TIME": "CLTV_TIME", "CSV_TIME": "CSV_TIME",
    "HASH_SIG": "HASH_SIG", "ONE_SHOT": "1SHOT",
    "LATCH_SET": "LATCH_S", "LATCH_RESET": "LATCH_R",
}

# Type code hex values
BLOCK_TYPE_CODES = {
    "SIG": "0x00", "MULTISIG": "0x01", "ADAPTOR_SIG": "0x03",
    "MUSIG_THRESHOLD": "0x04", "TIMELOCKED_SIG": "0x2A",
    "TIMELOCKED_MULTISIG": "0x2B", "CLTV_SIG": "0x2C",
    "CSV": "0x03", "CSV_TIME": "0x04", "CLTV": "0x05", "CLTV_TIME": "0x06",
    "HASH_PREIMAGE": "0x07", "HASH160_PREIMAGE": "0x08", "TAGGED_HASH": "0x09",
    "CTV": "0x0A", "VAULT_LOCK": "0x0B", "AMOUNT_LOCK": "0x0C",
    "RECURSE_SAME": "0x0D", "RECURSE_MODIFIED": "0x0E", "RECURSE_UNTIL": "0x0F",
    "RECURSE_COUNT": "0x10", "RECURSE_SPLIT": "0x11", "RECURSE_DECAY": "0x12",
    "COMPARE": "0x14", "SEQUENCER": "0x15", "ONE_SHOT": "0x16",
    "LATCH_SET": "0x1D", "LATCH_RESET": "0x1E",
    "COUNTER_DOWN": "0x1B", "COUNTER_UP": "0x1C", "COUNTER_PRESET": "0x1F",
    "TIMER_CONTINUOUS": "0x20", "TIMER_OFF_DELAY": "0x21",
    "RATE_LIMIT": "0x22", "EPOCH_GATE": "0x23",
    "HYSTERESIS_FEE": "0x24", "HYSTERESIS_VALUE": "0x25",
    "HTLC": "0x28", "HASH_SIG": "0x29", "PTLC": "0x2D",
    "COSIGN": "0x13", "ANCHOR": "0x17", "ANCHOR_CHANNEL": "0x18",
    "ANCHOR_POOL": "0x19", "ANCHOR_RESERVE": "0x1A",
    "ANCHOR_SEAL": "0x26", "ANCHOR_ORACLE": "0x27",
    "WEIGHT_LIMIT": "0x2E", "INPUT_COUNT": "0x2F",
    "OUTPUT_COUNT": "0x30", "RELATIVE_VALUE": "0x31",
    "ACCUMULATOR": "0x32", "KEY_REF_SIG": "0x33",
}

# Witness bytes contributed per block type (approximate)
BLOCK_WITNESS_BYTES = {
    "SIG": [("pubkey", 33), ("signature", 64)],
    "MULTISIG": [],  # variable
    "ADAPTOR_SIG": [("pubkey", 33), ("signature", 64)],
    "MUSIG_THRESHOLD": [("pubkey", 33), ("signature", 64)],
    "TIMELOCKED_SIG": [("pubkey", 33), ("signature", 64)],
    "TIMELOCKED_MULTISIG": [],
    "CLTV_SIG": [("pubkey", 33), ("signature", 64)],
    "HASH_PREIMAGE": [("hash", 32)],
    "HASH160_PREIMAGE": [("hash", 20)],
    "TAGGED_HASH": [("hash", 32)],
    "HTLC": [("pubkey", 33), ("signature", 64), ("hash", 32)],
    "HASH_SIG": [("pubkey", 33), ("signature", 64), ("hash", 32)],
    "PTLC": [("pubkey", 33), ("signature", 64)],
    "VAULT_LOCK": [("pubkey", 33), ("signature", 64)],
    "ACCUMULATOR": [("hash", 32), ("hash", 32)],
}

# ═══════════════════════════════════════════════════════════════
# PER-PRESET EDITORIAL CONTENT
# ═══════════════════════════════════════════════════════════════

PRESET_DESC = {
    "2-of-3 MULTISIG VAULT": {
        "subtitle": "Multi-output vault pattern using the MULTISIG block type. A v4 RUNG_TX creates three outputs: a 2-of-3 threshold multisig for primary spending, a timelocked single-key recovery path (CSV), and change. The spend demonstrates satisfying the 2-of-3 threshold with two Schnorr signatures.",
        "category": "SIGNATURE",
        "rung_desc": "Two rungs define the spending paths: SPEND requires any 2-of-3 keyholders, RECOVER uses CSV + single-key recovery.",
        "output_labels": ["PRIMARY SPEND", "RECOVERY", "CHANGE"],
        "spend_path": "2-of-3 Path",
        "how_it_works": [
            "Funding transaction creates three outputs. Vout 0 carries <span class=\"eval-keyword\">rung_conditions</span> with a single MULTISIG block: NUMERIC threshold = 2, three PUBKEY_COMMITs, and SCHEME = SCHNORR.",
            "To spend, 2 of the 3 keyholders construct a transaction. The ladder witness contains paired PUBKEY + SIGNATURE fields for each signer.",
            "The evaluator reads the threshold (2) from the conditions, then validates each pubkey against the PUBKEY_COMMITs and each signature against the Ladder sighash. 2 valid signatures from distinct committed keys &ge; threshold. <span class=\"eval-result-sat\">SATISFIED</span>.",
            "Vout 1 provides a recovery path: after a CSV delay, key 1 alone can sweep. This is a separate UTXO, not an alternative rung &mdash; funds are split at funding time.",
        ],
        "comparison": {
            "headers": ["Approach", "Threshold", "Key Privacy", "On-chain Cost"],
            "highlight": "Ladder MULTISIG",
            "rows": [
                ["Ladder MULTISIG", "M-of-N, single block", "PUBKEY_COMMIT (32B each)", "~310 vB fund, ~160 vB spend"],
                ["P2SH Multisig", "OP_CHECKMULTISIG", "Keys in redeemScript", "~370 vB spend"],
                ["Taproot MuSig2", "N-of-N key path", "Single aggregate key", "~111 vB spend"],
            ],
        },
    },
    "ATOMIC SWAP (HTLC)": {
        "subtitle": "Hash time-locked contract for trustless atomic swaps. The claim rung combines hash preimage verification with signature authorization and CSV-locked timeout. Atomic: if Alice reveals the preimage on one chain, Bob can claim on the other.",
        "category": "HASH + TIMELOCK",
        "rung_desc": "Two rungs: CLAIM requires hash preimage + signature + CSV timelock, REFUND uses CSV-locked signature recovery.",
        "output_labels": ["CLAIM PATH", "REFUND PATH", "CHANGE"],
        "spend_path": "Claim Path",
        "how_it_works": [
            "The funding TX creates outputs with HTLC conditions. The HTLC block combines a SHA-256 hash lock, a signature requirement, and a CSV relative timelock into a single block type.",
            "To claim, the recipient provides the hash preimage and a valid signature. The evaluator checks: SHA256(preimage) matches the committed hash, signature is valid, and sequence satisfies CSV.",
            "If the claim window passes, the sender can recover via the refund path using their own key after the CSV timeout.",
            "Cross-chain atomicity: the preimage revealed in the claim transaction on one chain can be used to claim the counterparty's HTLC on the other chain.",
        ],
        "comparison": {
            "headers": ["Approach", "Atomicity", "Privacy", "On-chain Cost"],
            "highlight": "Ladder HTLC",
            "rows": [
                ["Ladder HTLC", "Hash-locked", "Preimage links chains", "~200 vB spend"],
                ["Bitcoin Script HTLC", "OP_SHA256 + CLTV", "Same preimage link", "~300 vB spend"],
                ["Submarine Swap", "Lightning + on-chain", "Hash-locked", "~250 vB"],
            ],
        },
    },
    "ADAPTOR SIG SWAP": {
        "subtitle": "Schnorr adaptor signature atomic swap. The execute rung uses an adaptor signature that reveals the adaptor secret on-chain when the adapted signature is published. The cancel rung provides CSV-locked dual-signature recovery.",
        "category": "ADAPTOR SIGNATURE",
        "rung_desc": "Two rungs: EXECUTE uses adaptor signature (reveals secret on claim), CANCEL uses CSV-delayed dual-signature for timeout recovery.",
        "output_labels": ["EXECUTE", "CANCEL", "CHANGE"],
        "spend_path": "Execute Path",
        "how_it_works": [
            "The funding TX creates an ADAPTOR_SIG condition with the signing key and adaptor point. The adaptor point encodes a secret that will be revealed when the adapted signature is published on-chain.",
            "To execute the swap, the claimer adapts a pre-signature with the secret and publishes it. The evaluator verifies the adapted Schnorr signature against the signing key.",
            "Once the adapted signature is on-chain, the counterparty extracts the adaptor secret by comparing the pre-signature with the published signature (s_adapted - s_pre = secret).",
            "If the swap stalls, the cancel rung activates after the CSV timeout, requiring both parties' signatures to recover.",
        ],
        "comparison": {
            "headers": ["Approach", "Privacy", "Secret Mechanism", "On-chain Cost"],
            "highlight": "Ladder Adaptor Sig",
            "rows": [
                ["Ladder Adaptor Sig", "No hash link between chains", "Adaptor point extraction", "~200 vB spend"],
                ["HTLC Swap", "Hash links both chains", "Preimage revelation", "~250 vB spend"],
                ["Scriptless Script", "Same adaptor technique", "Off-chain coordination", "~111 vB (Taproot)"],
            ],
        },
    },
    "DCA COVENANT CHAIN": {
        "subtitle": "Dollar-cost averaging covenant. Each spend peels off a fixed payment and recursively re-encumbers the remainder. AMOUNT_LOCK enforces consistent payment size. RECURSE_MODIFIED increments a counter tracking completed purchases. The covenant chain self-terminates when the recursion depth is exhausted.",
        "category": "COVENANT + RECURSION",
        "rung_desc": "Three rungs: DCA makes the periodic payment (amount-locked + recursive), SKIP lets the owner defer a payment, and CANCEL exits the covenant entirely.",
        "output_labels": ["DCA PAYMENT", "SKIP", "CANCEL", "CHANGE"],
        "spend_path": "DCA Payment",
        "how_it_works": [
            "The funding TX encodes a DCA rung with SIG + AMOUNT_LOCK + COUNTER_UP + RECURSE_MODIFIED. The AMOUNT_LOCK constrains each payment output to a fixed range.",
            "Each DCA spend creates a payment output (fixed amount) and a carry-forward output with identical conditions but the counter incremented via RECURSE_MODIFIED.",
            "The mutation target is the COUNTER_UP block's <code>current</code> field. Each spend increments it by <code>delta</code>. When <code>current = target</code>, the covenant terminates naturally.",
            "The SKIP and CANCEL rungs provide escape valves: SKIP re-encumbers without payment, CANCEL requires a second signature and exits the covenant.",
        ],
    },
    "VAULT WITH UNVAULT + CLAWBACK": {
        "subtitle": "Bitcoin vault pattern using the VAULT_LOCK block type. A v4 RUNG_TX creates a 2-path output: the hot key can spend after a CSV relative delay (unvault path), while the recovery key can sweep immediately (clawback path). The delay gives the owner time to detect and claw back unauthorized spends.",
        "category": "VAULT",
        "rung_desc": "Two rungs encode the spending paths. UNVAULT uses the hot key with a CSV delay. CLAWBACK uses the recovery key with no delay &mdash; immediate recovery.",
        "output_labels": ["HOT_SPEND", "COLD_CLAWBACK", "CHANGE"],
        "spend_path": "Unvault Path",
        "how_it_works": [
            "The VAULT_LOCK block is self-contained: it commits both the hot key and recovery key PUBKEY_COMMITs, plus a numeric delay (CSV blocks). One block encodes both spend paths.",
            "Evaluator hot-key path: verify hot key signature, enforce nSequence &ge; delay (BIP-68 relative timelock). This gives the owner a time window to detect unauthorized access.",
            "Evaluator recovery path: verify recovery key signature, no timelock required. The cold key can sweep immediately, acting as a clawback if the hot key is compromised.",
            "The vault spends by mining enough blocks to satisfy the CSV delay, then signing with the hot key. In production, the watchtower monitors for unauthorized unvault attempts during the delay window.",
        ],
        "comparison": {
            "headers": ["Approach", "Clawback", "Delay Mechanism", "On-chain Cost"],
            "highlight": "Ladder VAULT_LOCK",
            "rows": [
                ["Ladder VAULT_LOCK", "Immediate cold key", "CSV (BIP-68)", "~170 vB spend"],
                ["OP_VAULT (BIP-345)", "OP_VAULT_RECOVER", "OP_CHECKTEMPLATEVERIFY", "Not yet activated"],
                ["2-of-3 Multisig", "2 keys override", "Manual intervention", "~370 vB spend"],
            ],
        },
    },
    "RATE-LIMITED WALLET": {
        "subtitle": "Wallet with per-block spend rate limiting. The RATE_LIMIT block constrains how much value can be sent in a single block, protecting against rapid drainage. Spend output is split: payment within the rate limit, carry-forward with same conditions.",
        "category": "PLC + RATE LIMITING",
        "rung_desc": "Single rung with SIG + RATE_LIMIT. The rate limit constrains the maximum output amount per block.",
        "output_labels": ["RATE_LIMITED", "CHANGE"],
        "spend_path": "Rate-Limited Spend",
        "how_it_works": [
            "The funding TX encodes a RATE_LIMIT block with <code>max_per_block</code>, <code>acc_cap</code>, and <code>refill_blocks</code> parameters. The evaluator checks that vout[0] value does not exceed <code>max_per_block</code>.",
            "Each spend produces two outputs: a payment within the rate limit sent to a fresh address, and a carry-forward output re-encumbered with the same conditions.",
            "The rate limit is enforced at consensus: the evaluator reads the spending transaction's vout[0].nValue and compares against max_per_block. If exceeded, the block is <span class=\"eval-result-unsat\">UNSATISFIED</span>.",
            "This creates a throttled wallet where even a compromised key cannot drain funds faster than the rate limit allows, giving the owner time to respond.",
        ],
    },
    "DEAD MAN'S SWITCH (INHERITANCE)": {
        "subtitle": "Bitcoin inheritance pattern using RECURSE_SAME + LATCH_SET. The owner must periodically sign a keepalive transaction to maintain control. Each spend re-encumbers the output with identical conditions via RECURSE_SAME, resetting the CSV clock. If the owner fails to sign within the timeout window, the heir can claim via the INHERIT path.",
        "category": "COVENANT",
        "rung_desc": "Two outputs with separate paths. ALIVE: owner keepalive with recursive covenant (SIG + LATCH_SET + RECURSE_SAME). INHERIT: heir claim path (CSV + SIG) on separate output.",
        "output_labels": ["KEEPALIVE", "HEIR_CLAIM", "CHANGE"],
        "spend_path": "Keepalive",
        "how_it_works": [
            "Funding TX creates two outputs. Vout 0 (ALIVE) has SIG + LATCH_SET (state=0) + RECURSE_SAME (max_depth=10). Vout 1 (INHERIT) has CSV (~6 months) + SIG (heir).",
            "The owner proves they're alive by spending vout 0 with a valid signature. RECURSE_SAME enforces the spending output carries byte-identical conditions &mdash; the covenant loop.",
            "Each keepalive resets the relative timeout on the INHERIT output. As long as the owner keeps spending within the CSV window, the heir cannot claim.",
            "If the owner fails to sign within the CSV window, the heir satisfies vout 1 by waiting out the lock and providing their signature. The INHERIT path has no recursion &mdash; it spends freely.",
        ],
        "comparison": {
            "headers": ["Approach", "Keepalive Mechanism", "Inheritance Trigger", "Complexity"],
            "highlight": "Ladder Dead Man's Switch",
            "rows": [
                ["Ladder Dead Man's Switch", "RECURSE_SAME carry-forward", "CSV timeout (trustless)", "3 block types"],
                ["Multisig + Timelock", "Sweep to new UTXO", "nLockTime expiry", "Script complexity"],
                ["Custodial Inheritance", "Login activity tracking", "Inactivity period", "Trust required"],
            ],
        },
    },
    "ESCROW WITH ORACLE": {
        "subtitle": "Three-party escrow with oracle arbitration. Three spend paths: buyer+seller agree (cooperative), buyer+oracle resolve (dispute favoring buyer), or seller+oracle resolve (dispute favoring seller). Any 2-of-3 parties can release funds.",
        "category": "MULTISIG + ESCROW",
        "rung_desc": "Three rungs represent the three resolution paths. AGREE: buyer+seller cooperative close. BUYER_WIN: buyer+oracle dispute resolution. SELLER_WIN: seller+oracle dispute resolution.",
        "output_labels": ["AGREE", "BUYER_WIN", "SELLER_WIN", "CHANGE"],
        "spend_path": "Cooperative Close",
        "how_it_works": [
            "Three rungs on the same output encode the three escrow resolution paths. Each rung requires two SIG blocks from different parties.",
            "The cooperative AGREE path (buyer+seller) is the happy path &mdash; both parties sign to release funds without oracle involvement.",
            "In a dispute, the oracle acts as tiebreaker. BUYER_WIN requires buyer+oracle signatures; SELLER_WIN requires seller+oracle signatures.",
            "The oracle never has unilateral control &mdash; it always needs one party's agreement. This is structurally identical to 2-of-3 multisig but with labeled paths for clarity.",
        ],
    },
    "PAYMENT CHANNEL": {
        "subtitle": "Bidirectional payment channel with cooperative close and unilateral exit paths. The cooperative path is a simple 2-of-2 multisig. Unilateral paths use CSV-locked signatures for timeout-based dispute resolution.",
        "category": "PAYMENT CHANNEL",
        "rung_desc": "Three rungs: COOP (2 SIG blocks for cooperative close), ALICE (CSV-delayed unilateral exit for Alice), BOB (CSV-delayed unilateral exit for Bob).",
        "output_labels": ["COOP_CLOSE", "ALICE_EXIT", "BOB_EXIT", "CHANGE"],
        "spend_path": "Cooperative Close",
        "how_it_works": [
            "The funding TX creates outputs with three spending paths. The cooperative rung requires both Alice and Bob's signatures &mdash; simple and cheap.",
            "If cooperation fails, either party can force-close after the CSV delay. The delay prevents instant theft by giving the counterparty time to submit a more recent state.",
            "Each unilateral exit path has its own CSV timeout. The party initiating the close must wait; the counterparty can respond immediately during the delay window.",
            "State updates happen off-chain by pre-signing new commitment transactions. Only the final state is broadcast &mdash; the channel can handle thousands of off-chain payments.",
        ],
    },
    "SEQUENCED PAYOUT": {
        "subtitle": "Multi-stage payout with sequencer-enforced ordering. Each rung represents a payout stage. The SEQUENCER block tracks which stage is current and only allows spending the correct stage in order.",
        "category": "PLC + SEQUENCING",
        "rung_desc": "Three sequenced rungs, each with SIG + SEQUENCER. The sequence counter ensures stages are spent in order: STAGE1 (current=0), STAGE2 (current=1), STAGE3 (current=2).",
        "output_labels": ["STAGE_1", "STAGE_2", "STAGE_3", "CHANGE"],
        "spend_path": "Stage 1",
        "how_it_works": [
            "The funding TX encodes three rungs with SEQUENCER blocks at different <code>current</code> values (0, 1, 2). Each rung also requires a SIG for authorization.",
            "The SEQUENCER evaluator checks <code>current == expected_stage</code>. Only the rung with the matching sequence number can be spent. This enforces strict ordering.",
            "After spending stage 0, only stage 1 becomes valid. After stage 1, only stage 2. This creates a deterministic payout schedule that cannot be reordered.",
            "Unlike timelocks which only enforce minimum wait times, the sequencer enforces strict ordering &mdash; you can't skip ahead or go backwards.",
        ],
    },
    "FEE-GATED COVENANT": {
        "subtitle": "Covenant with fee-rate hysteresis gating. The spend is only valid when network fee rates fall within a specified band, preventing execution during fee spikes. Combines HYSTERESIS_FEE with SIG and RECURSE_SAME.",
        "category": "PLC + COVENANT",
        "rung_desc": "Single rung with SIG + HYSTERESIS_FEE + RECURSE_SAME. The fee hysteresis band constrains when the covenant can be advanced.",
        "output_labels": ["FEE_GATED", "CHANGE"],
        "spend_path": "Fee-Gated Spend",
        "how_it_works": [
            "The HYSTERESIS_FEE block defines a fee-rate band with <code>high_sat_vb</code> and <code>low_sat_vb</code> bounds. The evaluator checks the transaction's effective fee rate falls within this band.",
            "RECURSE_SAME enforces the carry-forward covenant &mdash; the output conditions are byte-identical, re-encumbering with the same fee gate.",
            "This pattern is useful for automated covenant chains that should only advance during low-fee periods, optimizing on-chain costs.",
            "If fees are outside the band, the rung is <span class=\"eval-result-unsat\">UNSATISFIED</span> and the spend is rejected. The user must wait for fees to enter the acceptable range.",
        ],
    },
    "ONE-SHOT TRIGGER + LATCH": {
        "subtitle": "State machine with one-shot trigger and latch. The one-shot fires once to set the latch, which then enables a second spend path. The latch can be reset by an authorized key after a delay. Demonstrates programmable state transitions.",
        "category": "PLC + STATE MACHINE",
        "rung_desc": "Three rungs model a state machine: TRIGGER (ONE_SHOT + SIG + LATCH_SET), ARMED (SIG when latch is set), RESET (LATCH_RESET + SIG with CSV delay).",
        "output_labels": ["TRIGGER", "ARMED", "RESET", "CHANGE"],
        "spend_path": "Trigger",
        "how_it_works": [
            "The funding TX encodes a state machine with three paths. TRIGGER combines ONE_SHOT (fires once), LATCH_SET (sets state), and SIG (authorization).",
            "ONE_SHOT evaluates: if <code>state == 0</code>, SATISFIED (can fire). After firing, the state transitions to 1, locking the trigger permanently.",
            "LATCH_SET checks <code>state == 0</code> as a precondition, then transitions state. Once the latch is set, the ARMED rung becomes spendable for the authorized key.",
            "LATCH_RESET provides a recovery path: after a CSV delay, an authorized key can reset the latch back to state 0, re-enabling the trigger. This creates a reusable state machine.",
        ],
    },
    "RECURSIVE SPLIT (TREE)": {
        "subtitle": "Binary split covenant: a UTXO splits into 2 equal children on each spend. Each child inherits the same rung conditions with <code>max_splits</code> decremented. When splits are exhausted, the UTXO becomes freely spendable. Creates an on-chain binary tree of UTXOs.",
        "category": "RECURSION + SPLIT",
        "rung_desc": "Single rung with SIG + RECURSE_SPLIT. Each spend produces two child UTXOs with identical conditions and decremented split counter.",
        "output_labels": ["SPLIT_ROOT", "CHANGE"],
        "spend_path": "Binary Split",
        "how_it_works": [
            "The funding TX encodes a RECURSE_SPLIT block with <code>max_splits</code> and <code>min_sats</code>. The evaluator requires the spending TX to produce exactly 2 outputs with the same conditions.",
            "Each child output inherits byte-identical conditions except <code>max_splits</code> is decremented by 1. When <code>max_splits</code> reaches 0, the UTXO is freely spendable (no covenant).",
            "The <code>min_sats</code> parameter prevents dust outputs &mdash; each child must carry at least this amount. The split divides the UTXO roughly in half.",
            "With max_splits=3, the tree expands: 1 &rarr; 2 &rarr; 4 &rarr; 8 UTXOs. This pattern enables mass distribution from a single funding transaction.",
        ],
    },
    "BLOCK-HEIGHT TIMELOCK + COMPARE": {
        "subtitle": "CLTV block-height timelock combined with a COMPARE block for range validation. Funds are locked until a specific block height. The COMPARE block adds an additional numeric comparison constraint, demonstrating composed programmable logic.",
        "category": "TIMELOCK + PLC",
        "rung_desc": "Single rung with CLTV (height lock) + SIG (authorization) + COMPARE (range check). All three blocks must be SATISFIED to spend.",
        "output_labels": ["LOCKED", "CHANGE"],
        "spend_path": "Timelock Spend (Dry Run)",
        "how_it_works": [
            "The CLTV block checks that the transaction's nLockTime is &ge; the committed block height. If the current chain height is below this, the block is <span class=\"eval-result-unsat\">UNSATISFIED</span>.",
            "The COMPARE block performs a numeric comparison: operator determines the comparison type (EQ, LT, GT, etc.), and value_b/value_c are the operands.",
            "SIG provides authorization &mdash; even after the timelock expires, a valid signature is still required to spend.",
            "This is a dry-run example: the CLTV height is set far in the future (unreachable on regtest), so the transaction is funded and signed but not broadcast.",
        ],
    },
    "COUNTER-UP SUBSCRIPTION": {
        "subtitle": "Recurring subscription covenant: a counter increments on each payment (max N). The UTXO is amount-locked to a fixed payment size and auto-renews via RECURSE_MODIFIED. Three spend paths: PAY (increment counter), CANCEL (2-of-2 multisig), EXPIRE (counter reached target).",
        "category": "PLC + RECURSION",
        "rung_desc": "Three rungs: PAY (SIG + CTR_UP + AMT_LOCK + REC_MOD), CANCEL (dual SIG cooperative exit), EXPIRE (CTR_UP at target + SIG for final withdrawal).",
        "output_labels": ["PAYMENT", "CANCEL_SUB", "SUB_END", "CHANGE"],
        "spend_path": "Payment #1",
        "how_it_works": [
            "The PAY rung enforces subscription logic: SIG authorizes, COUNTER_UP tracks payments (0/24), AMOUNT_LOCK constrains output to fixed range, RECURSE_MODIFIED increments the counter.",
            "Each PAY spend creates a carry-forward output with identical conditions except the counter's <code>current</code> field is incremented by <code>delta</code> via RECURSE_MODIFIED.",
            "AMOUNT_LOCK constrains the output to exactly min=max sats, ensuring each payment is a fixed amount. The fee comes from the surplus funded above the lock.",
            "After 24 payments, <code>current = target = 24</code>. COUNTER_UP becomes <span class=\"eval-result-unsat\">UNSATISFIED</span>, locking PAY. The EXPIRE rung (requires counter at target) becomes spendable.",
        ],
    },
    "QUANTUM-SAFE VAULT": {
        "subtitle": "Post-quantum vault using Dilithium3 lattice-based signatures. Same spend logic as a standard vault but with quantum-resistant key material. Demonstrates that Ladder Script's PQ support is transparent &mdash; same block types, different SCHEME.",
        "category": "POST-QUANTUM",
        "rung_desc": "Two rungs: SPEND (VAULT_LOCK with Dilithium3 keys) and RECOVER (CSV + SIG with Dilithium3). Same vault pattern, quantum-resistant keys.",
        "output_labels": ["HOT_SPEND", "COLD_RECOVERY", "CHANGE"],
        "spend_path": "Hot Key (Dilithium3)",
        "how_it_works": [
            "The funding TX uses SCHEME = DILITHIUM3 for all key operations. Dilithium3 keys are larger (~1,952 bytes public, ~4,000 bytes private) but the conditions only store 32-byte PUBKEY_COMMITs.",
            "VAULT_LOCK operates identically to the SCHNORR version: hot key path with CSV delay, recovery key path with no delay. The scheme is encoded in the coil.",
            "The witness is significantly larger (~3,300 bytes for Dilithium3 signatures vs 64 bytes for Schnorr), which increases the spend transaction size.",
            "PQ support is a scheme-level choice, not a structural change. The same VAULT_LOCK evaluator handles both classical and post-quantum signatures.",
        ],
    },
    "QUANTUM VAULT + CHILDREN": {
        "subtitle": "Post-quantum vault with recursive split producing child UTXOs. Each child inherits quantum-safe conditions. Demonstrates PQ signatures with covenant recursion.",
        "category": "POST-QUANTUM + RECURSION",
        "rung_desc": "Two rungs: SPEND (SIG + RECURSE_SPLIT with Dilithium3) and RECOVER (CSV + SIG with Dilithium3). The RECURSE_SPLIT creates child UTXOs inheriting PQ conditions.",
        "output_labels": ["SPLIT_ROOT", "RECOVERY", "CHANGE"],
        "spend_path": "Binary Split (Dilithium3)",
        "how_it_works": [
            "The funding TX encodes RECURSE_SPLIT with SCHEME = DILITHIUM3. The split logic is identical to the classical version &mdash; two children with decremented max_splits.",
            "Each child inherits the same PQ conditions. The Dilithium3 scheme propagates through the covenant chain automatically.",
            "The recover rung provides a CSV-locked escape path with the recovery key. This works identically to the classical vault recovery.",
            "This preset demonstrates that recursion covenants compose naturally with PQ signatures &mdash; no special handling needed.",
        ],
    },
    "MULTI-INPUT CONSOLIDATION": {
        "subtitle": "CTV-based input consolidation. Multiple inputs are merged into a single output whose template hash is committed at funding time. CheckTemplateVerify ensures the exact output structure &mdash; amount, scriptPubKey, and all transaction fields.",
        "category": "CTV + CONSOLIDATION",
        "rung_desc": "Single rung with SIG + CTV. The CTV block commits to the exact spending transaction template (BIP-119 hash of outputs, sequences, etc.).",
        "output_labels": ["CTV_OUTPUT", "CHANGE"],
        "spend_path": "Template Spend",
        "how_it_works": [
            "At funding time, the BIP-119 template hash is auto-computed: SHA256(version || locktime || scriptsigs_hash || num_inputs || sequences_hash || num_outputs || outputs_hash || input_index).",
            "The CTV block stores this 32-byte hash in conditions. At spend time, the evaluator recomputes the hash from the actual spending transaction and compares.",
            "If any field differs (different output amount, different scriptPubKey, different number of outputs), the hash won't match and the spend is <span class=\"eval-result-unsat\">UNSATISFIED</span>.",
            "This enables pre-committed transaction graphs: the exact spend structure is fixed at funding time, useful for congestion control, vaults, and batched payouts.",
        ],
    },
    "MUSIG_THRESHOLD TREASURY": {
        "subtitle": "Treasury secured by MuSig threshold signature. The aggregated public key represents an N-of-M group. Single compact signature on-chain regardless of group size. More efficient than MULTISIG for large groups.",
        "category": "MUSIG + THRESHOLD",
        "rung_desc": "Single rung with MUSIG_THRESHOLD. The block commits the aggregate public key, threshold, and group size.",
        "output_labels": ["TREASURY", "CHANGE"],
        "spend_path": "Threshold Spend",
        "how_it_works": [
            "The MUSIG_THRESHOLD block stores three fields: <code>agg_pubkey</code> (the aggregate public key), <code>threshold</code>, and <code>group_size</code>.",
            "Unlike MULTISIG which reveals M individual keys + signatures, MuSig produces a single aggregate signature. On-chain cost is constant regardless of group size.",
            "The evaluator verifies the single signature against the aggregate key. The threshold/group_size fields are informational &mdash; the cryptographic aggregation happens off-chain.",
            "This is ideal for DAO treasuries and large organizations where revealing individual signers is undesirable and on-chain costs must be minimized.",
        ],
    },
    "PTLC PAYMENT CHANNEL": {
        "subtitle": "Point time-locked contract payment channel. Uses adaptor point signatures instead of hash preimages for improved privacy. CSV-locked refund path for timeout. PTLCs are the privacy-preserving successor to HTLCs.",
        "category": "ADAPTOR + TIMELOCK",
        "rung_desc": "Two rungs: CLAIM (PTLC with adaptor point + signing key + CSV) and REFUND (CSV-delayed SIG recovery).",
        "output_labels": ["CLAIM", "REFUND", "CHANGE"],
        "spend_path": "Claim Path",
        "how_it_works": [
            "The PTLC block combines an adaptor point signature with a CSV timelock. Unlike HTLC, there's no hash preimage &mdash; the secret is extracted from the signature itself.",
            "To claim, the recipient adapts a pre-signature with the secret and publishes it. The evaluator verifies the adapted signature and checks the CSV timelock.",
            "Privacy advantage: PTLCs don't create a linkable hash across channels. Each hop uses a different adaptor point, preventing correlation of multi-hop payments.",
            "The refund path activates after the CSV timeout, allowing the sender to recover funds if the recipient fails to claim.",
        ],
    },
    "CLTV_SIG VESTING SCHEDULE": {
        "subtitle": "Vesting schedule with multiple CLTV-locked tranches. Each rung unlocks at a different block height, releasing funds on a predetermined schedule. Demonstrates time-gated progressive access to funds.",
        "category": "TIMELOCK + VESTING",
        "rung_desc": "Multiple CLTV_SIG rungs at different heights. Each rung combines CLTV (height lock) with SIG (authorization) in a single block type. Earlier tranches unlock first.",
        "output_labels": ["TRANCHE_1", "TRANCHE_2", "TRANCHE_3", "CHANGE"],
        "spend_path": "Vesting Spend (Dry Run)",
        "how_it_works": [
            "Each CLTV_SIG block combines a block-height lock with signature verification. The evaluator checks nLockTime &ge; committed height AND verifies the signature.",
            "Multiple rungs at different heights create a vesting schedule. Tranche 1 unlocks at height H1, tranche 2 at H2 > H1, etc.",
            "The recipient can only spend each tranche after its height is reached. This is enforced at consensus &mdash; no trusted third party needed.",
            "This is a dry-run example: the CLTV heights are set far in the future, so transactions are funded and signed but not broadcast.",
        ],
    },
    "TIMELOCKED_MULTISIG VAULT RECOVERY": {
        "subtitle": "Vault with primary multisig path and timelocked recovery. The primary path requires 2-of-3 multisig. The recovery path activates after a CSV delay with a single recovery key. Combines threshold security with time-delayed fallback.",
        "category": "MULTISIG + RECOVERY",
        "rung_desc": "Two rungs: SPEND (TIMELOCKED_MULTISIG with 2-of-3 threshold + CSV) and RECOVER (CSV-delayed SIG for single-key recovery).",
        "output_labels": ["PRIMARY", "RECOVERY", "CHANGE"],
        "spend_path": "Multisig Path",
        "how_it_works": [
            "TIMELOCKED_MULTISIG combines threshold multisig with CSV timelock in a single block. The evaluator checks: M valid signatures from N committed keys AND nSequence satisfies the CSV delay.",
            "The primary path uses 2-of-3 with a short CSV. This ensures funds can't be spent instantly even with a quorum &mdash; there's always a small delay for monitoring.",
            "The recovery path uses a longer CSV delay with a single key. If the multisig keys are lost, the recovery key can sweep after waiting out the timeout.",
            "The tiered timelock design ensures: fast access with multisig quorum (short delay), slow access with single recovery key (long delay).",
        ],
    },
    "HTLC COMPACT SWAP": {
        "subtitle": "Compact HTLC atomic swap. The claim path combines hash preimage verification with signature authorization and CSV timelock. The refund path uses a CSV-locked SIG. Functionally identical to ATOMIC SWAP but using the compact HTLC block type.",
        "category": "HASH + TIMELOCK",
        "rung_desc": "Two rungs: CLAIM (HTLC block = hash + sig + timelock in one) and REFUND (CSV + SIG).",
        "output_labels": ["CLAIM", "REFUND", "CHANGE"],
        "spend_path": "Claim Path",
        "how_it_works": [
            "The HTLC block packs three checks into one: SHA-256 hash preimage verification, Schnorr signature validation, and CSV relative timelock &mdash; all in a single block type.",
            "To claim, the recipient provides the preimage and signature. The evaluator verifies SHA256(preimage) matches the hash, validates the signature, and checks CSV.",
            "This is more compact than using separate HASH_PREIMAGE + SIG + CSV blocks. The HTLC type code encodes the combined semantics in fewer condition bytes.",
            "The refund path activates after the CSV timeout. The sender signs with their own key to recover funds if the recipient doesn't claim.",
        ],
    },
    "HASH_SIG ATOMIC CLAIM": {
        "subtitle": "Hash-locked signature claim. Combines SHA-256 preimage revelation with signature verification in a single block type. Simpler than HTLC when no timeout path is needed. Useful for atomic claims where the hash preimage is the secret being traded.",
        "category": "HASH + SIGNATURE",
        "rung_desc": "Single rung with HASH_SIG. The block combines hash preimage + signature verification. No timeout path &mdash; the hash preimage is the sole claim condition.",
        "output_labels": ["CLAIM", "CHANGE"],
        "spend_path": "Hash+Sig Claim",
        "how_it_works": [
            "HASH_SIG combines two checks in one block: SHA256(preimage) must match the committed hash AND the signature must be valid for the committed PUBKEY_COMMIT.",
            "Unlike HTLC, there's no CSV timelock component. This is a pure hash-locked claim &mdash; whoever has the preimage and the key can spend immediately.",
            "The witness provides three fields: the public key (33B), the Schnorr signature (64B), and the preimage (32B). Total witness overhead: ~129 bytes.",
            "Use this when you need atomic revelation of a secret (preimage) combined with authorization (signature) without time-based expiry.",
        ],
    },
    "GOVERNANCE-GATED TREASURY": {
        "subtitle": "Treasury with governance gating. The spend requires both a multisig quorum and an oracle attestation (via ANCHOR_ORACLE), ensuring off-chain governance approval before on-chain execution. Two-layer authorization: cryptographic + governance.",
        "category": "MULTISIG + ORACLE",
        "rung_desc": "Two rungs: APPROVE (MULTISIG + ANCHOR_ORACLE for governance-gated spending) and EMERGENCY (CSV-delayed SIG for emergency recovery).",
        "output_labels": ["GOVERNED", "EMERGENCY", "CHANGE"],
        "spend_path": "Governance Approval",
        "how_it_works": [
            "The APPROVE rung combines MULTISIG (threshold of treasury signers) with ANCHOR_ORACLE (oracle pubkey attestation). Both must be SATISFIED to spend.",
            "ANCHOR_ORACLE checks that the oracle has committed an attestation. This represents off-chain governance approval &mdash; the oracle only signs after a governance vote passes.",
            "The EMERGENCY rung provides a fallback: after a CSV delay, a single emergency key can sweep. This handles oracle failure or governance deadlock.",
            "Two-layer security: even if the multisig quorum is compromised, the oracle gate prevents unauthorized spending. And if the oracle is compromised, it still needs the multisig.",
        ],
    },
    "ACCUMULATOR ALLOWLIST": {
        "subtitle": "Merkle accumulator allowlist. The spend requires proving membership in a Merkle tree of authorized keys. Enables large allowlists with compact on-chain footprint &mdash; only the 32-byte root is stored in conditions.",
        "category": "ACCUMULATOR + SIGNATURE",
        "rung_desc": "Single rung with SIG + ACCUMULATOR. The ACCUMULATOR block stores the Merkle root; the witness provides a Merkle proof + leaf.",
        "output_labels": ["ALLOWLISTED", "CHANGE"],
        "spend_path": "Merkle Proof Spend",
        "how_it_works": [
            "The ACCUMULATOR block stores a 32-byte Merkle root computed from the set of authorized key hashes. The on-chain footprint is constant regardless of allowlist size.",
            "To spend, the witness provides: the Merkle proof (sibling hashes along the path) and the leaf (the spender's key hash). The evaluator reconstructs the root and compares.",
            "If the reconstructed root matches the committed root, the key is in the allowlist. Combined with a SIG block, this proves both membership and authorization.",
            "This pattern scales to thousands of authorized keys with O(log N) proof size. Adding or removing keys requires updating the root in a new covenant output.",
        ],
    },
    "CLTV_TIME CALENDAR LOCK": {
        "subtitle": "Calendar-based timelock using CLTV_TIME with Unix timestamp. Funds are locked until a specific calendar date rather than a block height. Useful for contracts tied to real-world dates.",
        "category": "TIMELOCK + CALENDAR",
        "rung_desc": "Single rung with CLTV_TIME (Unix timestamp) + SIG. The funds unlock after a specific calendar date/time.",
        "output_labels": ["TIME_LOCKED", "CHANGE"],
        "spend_path": "Calendar Unlock (Dry Run)",
        "how_it_works": [
            "CLTV_TIME checks that nLockTime (interpreted as Unix timestamp when &ge; 500,000,000) is at or past the committed timestamp.",
            "Unlike CLTV which uses block heights, CLTV_TIME allows locking to calendar dates. The evaluator compares nLockTime against the committed Unix timestamp.",
            "The SIG block requires authorization &mdash; reaching the unlock time alone isn't sufficient, the keyholder must also sign.",
            "This is a dry-run example: the timestamp is set in the future (Jan 2027), so the transaction is funded and signed but not broadcast.",
        ],
    },
    "TIMER WATCHDOG": {
        "subtitle": "Continuous timer watchdog with recursive mutation. The timer requires N consecutive blocks of activity. Each spend increments the accumulated counter via RECURSE_MODIFIED. The inverted TIMER_CONTINUOUS block is SATISFIED while accumulated < target, allowing the covenant to progress.",
        "category": "PLC + RECURSION",
        "rung_desc": "Three rungs: ACTIVE (inverted TMR_CONT + SIG + REC_MOD for recursive counting), HELD (TMR_OFF + SIG for off-delay hold), EMERG (CSV + SIG for emergency timeout).",
        "output_labels": ["WATCHDOG_OK", "HOLD_WINDOW", "TIMEOUT_SWEEP", "CHANGE"],
        "spend_path": "Watchdog Increment",
        "how_it_works": [
            "The ACTIVE rung uses an <em>inverted</em> TIMER_CONTINUOUS block: it's SATISFIED when accumulated < target (the normal block would be UNSATISFIED). This allows the covenant to advance while counting.",
            "RECURSE_MODIFIED targets the TIMER_CONTINUOUS block's <code>accumulated</code> field (block_idx=0, param_idx=0), incrementing it by delta=1 on each spend.",
            "After 144 spends, accumulated reaches target. The inverted TIMER_CONTINUOUS becomes UNSATISFIED (since accumulated = target), locking the ACTIVE rung. The watchdog has completed.",
            "The HELD rung (TMR_OFF_DELAY) provides a hold window. The EMERG rung (CSV + SIG) is a safety timeout if the watchdog stalls.",
        ],
    },
    "PRESET COUNTER BOARD VOTE": {
        "subtitle": "Multi-party board vote with preset counter. The counter tracks approvals; when the preset threshold is reached, the funds are released. HYSTERESIS_VALUE limits payout size. Demonstrates governance-controlled spending with programmable thresholds.",
        "category": "PLC + GOVERNANCE",
        "rung_desc": "Three rungs: VOTE (SIG + CTR_PRE + HYST_VAL + REC_MOD for recursive voting), RELEASE (SIG when counter reaches preset), VETO (dual SIG for override).",
        "output_labels": ["VOTE", "RELEASE", "VETO", "CHANGE"],
        "spend_path": "Board Vote",
        "how_it_works": [
            "The VOTE rung uses COUNTER_PRESET to track board approvals. Each vote increments <code>current</code> toward <code>preset</code>. HYSTERESIS_VALUE constrains payout size within a band.",
            "RECURSE_MODIFIED mutates the counter on each vote, creating a carry-forward with the incremented count. The same conditions persist but the vote count advances.",
            "When <code>current = preset</code>, the COUNTER_PRESET block flips behavior and the RELEASE rung becomes spendable. The board has reached quorum.",
            "The VETO rung requires two signatures &mdash; a designated pair can override and cancel the vote at any point, providing a safety mechanism.",
        ],
    },
    "ANCHORED CHANNEL + RECURSE_UNTIL": {
        "subtitle": "Lightning channel with anchor binding and bounded recursion. ANCHOR_CHANNEL tags the commitment with local/remote keys. RECURSE_UNTIL bounds the protocol lifetime to a target block height.",
        "category": "ANCHOR + RECURSION",
        "rung_desc": "Three rungs: COOP (MUSIG_THR + ANCHOR_CHANNEL for cooperative close), UPDATE (SIG + ANCHOR_CHANNEL + RECURSE_UNTIL for state updates), EXPIRE (CLTV + SIG for channel expiry).",
        "output_labels": ["COOP_CLOSE", "STATE_UPDATE", "CHANNEL_EXPIRE", "CHANGE"],
        "spend_path": "Cooperative Close",
        "how_it_works": [
            "ANCHOR_CHANNEL commits the local and remote public keys, binding the UTXO to a specific channel. The anchor data is checked during evaluation.",
            "The COOP rung uses MUSIG_THRESHOLD for a compact cooperative close &mdash; single aggregate signature from both parties.",
            "The UPDATE rung allows state updates via RECURSE_UNTIL, which bounds the recursion depth by block height. When the target height is reached, updates stop and the channel must close.",
            "EXPIRE provides a hard deadline: after the CLTV height, a single key can sweep the channel. This prevents indefinite locking if the counterparty disappears.",
        ],
    },
    "SINGLE SIG (DILITHIUM3)": {
        "subtitle": "Single post-quantum signature using Dilithium3 lattice-based cryptography. The simplest possible PQ transaction &mdash; one rung, one SIG block, Dilithium3 scheme. Demonstrates the PQ witness overhead (~3,300 bytes) vs classical Schnorr (64 bytes).",
        "category": "POST-QUANTUM",
        "rung_desc": "Single rung with one SIG block using SCHEME = DILITHIUM3. Identical structure to a classical SIG, with PQ key material.",
        "output_labels": ["PQ_SPEND"],
        "spend_path": "Dilithium3 Spend",
        "how_it_works": [
            "The conditions are identical to a classical SIG rung: one PUBKEY_COMMIT (32 bytes, same as Schnorr). The SCHEME field in the coil selects Dilithium3.",
            "The witness contains the full Dilithium3 public key (~1,952 bytes) and signature (~3,293 bytes). This is ~50x larger than Schnorr (33+64 bytes).",
            "The evaluator verifies SHA256(dilithium3_pubkey) matches the PUBKEY_COMMIT, then validates the Dilithium3 signature against the Ladder sighash.",
            "PQ support is transparent to the condition encoding. The same SIG type code works for all schemes &mdash; only the witness and verification algorithm change.",
        ],
    },
    "SINGLE SIG (FALCON512)": {
        "subtitle": "Single post-quantum signature using FALCON-512 lattice-based cryptography. Compact PQ signatures (~690 bytes) with fast verification. Smaller than Dilithium3 but with different security assumptions.",
        "category": "POST-QUANTUM",
        "rung_desc": "Single rung with one SIG block using SCHEME = FALCON512. More compact PQ signatures than Dilithium3.",
        "output_labels": ["PQ_SPEND"],
        "spend_path": "FALCON-512 Spend",
        "how_it_works": [
            "FALCON-512 produces compact PQ signatures (~690 bytes) compared to Dilithium3's ~3,293 bytes. Public keys are also smaller (~897 bytes).",
            "The condition encoding is identical: 32-byte PUBKEY_COMMIT with FALCON512 scheme in the coil. The evaluator selects the correct verification algorithm based on scheme.",
            "Total witness overhead is ~1,587 bytes (897B pubkey + 690B signature) &mdash; about half of Dilithium3 but still 16x larger than Schnorr.",
            "FALCON-512 is based on NTRU lattice problems and uses Gaussian sampling. It offers a good tradeoff between signature size and security level.",
        ],
    },
    "SINGLE SIG (FALCON1024)": {
        "subtitle": "Single post-quantum signature using FALCON-1024 lattice-based cryptography. NIST Security Level 5 &mdash; the highest tier. Larger signatures (~1,800 bytes) and keys (~1,793 bytes) than FALCON-512, but with a stronger security margin against quantum attack.",
        "category": "POST-QUANTUM",
        "rung_desc": "Single rung with one SIG block using SCHEME = FALCON1024. Same structure as FALCON-512 but with Level 5 parameters.",
        "output_labels": ["PQ_SPEND"],
        "spend_path": "FALCON-1024 Spend",
        "how_it_works": [
            "FALCON-1024 doubles the lattice dimension from FALCON-512, providing NIST Security Level 5 (equivalent to AES-256). Public keys are ~1,793 bytes; signatures are ~1,800 bytes.",
            "The condition encoding is identical to all SIG schemes: a 32-byte PUBKEY_COMMIT in the conditions with FALCON1024 scheme byte in the coil. The evaluator hashes the full PQ public key from the witness and verifies the commitment.",
            "Total witness overhead is ~3,593 bytes (1,793B pubkey + 1,800B signature) &mdash; roughly double FALCON-512 but still slightly smaller than Dilithium3's total.",
            "FALCON-1024 uses the same NTRU lattice and Gaussian sampling as FALCON-512 but with larger parameters. Choose FALCON-1024 when maximum PQ security is required and the ~3.6 KB witness overhead is acceptable.",
        ],
        "comparison": {
            "headers": ["Property", "FALCON-512", "FALCON-1024", "Schnorr"],
            "rows": [
                ["Security Level", "NIST Level 1", "NIST Level 5", "128-bit classical"],
                ["Public Key", "~897 bytes", "~1,793 bytes", "32 bytes (x-only)"],
                ["Signature", "~690 bytes", "~1,800 bytes", "64 bytes"],
                ["Total Witness", "~1,587 bytes", "~3,593 bytes", "97 bytes"],
                ["Quantum Resistant", "Yes (lattice)", "Yes (lattice)", "No"],
            ],
            "highlight": 4,
        },
    },
    "SINGLE SIG (SPHINCS+)": {
        "subtitle": "Single post-quantum signature using SPHINCS+-SHA2 hash-based cryptography. The most conservative PQ assumption &mdash; security relies only on the collision resistance of SHA-256, not lattice hardness. Extremely large signatures (~49,856 bytes) make this a last-resort option for maximum PQ assurance.",
        "category": "POST-QUANTUM",
        "rung_desc": "Single rung with one SIG block using SCHEME = SPHINCS_SHA. Hash-based stateless signatures &mdash; no lattice assumptions.",
        "output_labels": ["PQ_SPEND"],
        "spend_path": "SPHINCS+ Spend",
        "how_it_works": [
            "SPHINCS+-SHA2 is a hash-based signature scheme (NIST FIPS 205, SLH-DSA). Unlike lattice-based schemes (Falcon, Dilithium), its security rests solely on SHA-256 collision resistance &mdash; the most conservative quantum-safety assumption.",
            "The condition encoding is identical to all other SIG blocks: 32-byte PUBKEY_COMMIT with SPHINCS_SHA scheme. The witness contains the full SPHINCS+ public key (32 bytes) and signature (~49,856 bytes).",
            "Total witness is dominated by the signature: ~49,888 bytes. This is ~500x larger than Schnorr and ~15x larger than Dilithium3. The tradeoff is minimal cryptographic assumptions.",
            "SPHINCS+ is stateless &mdash; no risk of key reuse vulnerabilities that affect earlier hash-based schemes (XMSS, LMS). Choose this when you need the strongest possible PQ guarantee and can tolerate the bandwidth cost.",
        ],
        "comparison": {
            "headers": ["Property", "SPHINCS+-SHA2", "Dilithium3", "Schnorr"],
            "rows": [
                ["Security Basis", "SHA-256 hashes", "Lattice problems", "Discrete log"],
                ["Public Key", "32 bytes", "~1,952 bytes", "32 bytes"],
                ["Signature", "~49,856 bytes", "~3,293 bytes", "64 bytes"],
                ["Total Witness", "~49,888 bytes", "~5,245 bytes", "97 bytes"],
                ["Quantum Resistant", "Yes (hash-based)", "Yes (lattice)", "No"],
                ["Assumption Risk", "Minimal (SHA-256)", "Moderate (lattice)", "High (DL)"],
            ],
            "highlight": 4,
        },
    },
    "SINGLE SIG (COMPACT)": {
        "subtitle": "Simplest possible RUNG_TX: a single compact-encoded SIG rung. The wire format uses COMPACT_SIG encoding &mdash; just the pubkey commit and scheme byte, no block array. Minimal transaction size demonstrates the most efficient Ladder Script encoding.",
        "category": "COMPACT SIG",
        "rung_desc": "Single rung using COMPACT_SIG wire encoding. Instead of a block array, the conditions contain just the pubkey commit and scheme &mdash; the most compact possible encoding.",
        "output_labels": ["PAYMENT"],
        "spend_path": "Compact Spend",
        "how_it_works": [
            "COMPACT_SIG is a wire optimization for single-SIG rungs. Instead of encoding a full block array (type code + field count + fields), the conditions contain just: pubkey_commit (32B) + scheme (1B).",
            "The evaluator transparently expands COMPACT_SIG into a SIG block evaluation. The signer provides the same witness: compressed pubkey (33B) + Schnorr signature (64B).",
            "This reduces the conditions overhead from ~38 bytes (full SIG block encoding) to ~34 bytes. The savings compound with multiple rungs or outputs.",
            "COMPACT_SIG is automatically used when a rung contains exactly one SIG block with SCHNORR or ECDSA scheme. PQ schemes use full block encoding.",
        ],
    },
    "DUAL SIG (COMPACT)": {
        "subtitle": "Two independent compact-encoded SIG rungs. Hot key for daily spending, cold key for recovery. Both rungs use COMPACT_SIG wire format &mdash; no block arrays needed. Common wallet pattern with minimal on-chain overhead.",
        "category": "COMPACT SIG",
        "rung_desc": "Two compact SIG rungs on separate outputs: HOT (daily spending key) and COLD (recovery key). Each uses COMPACT_SIG encoding.",
        "output_labels": ["HOT_SPEND", "COLD_SPEND"],
        "spend_path": "Hot Key Spend",
        "how_it_works": [
            "Two outputs, each with a single COMPACT_SIG rung. The hot key output is for daily spending; the cold key output is for recovery.",
            "Both rungs are independently spendable &mdash; either key can authorize its respective output without the other. This provides key separation.",
            "COMPACT_SIG encoding on both rungs keeps the funding transaction minimal. Each output adds ~34 bytes of conditions overhead.",
            "This is the standard hot/cold wallet pattern: keep the hot key accessible for daily use, store the cold key securely for recovery.",
        ],
    },
}


def esc(s):
    return html.escape(str(s))


def slug(title):
    return re.sub(r'[^a-z0-9]+', '-', title.lower()).strip('-')


def fmt_sats(value_btc):
    sats = round(float(value_btc) * 1e8)
    return f"{sats:,}"


def block_label(block):
    btype = block.get("type", "?")
    short = BLOCK_SHORT.get(btype, btype)
    vals = block.get("values", {})
    if btype == "COUNTER_UP" and "current" in vals and "target" in vals:
        short = f"CTR_UP ({vals['current']}/{vals['target']})"
    elif btype == "COUNTER_PRESET" and "current" in vals and "preset" in vals:
        short = f"CTR_PRE ({vals['current']}/{vals['preset']})"
    elif btype == "TIMER_CONTINUOUS" and "accumulated" in vals and "target" in vals:
        inv = " INV" if block.get("inverted") else ""
        short = f"TMR_CONT ({vals['accumulated']}/{vals['target']}){inv}"
    elif btype == "CSV" and "blocks" in vals:
        short = f"CSV ({vals['blocks']})"
    elif btype == "CLTV" and "height" in vals:
        short = f"CLTV ({vals['height']})"
    elif btype == "CLTV_SIG" and "height" in vals:
        short = f"CLTV_SIG ({vals['height']})"
    elif btype == "AMOUNT_LOCK" and "min" in vals:
        short = f"AMT_LOCK ({vals['min']})"
    elif btype == "RECURSE_MODIFIED":
        delta = vals.get("delta", vals.get("decay_per_step", "?"))
        short = f"REC_MOD (+{delta})"
    elif btype == "RECURSE_SPLIT" and "max_splits" in vals:
        short = f"REC_SPLIT ({vals['max_splits']})"
    elif btype == "RECURSE_SAME" and "max_depth" in vals:
        short = f"REC_SAME ({vals['max_depth']})"
    elif btype == "SEQUENCER" and "current" in vals and "total" in vals:
        short = f"SEQ ({vals['current']}/{vals['total']})"
    elif btype == "MULTISIG" and "threshold" in vals:
        pks = vals.get("pubkeys", "")
        n = len([k for k in pks.split(",") if k.strip()]) if pks else "?"
        short = f"MSIG ({vals['threshold']}/{n})"
    elif btype == "TIMELOCKED_MULTISIG" and "threshold" in vals:
        short = f"TL_MSIG ({vals['threshold']})"
    elif btype == "MUSIG_THRESHOLD" and "threshold" in vals:
        short = f"MUSIG ({vals['threshold']}/{vals.get('group_size', '?')})"
    elif btype == "VAULT_LOCK" and "delay" in vals:
        short = f"VAULT ({vals['delay']}blk)"
    elif btype == "RECURSE_UNTIL" and "target_height" in vals:
        short = f"REC_UNTIL ({vals['target_height']})"
    elif btype == "RATE_LIMIT" and "max_per_block" in vals:
        short = f"RATE_LIM ({vals['max_per_block']})"
    elif btype == "ONE_SHOT":
        short = "1SHOT"
    elif btype == "HYSTERESIS_VALUE":
        short = "HYST_VAL"
    elif btype == "HYSTERESIS_FEE":
        short = "HYST_FEE"
    elif btype == "LATCH_SET" and "state" in vals:
        short = f"LATCH_S ({vals['state']})"
    elif btype == "TIMER_OFF_DELAY" and "remaining" in vals:
        short = f"TMR_OFF ({vals['remaining']})"
    elif btype == "RECURSE_COUNT" and "remaining" in vals:
        short = f"REC_CNT ({vals['remaining']})"
    return short


def block_css_class(btype):
    return BLOCK_FAMILY.get(btype, "val")


def json_highlight(obj, indent=2):
    raw = json.dumps(obj, indent=indent)
    raw = html.escape(raw)
    raw = re.sub(r'&quot;(\w+)&quot;(\s*:)', r'<span class="json-key">&quot;\1&quot;</span>\2', raw)
    raw = re.sub(r':\s*&quot;([^&]*)&quot;', r': <span class="json-str">&quot;\1&quot;</span>', raw)
    raw = re.sub(r':\s*(-?\d+\.?\d*)', r': <span class="json-num">\1</span>', raw)
    return raw


def is_compact_eligible(blocks, scheme="SCHNORR"):
    if len(blocks) == 1 and blocks[0]["type"] == "SIG":
        s = blocks[0].get("values", {}).get("scheme", scheme)
        return s in ("SCHNORR", "ECDSA", "", None)
    return False


def generate_doc(preset, result):
    title = preset["title"]
    desc_info = PRESET_DESC.get(title, {"subtitle": title, "category": "TRANSACTION"})
    subtitle = desc_info.get("subtitle", "")
    category = desc_info.get("category", "TRANSACTION")
    rung_desc = desc_info.get("rung_desc", "")
    output_labels = desc_info.get("output_labels", [])
    spend_path = desc_info.get("spend_path", "")
    how_it_works = desc_info.get("how_it_works", [])
    comparison = desc_info.get("comparison")
    status = result.get("status", "?")
    fund_decoded = result.get("fund_decoded")
    spend_decoded = result.get("spend_decoded")
    rungs = preset.get("rungs", [])
    scheme = preset.get("scheme", "SCHNORR")

    # Collect unique block types + families
    all_block_types = []
    css_families = set()
    for rung in rungs:
        for block in rung.get("blocks", []):
            btype = block["type"]
            css_families.add(block_css_class(btype))
            if btype not in all_block_types:
                all_block_types.append(btype)

    compact_rungs = [i for i, r in enumerate(rungs) if is_compact_eligible(r.get("blocks", []), scheme)]
    if compact_rungs:
        css_families.add("sig")

    # Scheme badges
    scheme_badges = []
    for btype in all_block_types:
        tc = BLOCK_TYPE_CODES.get(btype, "")
        fam = BLOCK_FAMILY.get(btype, "val")
        color, bg, border = FAMILY_COLORS.get(fam, FAMILY_COLORS["val"])
        label = BLOCK_SHORT.get(btype, btype)
        badge_label = f"{label} &middot; TYPE {tc}" if tc else label
        scheme_badges.append((badge_label, color, bg, border))
    # Add scheme badge
    scheme_colors = {
        "SCHNORR": ("#00d4ff", "rgba(0, 212, 255, 0.1)", "rgba(0, 212, 255, 0.25)"),
        "ECDSA": ("#f7931a", "rgba(247, 147, 26, 0.1)", "rgba(247, 147, 26, 0.25)"),
        "FALCON512": ("#00ff88", "rgba(0, 255, 136, 0.1)", "rgba(0, 255, 136, 0.25)"),
        "DILITHIUM3": ("#a855f7", "rgba(168, 85, 247, 0.1)", "rgba(168, 85, 247, 0.25)"),
    }
    sc = scheme_colors.get(scheme, scheme_colors["SCHNORR"])
    scheme_badges.append((f"{scheme} &middot; SCHEME", sc[0], sc[1], sc[2]))

    badges_html = '<div style="display: flex; gap: 8px; margin-top: 14px; flex-wrap: wrap;">\n'
    for label, color, bg, border in scheme_badges:
        badges_html += f'    <span class="scheme-badge" style="background: {bg}; color: {color}; border: 1px solid {border};">{label}</span>\n'
    badges_html += '  </div>'

    # Build rung diagram with arrows + output labels
    num_real_outputs = len(preset.get("outputs", []))
    rung_diagram_html = ""
    for ri, rung in enumerate(rungs):
        label = rung.get("label", f"R{ri}")
        blocks = rung.get("blocks", [])
        is_compact = ri in compact_rungs
        out_label = output_labels[ri] if ri < len(output_labels) else ""

        fam = BLOCK_FAMILY.get(blocks[0]["type"], "sig") if blocks else "sig"
        fam_color, fam_bg, fam_border = FAMILY_COLORS.get(fam, FAMILY_COLORS["val"])

        blocks_html = ""
        if is_compact:
            sig_color, sig_bg, sig_border = FAMILY_COLORS["sig"]
            blocks_html = f'<div class="rung-block" style="background: {sig_bg}; color: {sig_color}; border: 1px solid {sig_border};">COMPACT_SIG</div>'
        else:
            for bi, block in enumerate(blocks):
                btype = block["type"]
                bf = block_css_class(btype)
                bc, bbg, bborder = FAMILY_COLORS.get(bf, FAMILY_COLORS["val"])
                lbl = block_label(block)
                if bi > 0:
                    blocks_html += '<div class="rung-arrow">+</div>\n        '
                blocks_html += f'<div class="rung-block" style="background: {bbg}; color: {bc}; border: 1px solid {bborder};">{esc(lbl)}</div>'

        if out_label:
            blocks_html += f'\n        <div class="rung-arrow">&rarr;</div>\n        <div class="rung-output">{esc(out_label)}</div>'

        rung_diagram_html += f"""    <div class="rung-row">
      <div class="rung-label-box" style="background: {fam_bg}; color: {fam_color}; border: 1px solid {fam_border};">{esc(label)}</div>
      <div class="rung-blocks">
        {blocks_html}
      </div>
    </div>
"""

    # Output Structure diagram
    output_structure_html = ""
    if fund_decoded and fund_decoded.get("vout"):
        vouts = fund_decoded["vout"]
        output_structure_html = '<div class="doc-section">\n  <div class="section-label">Output Structure</div>\n'
        output_structure_html += '  <p class="section-text">The funding transaction splits funds across outputs with different security policies.</p>\n'
        output_structure_html += '  <div class="output-diagram">\n'
        for vi, vo in enumerate(vouts):
            sats = fmt_sats(vo.get("value", 0))
            spk_type = vo.get("scriptPubKey", {}).get("type", "unknown")

            # Determine output label and blocks
            if vi < len(rungs):
                rung = rungs[vi]
                blocks = rung.get("blocks", [])
                is_compact = vi in compact_rungs
                out_lbl = output_labels[vi] if vi < len(output_labels) else rung.get("label", f"RUNG_{vi}")
                fam = BLOCK_FAMILY.get(blocks[0]["type"], "sig") if blocks else "sig"
                fam_color, fam_bg, fam_border = FAMILY_COLORS.get(fam, FAMILY_COLORS["val"])

                inner_blocks = ""
                if is_compact:
                    inner_blocks = '<div class="rung-block" style="background: rgba(230, 168, 23, 0.1); color: #e6a817; border: 1px solid rgba(230, 168, 23, 0.2);">COMPACT_SIG</div>'
                else:
                    parts = []
                    for b in blocks:
                        bf = block_css_class(b["type"])
                        bc, bbg, bborder = FAMILY_COLORS.get(bf, FAMILY_COLORS["val"])
                        parts.append(f'<div class="rung-block" style="background: {bbg}; color: {bc}; border: 1px solid {bborder};">{esc(block_label(b))}</div>')
                    inner_blocks = '<div class="rung-arrow">+</div>'.join(parts)
            elif vi == len(vouts) - 1:
                out_lbl = "CHANGE"
                fam_color, fam_bg, fam_border = "#888", "rgba(100, 100, 100, 0.1)", "rgba(100, 100, 100, 0.2)"
                inner_blocks = '<div class="rung-block" style="background: rgba(100, 100, 100, 0.1); color: #888; border: 1px solid rgba(100, 100, 100, 0.2);">SIG (wallet)</div>'
            else:
                oi_label = output_labels[vi] if vi < len(output_labels) else f"RUNG_{vi}"
                out_lbl = oi_label
                fam_color, fam_bg, fam_border = "#888", "rgba(136, 136, 136, 0.08)", "rgba(136, 136, 136, 0.2)"
                inner_blocks = f'<div class="rung-block" style="background: rgba(136, 136, 136, 0.08); color: #888; border: 1px solid rgba(136, 136, 136, 0.2);">(conditions)</div>'

            output_structure_html += f"""    <div class="output-row">
      <div class="output-label-box" style="background: {fam_bg}; color: {fam_color}; border: 1px solid {fam_border};">VOUT {vi}<div class="output-amount">{sats} sats</div></div>
      <div class="output-blocks">
        {inner_blocks}
        <div class="rung-arrow">&rarr;</div>
        <div class="rung-output">{esc(out_lbl)}</div>
      </div>
    </div>
"""
        output_structure_html += '  </div>\n</div>\n'

    # Transaction pair
    fund_html = '<div class="tx-field"><div class="tx-field-value" style="color: #666;">No fund data available</div></div>'
    spend_html = '<div class="tx-field"><div class="tx-field-value" style="color: #666;">No spend data available</div></div>'
    spend_label = f"Spending Transaction ({esc(spend_path)})" if spend_path else "Spending Transaction"

    if fund_decoded:
        fund_txid = fund_decoded.get("txid", "?")
        fund_size = fund_decoded.get("size", "?")
        fund_vsize = fund_decoded.get("vsize", "?")
        fund_vout = fund_decoded.get("vout", [])

        output_descs = []
        for vi, vo in enumerate(fund_vout):
            sats = fmt_sats(vo.get("value", 0))
            lbl = output_labels[vi] if vi < len(output_labels) else ("change" if vi == len(fund_vout) - 1 else f"rung {vi}")
            output_descs.append(f"vout {vi}: {lbl} ({sats} sats)")

        fund_html = f"""<div class="tx-field">
        <div class="tx-field-name">TXID</div>
        <div class="tx-field-value txid">{esc(fund_txid)}</div>
      </div>
      <div class="tx-field">
        <div class="tx-field-name">Version</div>
        <div class="tx-field-value">4 (RUNG_TX)</div>
      </div>
      <div class="tx-field">
        <div class="tx-field-name">Size</div>
        <div class="tx-field-value">{fund_size} bytes &middot; {fund_vsize} vB</div>
      </div>
      <div class="tx-field">
        <div class="tx-field-name">Outputs</div>
        <div class="tx-field-value">{len(fund_vout)} &mdash; {', '.join(output_descs[:4])}</div>
      </div>
      <div class="tx-field">
        <div class="tx-field-name">Confirmations</div>
        <div class="tx-field-value highlight">1</div>
      </div>"""

    if spend_decoded:
        spend_txid = spend_decoded.get("txid", "?")
        spend_size = spend_decoded.get("size", "?")
        spend_vsize = spend_decoded.get("vsize", "?")
        spend_vout = spend_decoded.get("vout", [])
        spend_vin = spend_decoded.get("vin", [])

        witness_hex = ""
        if spend_vin and spend_vin[0].get("txinwitness"):
            witness_hex = spend_vin[0]["txinwitness"][0] if spend_vin[0]["txinwitness"] else ""
        witness_bytes = len(witness_hex) // 2 if witness_hex else 0

        spend_out_descs = []
        for vi, vo in enumerate(spend_vout):
            sats = fmt_sats(vo.get("value", 0))
            spk_type = vo.get("scriptPubKey", {}).get("type", "unknown")
            if spk_type == "rung_conditions":
                spend_out_descs.append(f"{sats} sats (carry-forward)" if len(spend_vout) == 1 else f"{sats} sats (rung conditions)")
            else:
                spend_out_descs.append(f"{sats} sats")

        if status == "DRY_RUN":
            spend_label = f"Spending Transaction ({esc(spend_path)}) &mdash; Dry Run"

        # Determine signer description from first rung
        signer_desc = ""
        if rungs:
            target = rungs[0]
            blocks = target.get("blocks", [])
            sig_types = [b["type"] for b in blocks if b["type"] in ("SIG", "MULTISIG", "ADAPTOR_SIG", "MUSIG_THRESHOLD", "TIMELOCKED_SIG", "CLTV_SIG", "VAULT_LOCK", "HTLC", "HASH_SIG", "PTLC", "TIMELOCKED_MULTISIG")]
            if len(sig_types) == 1:
                st = sig_types[0]
                if st == "MULTISIG":
                    t = blocks[0].get("values", {}).get("threshold", "?") if blocks[0]["type"] == "MULTISIG" else "?"
                    for b in blocks:
                        if b["type"] == "MULTISIG":
                            pks = b["values"].get("pubkeys", "")
                            n = len([k for k in pks.split(",") if k.strip()])
                            signer_desc = f"{t} of {n} multisig"
                            break
                elif st == "VAULT_LOCK":
                    signer_desc = "hot key (VAULT_LOCK)"
                elif st == "ADAPTOR_SIG":
                    signer_desc = "adaptor signature"
                elif st == "MUSIG_THRESHOLD":
                    signer_desc = "MuSig threshold"
                elif st in ("HTLC", "HASH_SIG"):
                    signer_desc = f"{st} (hash + sig)"
                else:
                    signer_desc = st
            elif len(sig_types) > 1:
                signer_desc = " + ".join(sig_types)

        spend_html = f"""<div class="tx-field">
        <div class="tx-field-name">TXID</div>
        <div class="tx-field-value txid">{esc(spend_txid)}</div>
      </div>
      <div class="tx-field">
        <div class="tx-field-name">Version</div>
        <div class="tx-field-value">4 (RUNG_TX)</div>
      </div>
      <div class="tx-field">
        <div class="tx-field-name">Size</div>
        <div class="tx-field-value">{spend_size} bytes &middot; {spend_vsize} vB</div>
      </div>
      <div class="tx-field">
        <div class="tx-field-name">Outputs</div>
        <div class="tx-field-value">{len(spend_vout)} &mdash; {'; '.join(spend_out_descs)}</div>
      </div>"""
        if signer_desc:
            spend_html += f"""
      <div class="tx-field">
        <div class="tx-field-name">Signers</div>
        <div class="tx-field-value highlight">{esc(signer_desc)}</div>
      </div>"""
        spend_html += f"""
      <div class="tx-field">
        <div class="tx-field-name">Witness</div>
        <div class="tx-field-value">{witness_bytes} bytes (ladder witness)</div>
      </div>
      <div class="tx-field">
        <div class="tx-field-name">Confirmations</div>
        <div class="tx-field-value highlight">{'DRY RUN' if status == 'DRY_RUN' else '1'}</div>
      </div>"""

    # Witness breakdown bar
    witness_bar_html = ""
    if spend_decoded and rungs:
        target_blocks = rungs[0].get("blocks", [])
        if is_compact_eligible(target_blocks, scheme):
            target_blocks = [{"type": "SIG", "values": target_blocks[0].get("values", {})}]

        segments = [("overhead", "HDR", 4)]
        legend_items = []
        legend_colors_seen = set()

        for block in target_blocks:
            btype = block["type"]
            wit_fields = BLOCK_WITNESS_BYTES.get(btype, [])
            if wit_fields:
                for fname, fbytes in wit_fields:
                    segments.append((fname, f"{fbytes}B", fbytes))
            else:
                fam = BLOCK_FAMILY.get(btype, "val")
                short = BLOCK_SHORT.get(btype, btype)
                segments.append((fam, short[:3], 1))

        segments.append(("overhead", "COIL", 6))

        # Build witness bar
        total = sum(s[2] for s in segments)
        witness_bar_html = '<div class="doc-section">\n  <div class="section-label">Spending Witness Breakdown</div>\n'
        witness_bar_html += '  <p class="section-text">The ladder witness provides data for each block in the rung. Blocks that need no witness data (validation-only blocks) contribute zero bytes.</p>\n'
        witness_bar_html += '  <div class="witness-bar">\n'
        for seg_type, seg_label, seg_bytes in segments:
            color_map = {
                "pubkey": "#f7931a", "signature": "#00ff88", "hash": "#00d4ff",
                "overhead": "#4a4a4a", "plc": "#a855f7", "rec": "#e6a817",
                "cov": "#00d4ff", "time": "#f7931a", "sig": "#00ff88",
                "adaptor": "#ff6b9d", "anchor": "#00ff88", "val": "#888",
            }
            color = color_map.get(seg_type, "#4a4a4a")
            flex = max(seg_bytes, 1)
            witness_bar_html += f'    <div class="witness-seg" style="flex: {flex}; background: {color};" title="{seg_label}: {seg_bytes} bytes">{seg_label}</div>\n'
            if seg_type not in legend_colors_seen:
                legend_colors_seen.add(seg_type)
                name_map = {"pubkey": "Public Key", "signature": "Signature", "hash": "Hash/Preimage", "overhead": "Framing"}
                legend_items.append((name_map.get(seg_type, seg_type.upper()), color))

        witness_bar_html += '  </div>\n  <div class="witness-legend">\n'
        for name, color in legend_items:
            witness_bar_html += f'    <div class="witness-legend-item"><div class="witness-legend-dot" style="background: {color};"></div> {name}</div>\n'
        witness_bar_html += '  </div>\n</div>\n'

    # Verification grid
    verify_html = ""
    if fund_decoded and spend_decoded:
        fund_vout_0 = fund_decoded.get("vout", [{}])[0]
        input_sats = round(float(fund_vout_0.get("value", 0)) * 1e8)
        total_spend_out = sum(round(float(vo.get("value", 0)) * 1e8) for vo in spend_decoded.get("vout", []))
        fee_sats = input_sats - total_spend_out if input_sats > total_spend_out else 0

        # Add block-specific verification items
        extra_verify = []
        if rungs:
            target_blocks = rungs[0].get("blocks", [])
            for block in target_blocks:
                btype = block["type"]
                vals = block.get("values", {})
                if btype == "MULTISIG":
                    t = vals.get("threshold", "?")
                    pks = vals.get("pubkeys", "")
                    n = len([k for k in pks.split(",") if k.strip()])
                    extra_verify.append(("Threshold", f"{t} of {n}", "MULTISIG check"))
                elif btype == "VAULT_LOCK":
                    extra_verify.append(("Vault Path", "Hot Key", f"CSV delay: {vals.get('delay', '?')} blocks"))
                elif btype in ("RECURSE_SAME", "RECURSE_MODIFIED", "RECURSE_SPLIT"):
                    extra_verify.append(("Recursion", BLOCK_SHORT.get(btype, btype), "Conditions carried forward"))
                elif btype == "CTV":
                    extra_verify.append(("CTV", "Template Match", "BIP-119 hash verified"))

        verify_html = '<div class="doc-section">\n  <div class="section-label">Verification</div>\n'
        verify_html += '  <div class="verify-grid">\n'
        verify_html += f"""    <div class="verify-item">
      <div class="verify-label">Input Amount</div>
      <div class="verify-value">{input_sats:,} sats</div>
      <div class="verify-check">vout[0] of fund TX</div>
    </div>
    <div class="verify-item">
      <div class="verify-label">Output Amount</div>
      <div class="verify-value">{total_spend_out:,} sats</div>
      <div class="verify-check">{len(spend_decoded.get('vout', []))} output(s)</div>
    </div>
    <div class="verify-item">
      <div class="verify-label">Fee</div>
      <div class="verify-value">{fee_sats:,} sats</div>
      <div class="verify-check">{input_sats:,} &minus; {total_spend_out:,}</div>
    </div>
"""
        for label, value, check in extra_verify:
            verify_html += f"""    <div class="verify-item">
      <div class="verify-label">{esc(label)}</div>
      <div class="verify-value">{esc(value)}</div>
      <div class="verify-check">{esc(check)}</div>
    </div>
"""
        verify_html += '  </div>\n</div>\n'

    # How It Works
    how_html = ""
    if how_it_works:
        how_title = f"How {title.title()} Works" if len(title) < 40 else "How It Works"
        how_html = f'<div class="doc-section">\n  <div class="section-label">{esc(how_title)}</div>\n\n  <div class="eval-box">\n'
        for i, step in enumerate(how_it_works, 1):
            how_html += f'    <div class="eval-step">\n      <div class="eval-step-num">{i}.</div>\n      <div class="eval-step-text">{step}</div>\n    </div>\n'
        how_html += '  </div>\n</div>\n'

    # Comparison table
    comparison_html = ""
    if comparison:
        headers = comparison["headers"]
        highlight = comparison.get("highlight", "")
        rows = comparison["rows"]
        comparison_html = '<div class="doc-section">\n  <div class="section-label">Comparison</div>\n'
        comparison_html += '  <table class="field-table">\n    <thead>\n      <tr>'
        for h in headers:
            comparison_html += f'<th>{esc(h)}</th>'
        comparison_html += '</tr>\n    </thead>\n    <tbody>\n'
        for row in rows:
            is_highlight = row[0] == highlight
            style = ' style="background: rgba(168, 85, 247, 0.04);"' if is_highlight else ""
            comparison_html += f'      <tr{style}>'
            for ci, cell in enumerate(row):
                if ci == 0:
                    color = ' style="color: #a855f7;"' if is_highlight else ""
                    comparison_html += f'<td class="field-name"{color}>{esc(cell)}</td>'
                else:
                    comparison_html += f'<td>{esc(cell)}</td>'
            comparison_html += '</tr>\n'
        comparison_html += '    </tbody>\n  </table>\n</div>\n'

    # Dry run note
    dry_run_note = ""
    if status == "DRY_RUN":
        note = result.get("note", "Timelock not satisfiable on regtest")
        dry_run_note = f"""<div class="doc-section">
  <div style="background: rgba(247, 147, 26, 0.08); border: 1px solid rgba(247, 147, 26, 0.2); border-radius: 8px; padding: 14px 18px; font-size: 12px; font-family: 'Geist Mono', 'IBM Plex Mono', monospace; color: #f7931a;">
    DRY RUN &mdash; {esc(note)}
  </div>
</div>
"""

    # Full JSON
    fund_json_html = ""
    if fund_decoded:
        fund_json_html = f'<div class="doc-section">\n  <div class="section-label">Funding Transaction JSON</div>\n  <div class="json-block">\n    <pre>{json_highlight(fund_decoded)}</pre>\n  </div>\n</div>\n'

    spend_json_html = ""
    if spend_decoded:
        label = "Spending Transaction JSON"
        if spend_path:
            label += f" ({esc(spend_path)})"
        if status == "DRY_RUN":
            label += " &mdash; Dry Run"
        spend_json_html = f'<div class="doc-section">\n  <div class="section-label">{label}</div>\n  <div class="json-block">\n    <pre>{json_highlight(spend_decoded)}</pre>\n  </div>\n</div>\n'

    # CSS classes
    block_css_rules = ""
    for cls in sorted(css_families):
        color, bg, border = FAMILY_COLORS.get(cls, FAMILY_COLORS["val"])
        block_css_rules += f"  .rung-block.{cls} {{ background: {bg}; color: {color}; border: 1px solid {border}; }}\n"

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{esc(title)} &mdash; Transaction Examples</title>
<link rel="stylesheet" href="../blocks/style.css">
<style>
  .tx-pair {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 20px 0; }}
  .tx-box {{ background: #0a0a0a; border: 1px solid #242424; border-radius: 10px; padding: 18px; }}
  .tx-box-label {{ font-size: 10px; font-family: 'Geist Mono', 'IBM Plex Mono', monospace; font-weight: 600; letter-spacing: 1.5px; text-transform: uppercase; margin-bottom: 12px; color: #888; }}
  .tx-box-label .arrow-right {{ color: #f7931a; }}
  .tx-box-label .arrow-left {{ color: #00d4ff; }}
  .tx-field {{ margin-bottom: 10px; }}
  .tx-field:last-child {{ margin-bottom: 0; }}
  .tx-field-name {{ font-size: 11px; font-family: 'Geist Mono', 'IBM Plex Mono', monospace; color: #666; margin-bottom: 2px; }}
  .tx-field-value {{ font-size: 13px; font-family: 'Geist Mono', 'IBM Plex Mono', monospace; color: #ccc; word-break: break-all; }}
  .tx-field-value.txid {{ font-size: 11px; color: #f7931a; }}
  .tx-field-value.highlight {{ color: #00ff88; }}

  .witness-bar {{ display: flex; height: 28px; border-radius: 6px; overflow: hidden; margin: 16px 0 8px; }}
  .witness-seg {{ display: flex; align-items: center; justify-content: center; font-size: 9px; font-family: 'Geist Mono', 'IBM Plex Mono', monospace; font-weight: 600; color: #050505; }}
  .witness-legend {{ display: flex; gap: 16px; flex-wrap: wrap; margin-top: 4px; }}
  .witness-legend-item {{ display: flex; align-items: center; gap: 6px; font-size: 11px; font-family: 'Geist Mono', 'IBM Plex Mono', monospace; color: #888; }}
  .witness-legend-dot {{ width: 9px; height: 9px; border-radius: 3px; }}

  .verify-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin: 16px 0; }}
  .verify-item {{ background: #0a0a0a; border: 1px solid rgba(0, 255, 136, 0.25); border-radius: 8px; padding: 14px; text-align: center; }}
  .verify-label {{ font-size: 10px; font-family: 'Geist Mono', 'IBM Plex Mono', monospace; color: #666; letter-spacing: 1px; text-transform: uppercase; margin-bottom: 6px; }}
  .verify-value {{ font-size: 16px; font-family: 'Geist Mono', 'IBM Plex Mono', monospace; font-weight: 600; color: #00ff88; }}
  .verify-check {{ font-size: 11px; font-family: 'Geist Mono', 'IBM Plex Mono', monospace; color: #00ff88; margin-top: 4px; }}

  .scheme-badge {{ display: inline-block; font-size: 10px; font-family: 'Geist Mono', 'IBM Plex Mono', monospace; font-weight: 600; padding: 3px 10px; border-radius: 5px; letter-spacing: 0.5px; }}

  .rung-diagram {{ display: flex; flex-direction: column; gap: 6px; margin: 16px 0; }}
  .rung-row {{ display: flex; align-items: stretch; gap: 0; }}
  .rung-label-box {{ width: 80px; min-width: 80px; display: flex; align-items: center; justify-content: center; font-size: 10px; font-family: 'Geist Mono', 'IBM Plex Mono', monospace; font-weight: 700; letter-spacing: 1px; border-radius: 6px 0 0 6px; padding: 10px 6px; }}
  .rung-blocks {{ display: flex; gap: 4px; flex: 1; padding: 8px; background: #0a0a0a; border: 1px solid #242424; border-left: none; border-radius: 0 6px 6px 0; align-items: center; flex-wrap: wrap; }}
  .rung-block {{ font-size: 9px; font-family: 'Geist Mono', 'IBM Plex Mono', monospace; font-weight: 600; padding: 6px 10px; border-radius: 4px; display: flex; align-items: center; letter-spacing: 0.5px; }}
  .rung-arrow {{ font-size: 11px; color: #444; margin: 0 2px; }}
  .rung-output {{ font-size: 9px; font-family: 'Geist Mono', 'IBM Plex Mono', monospace; font-weight: 600; padding: 6px 10px; border-radius: 4px; letter-spacing: 0.5px; background: rgba(0, 255, 136, 0.08); color: #00ff88; border: 1px solid rgba(0, 255, 136, 0.2); margin-left: auto; }}

  .output-diagram {{ display: flex; flex-direction: column; gap: 6px; margin: 16px 0; }}
  .output-row {{ display: flex; align-items: stretch; gap: 0; }}
  .output-label-box {{ width: 80px; min-width: 80px; display: flex; flex-direction: column; align-items: center; justify-content: center; font-size: 10px; font-family: 'Geist Mono', 'IBM Plex Mono', monospace; font-weight: 700; letter-spacing: 1px; border-radius: 6px 0 0 6px; padding: 10px 6px; }}
  .output-amount {{ font-size: 8px; font-weight: 400; margin-top: 2px; opacity: 0.7; }}
  .output-blocks {{ display: flex; gap: 4px; flex: 1; padding: 8px; background: #0a0a0a; border: 1px solid #242424; border-left: none; border-radius: 0 6px 6px 0; align-items: center; flex-wrap: wrap; }}

{block_css_rules}
  .json-block {{ background: #141414; border: 1px solid #1a1a1a; border-radius: 10px; padding: 18px 22px; margin: 16px 0; overflow-x: auto; font-size: 12px; line-height: 1.6; }}
  .json-block pre {{ margin: 0; font-family: 'Geist Mono', 'IBM Plex Mono', monospace; color: #ccc; white-space: pre-wrap; word-break: break-all; }}
  .json-key {{ color: #00d4ff; }}
  .json-str {{ color: #00ff88; }}
  .json-num {{ color: #f7931a; }}

  @media (max-width: 640px) {{
    .tx-pair {{ grid-template-columns: 1fr; }}
    .verify-grid {{ grid-template-columns: 1fr 1fr; }}
  }}
</style>
</head>
<body>

<div class="doc-content">

<div class="block-title-section">
  <div class="block-type-code">TRANSACTION EXAMPLE &middot; {esc(category)}</div>
  <h1 class="block-title">{esc(title)}</h1>
  <p class="block-subtitle">{esc(subtitle)}</p>
  {badges_html}
</div>

{dry_run_note}

<!-- Rung Diagram -->
<div class="doc-section">
  <div class="section-label">Rung Structure</div>
  <p class="section-text">{esc(rung_desc) if rung_desc else f'{len(rungs)} rung(s) define the spending conditions.'}</p>

  <div class="rung-diagram">
{rung_diagram_html}  </div>
</div>

{output_structure_html}

<!-- Transaction Pair -->
<div class="doc-section">
  <div class="section-label">Transactions</div>

  <div class="tx-pair">
    <div class="tx-box">
      <div class="tx-box-label"><span class="arrow-right">&#9654;</span> Funding Transaction</div>
      {fund_html}
    </div>

    <div class="tx-box">
      <div class="tx-box-label"><span class="arrow-left">&#9664;</span> {spend_label}</div>
      {spend_html}
    </div>
  </div>
</div>

{witness_bar_html}

{verify_html}

{how_html}

{comparison_html}

{fund_json_html}

{spend_json_html}

<!-- Nav -->
<div class="doc-nav">
  <span onclick="if(window.parent !== window) window.parent.location.hash='TX_INDEX'; else window.location.href='../index.html#TX_INDEX';">&#8592; All Transaction Examples</span>
  <span></span>
</div>

</div>

</body>
</html>"""

    return page


def main():
    parser = argparse.ArgumentParser(description="Generate TX doc pages from test results")
    parser.add_argument("--results", default=RESULTS_PATH)
    parser.add_argument("--outdir", default=OUT_DIR)
    parser.add_argument("--preset", help="Generate only this preset (title substring)")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--force", action="store_true", help="Overwrite existing files")
    args = parser.parse_args()

    with open(args.results) as f:
        results = json.load(f)

    if args.list:
        for r in results:
            s = slug(r["title"])
            exists = os.path.exists(os.path.join(args.outdir, f"{s}.html"))
            marker = " [EXISTS]" if exists else ""
            has_data = " (fund+spend)" if r.get("fund_decoded") and r.get("spend_decoded") else " (fund only)" if r.get("fund_decoded") else " (NO DATA)"
            has_desc = " [EDITORIAL]" if r["title"] in PRESET_DESC else ""
            print(f"  {r['title']:45s} → {s}.html{marker}{has_data}{has_desc}")
        return

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import importlib.util
    spec = importlib.util.spec_from_file_location("test_presets",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "test-presets.py"))
    tp = importlib.util.module_from_spec(spec)
    import unittest.mock
    with unittest.mock.patch('sys.argv', ['test-presets.py', '--list']):
        try:
            spec.loader.exec_module(tp)
        except SystemExit:
            pass

    presets_by_title = {p["title"]: p for p in tp.PRESETS}
    os.makedirs(args.outdir, exist_ok=True)

    generated = 0
    skipped = 0

    for r in results:
        title = r["title"]
        if args.preset and args.preset.lower() not in title.lower():
            continue
        if not r.get("fund_decoded"):
            print(f"  SKIP {title} — no decoded TX data")
            skipped += 1
            continue
        s = slug(title)
        out_path = os.path.join(args.outdir, f"{s}.html")
        if os.path.exists(out_path) and not args.force:
            print(f"  EXISTS {s}.html — use --force to overwrite")
            skipped += 1
            continue

        preset = presets_by_title.get(title)
        if not preset:
            print(f"  SKIP {title} — no preset definition found")
            skipped += 1
            continue

        page_html = generate_doc(preset, r)
        with open(out_path, "w") as f:
            f.write(page_html)
        print(f"  WROTE {s}.html ({len(page_html):,} bytes)")
        generated += 1

    print(f"\nGenerated: {generated}, Skipped: {skipped}")


if __name__ == "__main__":
    main()
