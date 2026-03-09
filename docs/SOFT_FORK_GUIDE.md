# Ladder Script Soft Fork Activation Guide

## 1. Overview

Ladder Script introduces transaction version 4 (`RUNG_TX`) to Bitcoin, replacing opcode-based Script with typed, structured spending conditions for participating outputs. The soft fork changes the following:

**What changes:**
- Transaction version 4 gains consensus meaning (currently non-standard, treated as anyone-can-spend).
- Outputs with scriptPubKey prefix `0xc1` (inline conditions) or `0xc2` (MLSC Merkle root) are recognised as ladder conditions and evaluated by the ladder evaluator.
- Witness validation for v4 inputs uses the ladder sighash (`TaggedHash("LadderSighash")`) instead of the Script interpreter.
- Post-quantum signature schemes (FALCON-512/1024, Dilithium3, SPHINCS_SHA) become available through the SCHEME field.
- All block types are standard.

**What does not change:**
- Transaction versions 1 and 2 are validated identically to current rules.
- All existing UTXOs, scripts, addresses, and spending paths remain valid.
- The UTXO set structure, block format, and P2P protocol are unchanged.
- Segregated witness (BIP-141), Taproot (BIP-341), and all other existing soft fork rules remain in effect.

## 2. Activation Strategy

Ladder Script uses BIP-9 versionbits deployment with a single activation. All block types activate simultaneously.

### BIP-9 Mechanics

BIP-9 defines a state machine for each deployment:

```
DEFINED  -->  STARTED  -->  LOCKED_IN  -->  ACTIVE
                  |
                  +--->  FAILED
```

- **DEFINED:** The deployment exists in code but signalling has not started.
- **STARTED:** The `start_time` has passed. Miners can signal readiness by setting the assigned version bit.
- **LOCKED_IN:** The signalling threshold was met in a retarget period (2,016 blocks). Activation is guaranteed at the next retarget.
- **ACTIVE:** The new consensus rules are enforced.
- **FAILED:** The `timeout` has passed without reaching the threshold.

### Block Type Families

All block types are activated as a single deployment:

- Signature, Timelock, and Hash (0x0001-0x02FF): SIG, MULTISIG, ADAPTOR_SIG, MUSIG_THRESHOLD, CSV, CSV_TIME, CLTV, CLTV_TIME, HASH_PREIMAGE, HASH160_PREIMAGE, and TAGGED_HASH.
- Covenant and Anchor (0x0300-0x05FF): CTV, VAULT_LOCK, AMOUNT_LOCK, ANCHOR, ANCHOR_CHANNEL, ANCHOR_POOL, ANCHOR_RESERVE, ANCHOR_SEAL, and ANCHOR_ORACLE.
- Recursion and PLC (0x0400-0x06FF): RECURSE_SAME, RECURSE_MODIFIED, RECURSE_UNTIL, RECURSE_COUNT, RECURSE_SPLIT, RECURSE_DECAY, and all PLC block types (HYSTERESIS through COSIGN).

## 3. Block Type Families

### Signature, Timelock, and Hash (0x0001-0x02FF)

**Block type range:** 0x0001-0x02FF (11 block types)

**Scope:** The core ladder framework providing feature parity with existing Script capabilities. Every spending pattern expressible in P2PKH, P2SH, P2WPKH, P2WSH, and P2TR can be expressed as a ladder.

**Block types:**
- SIG (0x0001): Single signature, equivalent to P2PKH/P2WPKH/P2TR key-path.
- MULTISIG (0x0002): M-of-N threshold, equivalent to OP_CHECKMULTISIG.
- ADAPTOR_SIG (0x0003): Adaptor signatures for atomic swaps and payment channels.
- CSV (0x0101) / CSV_TIME (0x0102): Relative timelocks, equivalent to BIP-68/BIP-112.
- CLTV (0x0103) / CLTV_TIME (0x0104): Absolute timelocks, equivalent to BIP-65.
- HASH_PREIMAGE (0x0201): SHA-256 HTLC hash locks.
- HASH160_PREIMAGE (0x0202): HASH160 hash locks.
- TAGGED_HASH (0x0203): BIP-340 tagged hash verification.

**Risk profile:** Low. These conditions map directly to well-understood Script operations that have been running on mainnet for years. The primary new risk surface is the wire format deserialisation and the ladder sighash computation, both of which are covered by 185 unit tests and 115 functional tests.

**What this enables:**
- Standard single-sig and multisig wallets using ladder outputs.
- Lightning HTLCs expressed as ladder conditions (HASH_PREIMAGE + CSV + SIG).
- Time-locked savings vaults (SIG + CLTV).
- Atomic swaps via adaptor signatures (ADAPTOR_SIG).
- Post-quantum signatures via the SCHEME field in SIG and MULTISIG blocks.

### Covenant and Anchor (0x0300-0x05FF)

**Block type range:** 0x0300-0x05FF (9 block types)

**Scope:** Output constraints and protocol-specific UTXO tagging. These are capabilities that do not exist in current Script and represent genuinely new transaction semantics.

**Block types:**
- CTV (0x0301): OP_CHECKTEMPLATEVERIFY (BIP-119) covenant.
- VAULT_LOCK (0x0302): Vault with enforced delay period.
- AMOUNT_LOCK (0x0303): Output amount range enforcement.
- ANCHOR (0x0501): Generic protocol anchor.
- ANCHOR_CHANNEL (0x0502): Lightning channel anchor.
- ANCHOR_POOL (0x0503): Pool participant anchor.
- ANCHOR_RESERVE (0x0504): N-of-M guardian reserve anchor.
- ANCHOR_SEAL (0x0505): Permanent data commitment seal.
- ANCHOR_ORACLE (0x0506): Oracle quorum anchor.

**Risk profile:** Moderate. CTV introduces transaction introspection (the spending transaction must match a committed template). AMOUNT_LOCK introduces output amount inspection. Anchor types introduce protocol-specific semantics that must be correctly evaluated. Vaults introduce a new time-delay covenant pattern.

**What this enables:**
- Non-interactive payment channels via CTV.
- Vault custody patterns with enforced cooling periods.
- Protocol-tagged UTXOs for Lightning, mining pools, and oracle networks.
- Amount-bounded outputs for change management and dust prevention.

### Recursion and Programmable Logic Controllers (0x0400-0x06FF)

**Block type range:** 0x0400-0x06FF (20 block types)

**Scope:** Self-referencing conditions and stateful logic. Recursive block types require the ladder evaluator to inspect both the input conditions and the output conditions of the spending transaction. PLC block types introduce industrial automation primitives.

**Block types:**
- RECURSE_SAME (0x0401) through RECURSE_DECAY (0x0406): Six recursion variants enabling self-perpetuating UTXOs with controlled evolution.
- HYSTERESIS_FEE (0x0601) through COSIGN (0x0681): Fourteen PLC block types enabling stateful spending logic.

**Risk profile:** High. Recursive conditions create the possibility of permanently unspendable outputs if the recursion termination condition is never met. PLC state machines introduce implicit state that must be correctly tracked across transaction chains. The interaction between recursion and covenants requires careful analysis to prevent unexpected constraint propagation.

**What this enables:**
- Self-perpetuating vaults that re-encumber on every spend (RECURSE_SAME).
- Countdown vaults that allow spending after N intermediate transactions (RECURSE_COUNT).
- Rate-limited wallets that restrict withdrawal frequency (RATE_LIMIT).
- Multi-step approval processes with accumulating signatures (COUNTER_PRESET).
- State machines for complex business logic (LATCH_SET + LATCH_RESET chains).
- Fee-governed outputs that constrain transaction fee rates (HYSTERESIS_FEE).
- Time-decaying parameters for graduated release schedules (RECURSE_DECAY).

### Compound (0x0700-0x07FF)

**Block type range:** 0x0700-0x07FF (6 block types)

**Scope:** Multi-condition blocks that combine signature, timelock, and hash checks into a single block with a single header, saving wire bytes.

**Block types:**
- TIMELOCKED_SIG (0x0701): SIG + CSV combined.
- HTLC (0x0702): HASH_PREIMAGE + CSV + SIG for atomic swaps.
- HASH_SIG (0x0703): HASH_PREIMAGE + SIG combined.
- PTLC (0x0704): ADAPTOR_SIG + CSV for payment channels.
- CLTV_SIG (0x0705): SIG + CLTV combined.
- TIMELOCKED_MULTISIG (0x0706): MULTISIG + CSV combined.

**Risk profile:** Low. These are syntactic sugar over well-understood primitive block combinations. Each compound evaluator delegates to the same verification routines as the corresponding separate blocks.

**What this enables:**
- Atomic swaps with 8-16 bytes less wire overhead per HTLC.
- Payment channel constructions with compact PTLC blocks.
- Time-delayed multisig vaults without separate CSV blocks.

### Governance (0x0800-0x08FF)

**Block type range:** 0x0800-0x08FF (6 block types)

**Scope:** Transaction-level structural constraints that enforce spending windows, weight limits, I/O fanout bounds, value ratios, and set membership.

**Block types:**
- EPOCH_GATE (0x0801): Spending window gate based on block height modular arithmetic.
- WEIGHT_LIMIT (0x0802): Maximum transaction weight.
- INPUT_COUNT (0x0803): Min/max number of inputs.
- OUTPUT_COUNT (0x0804): Min/max number of outputs.
- RELATIVE_VALUE (0x0805): Anti-siphon output value ratio.
- ACCUMULATOR (0x0806): Merkle set membership proof.

**Risk profile:** Moderate. These blocks inspect transaction structure (weight, input/output counts, value ratios) which introduces new introspection surface. ACCUMULATOR introduces Merkle proof verification in the evaluator.

**What this enables:**
- Treasury governance with periodic spending windows (EPOCH_GATE).
- Transaction structure enforcement for protocol compliance (weight, I/O counts).
- Allowlist-based spending via Merkle accumulators.
- Anti-siphon protection for covenant chains (RELATIVE_VALUE).

## 4. Node Upgrade Path

### Upgraded nodes

Upgraded nodes enforce the full ladder evaluation rules for v4 transactions. All block types are standard upon activation.

- Before activation: v4 transactions are non-standard (not relayed, not mined by default). If included in a block by a miner, they are valid (anyone-can-spend semantics).
- After activation: v4 transactions with all block types are standard and relayed.

### Non-upgraded nodes

Non-upgraded nodes do not recognize the `0xc1` prefix or the ladder evaluator. Their behaviour depends on the activation state:

**Before activation:** v4 transactions are non-standard. Non-upgraded nodes neither relay nor mine them. No impact.

**After activation:** Non-upgraded nodes accept blocks containing v4 transactions because:

1. The transaction version 4 is not invalid under existing consensus rules (versions are a 32-bit signed integer; only negative versions are invalid).
2. The `0xc1` scriptPubKey prefix does not match any existing standard output type, so the output is treated as anyone-can-spend.
3. The soft fork security model ensures that non-upgraded nodes accept all blocks that upgraded nodes accept, because the new rules are strictly more restrictive (upgraded nodes reject transactions that non-upgraded nodes would accept, never the reverse).

**Risk to non-upgraded nodes:** Non-upgraded nodes may accept an invalid v4 transaction (one that violates ladder rules) if it appears in a block. However, this can only happen if a majority of mining hashrate colludes to include an invalid transaction, which breaks the security assumption for any soft fork.

**Recommendation:** Node operators should upgrade before activation to enforce the full rule set.

### SPV clients

SPV clients verify block headers and Merkle proofs but do not validate transactions. They are unaffected by the soft fork and continue to function identically. SPV clients that wish to validate ladder conditions must implement the ladder evaluator.

## 5. Miner Signalling

### BIP-9 Bit Assignment

| Deployment | Version Bit | Start Time | Timeout | Threshold |
|------------|-------------|------------|---------|-----------|
| Ladder Script | Bit 5 | Epoch TBD | Start + 1 year | 90% (1,815 of 2,016 blocks) |

**Threshold rationale:** The 90% threshold (rather than 95%) balances activation speed against consensus safety. Ladder Script introduces new transaction semantics but does not modify existing validation rules, limiting the blast radius of a split.

**Signalling mechanism:** Miners signal readiness by setting the assigned bit in the block header's `nVersion` field during the STARTED period. The bit is checked during each retarget period (2,016 blocks, approximately 2 weeks). If the threshold is met in any retarget period, the deployment enters LOCKED_IN and activates at the next retarget boundary.

**Timeout rationale:** A 1-year timeout provides adequate time for miner coordination while ensuring that a stalled deployment does not permanently consume a version bit.

### Miner Considerations

Miners who signal for Ladder Script should ensure:

1. Their node software includes the ladder evaluator and enforces ladder consensus rules.
2. Their block template construction correctly handles v4 transactions in the mempool.
3. Their fee estimation accounts for the different witness size characteristics of ladder transactions (PQ signatures can be significantly larger than Schnorr).

Miners who have not upgraded should not signal, as signalling implies enforcement of the new rules.

## 6. Wallet Integration

### Detecting Ladder Support

Wallets can determine the activation state by querying the node's `getblockchaininfo` RPC, which includes the BIP-9 deployment status for each soft fork.

```json
{
  "softforks": {
    "ladder": {
      "type": "bip9",
      "bip9": {
        "status": "active",
        "start_time": ...,
        "timeout": ...,
        "since": 850000
      }
    }
  }
}
```

### Creating Ladder Outputs

Wallets create ladder-locked outputs using the `createrung` and `createrungtx` RPCs:

1. Define the spending conditions as a JSON structure of rungs, blocks, and typed fields.
2. Call `createrung` to serialise the conditions to hex.
3. Call `createrungtx` with the serialised conditions and desired output amounts to construct an unsigned v4 transaction.

The resulting transaction has `nVersion = 4` and outputs with `scriptPubKey = 0xc1 || conditions`.

### Spending Ladder Outputs

Wallets spend ladder-locked outputs using the `signrungtx` RPC:

1. Construct a v4 transaction that spends the ladder-locked UTXO.
2. Call `signrungtx` with the unsigned transaction, the private key(s), and the spent output information (amount, scriptPubKey).
3. The RPC computes the ladder sighash, signs with the appropriate scheme, and assembles the witness.

### Address Format

Ladder conditions do not map to existing address formats (P2PKH, P2SH, P2WPKH, P2WSH, P2TR). A future BIP should define a Bech32m address format for ladder outputs. In the interim, wallets can exchange ladder conditions as hex-encoded scriptPubKeys or use the `createrung` RPC output directly.

### Fee Estimation

Ladder witnesses can be significantly larger than equivalent Script witnesses, particularly when post-quantum signatures are used. Wallets should account for the following witness sizes when estimating fees:

| Scheme | Typical Witness Overhead |
|--------|------------------------|
| Schnorr SIG | ~100 bytes (comparable to P2TR key-path) |
| ECDSA SIG | ~110 bytes (comparable to P2WPKH) |
| FALCON-512 SIG | ~1,600 bytes |
| FALCON-1024 SIG | ~3,100 bytes |
| DILITHIUM3 SIG | ~5,300 bytes |

The MAX_LADDER_WITNESS_SIZE limit of 10,000 bytes applies per input.

## 7. Risk Analysis

### Consensus Split

**Risk:** If the activation threshold is met but a significant minority of hashrate has not upgraded, the network could experience a temporary chain split where non-upgraded miners build on blocks that upgraded miners reject.

**Mitigation:** The 90% threshold ensures overwhelming hashrate agreement before activation. The LOCKED_IN grace period (one retarget period, approximately 2 weeks) provides additional time for stragglers to upgrade.

### Deserialisation Vulnerabilities

**Risk:** The wire format deserialiser is a new attack surface. Malformed ladder witnesses could trigger crashes, memory corruption, or consensus divergence between implementations.

**Mitigation:** The deserialiser performs exhaustive validation: type checks, size bounds, trailing byte rejection, and total size limits. It is covered by 185 unit tests, fuzz testing (`rung_deserialize.cpp`), and functional tests that explicitly test malformed inputs. The MAX_LADDER_WITNESS_SIZE limit prevents memory exhaustion.

### Witness Bloat

**Risk:** Post-quantum signatures are significantly larger than Schnorr signatures. A transaction with a Dilithium3 signature consumes approximately 5.3 KB of witness space per input, compared to 64 bytes for Schnorr.

**Mitigation:** The MAX_LADDER_WITNESS_SIZE limit of 10,000 bytes per input prevents unbounded growth. Mempool policy can further restrict witness sizes. The fee market naturally discourages witness bloat (larger witnesses cost more in fees). Post-quantum schemes are expected to be used sparingly during a transition period.

### Recursive Output Locking

**Risk:** Recursion block types can create UTXOs that re-encumber indefinitely if the termination condition is never met. Users could accidentally lock funds permanently.

**Mitigation:** RECURSE_UNTIL has an explicit block height termination. RECURSE_COUNT has a countdown to zero. RECURSE_DECAY reduces parameters toward termination. Wallet software should warn users when creating recursive conditions and simulate the termination path.

### PLC State Machine Complexity

**Risk:** The interaction between PLC block types (latches, counters, sequencers) creates implicit state that exists across transaction chains. Bugs in state tracking could lead to funds being locked or unlocked unexpectedly.

**Mitigation:** Each PLC block type evaluates independently based on its field values. There is no shared mutable state between blocks; state is encoded explicitly in the conditions and must be explicitly mutated via RECURSE_MODIFIED. The evaluator is stateless per invocation, reducing the surface for state-related bugs.

### Sighash Divergence

**Risk:** The ladder sighash (`TaggedHash("LadderSighash")`) is a new hash algorithm. Implementation differences between signing and verification code could cause valid signatures to be rejected.

**Mitigation:** The sighash algorithm is derived from BIP-341 with minimal modifications (removal of annex/tapscript extensions, addition of conditions_hash). Unit tests verify determinism, hash type variants, and round-trip sign/verify cycles. The tagged hash prefix ensures domain separation from BIP-341 sighashes.

### Unknown Block Type Semantics

**Risk:** The forward-compatibility rule (unknown types return UNSATISFIED, inverted unknown returns SATISFIED) could be exploited if an attacker crafts a transaction with an unknown block type in an inverted position, causing it to be trivially spendable.

**Mitigation:** Conditions with unknown block types are policy-non-standard and will not be relayed or mined by default. A miner would have to deliberately include such a transaction. After activation, the evaluator enforces the actual condition for all defined block types.

## 8. Timeline

The following timeline assumes community review begins at publication and proceeds without major objections. All dates are approximate.

| Milestone | Target Date | Duration | Description |
|-----------|-------------|----------|-------------|
| BIP publication | 2026-03-06 | — | Formal specification published for community review. |
| Reference implementation review | 2026-03 to 2026-06 | 3 months | Code review of `src/rung/` by independent reviewers. Fuzz testing campaigns. |
| Testnet deployment | 2026-06 | — | Ladder Script activated on signet/testnet. Wallet developers begin integration testing. |
| Signalling start | 2026-09 | — | BIP-9 signalling begins on mainnet. |
| Activation | 2026-10 to 2026-11 | 1-2 months | Estimated activation assuming 90% miner readiness. All block types become standard. |

**Total timeline:** Approximately 8 months from publication to activation.

**Failure criteria:** If the deployment fails to reach the 90% threshold within its 1-year timeout, it enters FAILED state. A new BIP-9 deployment with a fresh version bit and updated parameters would be required to retry.

### Post-Activation Monitoring

After activation, the following should be monitored:

- **Block validation time:** Ladder evaluation adds computation per v4 input. Monitor for block validation latency increases.
- **Mempool behaviour:** Ensure v4 transactions are correctly relayed and that policy enforcement matches expectations.
- **UTXO set growth:** Ladder conditions with large PQ public keys increase UTXO set size. Monitor growth rate.
- **Reorg behaviour:** Verify that v4 transactions are correctly handled during chain reorganizations.
- **Wallet adoption:** Track the percentage of outputs using ladder conditions.
