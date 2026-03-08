# Ladder Script Soft Fork Activation Guide

## 1. Overview

Ladder Script introduces transaction version 4 (`RUNG_TX`) to Bitcoin, replacing opcode-based Script with typed, structured spending conditions for participating outputs. The soft fork changes the following:

**What changes:**
- Transaction version 4 gains consensus meaning (currently non-standard, treated as anyone-can-spend).
- Outputs with scriptPubKey prefix `0xc1` are recognized as ladder conditions and evaluated by the ladder evaluator.
- Witness validation for v4 inputs uses the ladder sighash (`TaggedHash("LadderSighash")`) instead of the Script interpreter.
- All 48 block types across 9 families are activated simultaneously.
- Post-quantum signature schemes (FALCON-512/1024, Dilithium3, SPHINCS+-SHA) become available through the SCHEME field.

**What does not change:**
- Transaction versions 1 and 2 are validated identically to current rules.
- All existing UTXOs, scripts, addresses, and spending paths remain valid.
- The UTXO set structure, block format, and P2P protocol are unchanged.
- Segregated witness (BIP-141), Taproot (BIP-341), and all other existing soft fork rules remain in effect.

## 2. Activation Strategy

Ladder Script uses BIP-9 versionbits deployment with a single activation covering all 48 block types. All nine families — Signature, Timelock, Hash, Covenant, Recursion, Anchor, PLC, Compound, and Governance — activate together as one unit.

### BIP-9 Mechanics

BIP-9 defines a state machine for each deployment:

```
DEFINED  -->  STARTED  -->  LOCKED_IN  -->  ACTIVE
                  |
                  +--->  FAILED
```

- **DEFINED:** The deployment exists in code but signaling has not started.
- **STARTED:** The `start_time` has passed. Miners can signal readiness by setting the assigned version bit.
- **LOCKED_IN:** The signaling threshold was met in a retarget period (2,016 blocks). Activation is guaranteed at the next retarget.
- **ACTIVE:** The new consensus rules are enforced.
- **FAILED:** The `timeout` has passed without reaching the threshold.

### Single Activation Rationale

A single activation is preferred over a phased approach because:

1. **All block types are interdependent.** Compound blocks reference base block evaluators. Governance blocks constrain transactions that contain any family's blocks. Recursion depends on covenants. Splitting activation creates artificial boundaries that do not reflect the architecture.
2. **Reduced complexity.** One activation means one set of consensus rules, one signaling period, one upgrade path. No need for version bit juggling or conditional policy logic.
3. **Complete testing.** All 48 block types and their interactions have been tested together from the start. Splitting them into phases would require testing configurations that were never developed against.

## 3. Block Type Families

All 48 block types activated as a single unit:

| Family | Range | Count | Block Types |
|--------|-------|-------|-------------|
| Signature | 0x0001-0x00FF | 3 | SIG, MULTISIG, ADAPTOR_SIG |
| Timelock | 0x0100-0x01FF | 4 | CSV, CSV_TIME, CLTV, CLTV_TIME |
| Hash | 0x0200-0x02FF | 3 | HASH_PREIMAGE, HASH160_PREIMAGE, TAGGED_HASH |
| Covenant | 0x0300-0x03FF | 3 | CTV, VAULT_LOCK, AMOUNT_LOCK |
| Recursion | 0x0400-0x04FF | 6 | RECURSE_SAME, RECURSE_MODIFIED, RECURSE_UNTIL, RECURSE_COUNT, RECURSE_SPLIT, RECURSE_DECAY |
| Anchor | 0x0500-0x05FF | 6 | ANCHOR, ANCHOR_CHANNEL, ANCHOR_POOL, ANCHOR_RESERVE, ANCHOR_SEAL, ANCHOR_ORACLE |
| PLC | 0x0600-0x06FF | 14 | HYSTERESIS_FEE, HYSTERESIS_VALUE, TIMER_CONTINUOUS, TIMER_OFF_DELAY, LATCH_SET, LATCH_RESET, COUNTER_DOWN, COUNTER_PRESET, COUNTER_UP, COMPARE, SEQUENCER, ONE_SHOT, RATE_LIMIT, COSIGN |
| Compound | 0x0700-0x07FF | 3 | TIMELOCKED_SIG, HTLC, HASH_SIG |
| Governance | 0x0800-0x08FF | 6 | EPOCH_GATE, WEIGHT_LIMIT, INPUT_COUNT, OUTPUT_COUNT, RELATIVE_VALUE, ACCUMULATOR |

**Risk profile:** The block types range from low-risk (Signature, Timelock, Hash — direct equivalents of existing Script operations) to higher complexity (Recursion, PLC — stateful logic with no Script equivalent). All have been tested together and evaluated as a complete system.

**What this enables:**
- Standard single-sig and multisig wallets using ladder outputs.
- Lightning HTLCs as single compound blocks (HTLC), saving 16 bytes per instance.
- Covenants, vaults, and output constraints without new opcodes.
- Self-perpetuating recursive covenants with provable termination.
- Industrial automation patterns (rate limiting, sequencing, latching) for spending policy.
- Transaction-level governance (weight limits, I/O count bounds, value ratio enforcement).
- Post-quantum signatures via the SCHEME field.
- Merkle set membership proofs (ACCUMULATOR) for whitelist/blacklist enforcement.

## 4. Node Upgrade Path

### Upgraded nodes

Upgraded nodes enforce the full ladder evaluation rules for v4 transactions. All 48 block types are consensus-valid and policy-standard after activation. Before activation, v4 transactions are non-standard (not relayed, not mined by default). If included in a block by a miner, they are valid (anyone-can-spend semantics).

### Non-upgraded nodes

Non-upgraded nodes do not recognize the `0xc1` prefix or the ladder evaluator. Their behavior depends on the activation state:

**Before activation:** v4 transactions are non-standard. Non-upgraded nodes neither relay nor mine them. No impact.

**After activation:** Non-upgraded nodes accept blocks containing v4 transactions because:

1. The transaction version 4 is not invalid under existing consensus rules (versions are a 32-bit signed integer; only negative versions are invalid).
2. The `0xc1` scriptPubKey prefix does not match any existing standard output type, so the output is treated as anyone-can-spend.
3. The soft fork security model ensures that non-upgraded nodes accept all blocks that upgraded nodes accept, because the new rules are strictly more restrictive (upgraded nodes reject transactions that non-upgraded nodes would accept, never the reverse).

**Risk to non-upgraded nodes:** Non-upgraded nodes may accept an invalid v4 transaction (one that violates ladder rules) if it appears in a block. However, this can only happen if a majority of mining hashrate colludes to include an invalid transaction, which breaks the security assumption for any soft fork.

**Recommendation:** Node operators should upgrade before activation to enforce the full rule set.

### SPV clients

SPV clients verify block headers and Merkle proofs but do not validate transactions. They are unaffected by the soft fork and continue to function identically. SPV clients that wish to validate ladder conditions must implement the ladder evaluator.

## 5. Miner Signaling

### BIP-9 Bit Assignment

| Version Bit | Start Time | Timeout | Threshold |
|-------------|------------|---------|-----------|
| Bit 5 | Epoch TBD | Start + 1 year | 90% (1,815 of 2,016 blocks) |

**Threshold rationale:** The 90% threshold (rather than 95%) balances activation speed against consensus safety. Ladder Script introduces new transaction semantics but does not modify existing validation rules, limiting the blast radius of a split.

**Signaling mechanism:** Miners signal readiness by setting the assigned bit in the block header's `nVersion` field during the STARTED period. The bit is checked during each retarget period (2,016 blocks, approximately 2 weeks). If the threshold is met in any retarget period, the deployment enters LOCKED_IN and activates at the next retarget boundary.

**Timeout rationale:** A 1-year timeout provides adequate time for miner coordination while ensuring that a stalled deployment does not permanently consume a version bit.

### Miner Considerations

Miners who signal for Ladder Script should ensure:

1. Their node software includes the ladder evaluator and enforces ladder consensus rules.
2. Their block template construction correctly handles v4 transactions in the mempool.
3. Their fee estimation accounts for the different witness size characteristics of ladder transactions (PQ signatures can be significantly larger than Schnorr).

Miners who have not upgraded should not signal, as signaling implies enforcement of the new rules.

## 6. Wallet Integration

### Detecting Ladder Support

Wallets can determine the activation state by querying the node's `getblockchaininfo` RPC, which includes the BIP-9 deployment status:

```json
{
  "softforks": {
    "ladder_script": {
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
2. Call `createrung` to serialize the conditions to hex.
3. Call `createrungtx` with the serialized conditions and desired output amounts to construct an unsigned v4 transaction.

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
| SPHINCS+-SHA SIG | ~49,400 bytes |

The MAX_LADDER_WITNESS_SIZE limit of 100,000 bytes applies per input. Transactions with multiple PQ-signed inputs may approach the standard block weight limit.

## 7. Risk Analysis

### Consensus Split

**Risk:** If the activation threshold is met but a significant minority of hashrate has not upgraded, the network could experience a temporary chain split where non-upgraded miners build on blocks that upgraded miners reject.

**Mitigation:** The 90% threshold ensures overwhelming hashrate agreement before activation. The LOCKED_IN grace period (one retarget period, approximately 2 weeks) provides additional time for stragglers to upgrade.

### Deserialization Vulnerabilities

**Risk:** The wire format deserializer is a new attack surface. Malformed ladder witnesses could trigger crashes, memory corruption, or consensus divergence between implementations.

**Mitigation:** The deserializer performs exhaustive validation: type checks, size bounds, trailing byte rejection, and total size limits. It is covered by 185 unit tests, fuzz testing (`rung_deserialize.cpp`), and functional tests that explicitly test malformed inputs. The MAX_LADDER_WITNESS_SIZE limit prevents memory exhaustion.

### Witness Bloat

**Risk:** Post-quantum signatures are orders of magnitude larger than Schnorr signatures. A transaction with a SPHINCS+-SHA signature consumes approximately 49 KB of witness space per input, compared to 64 bytes for Schnorr.

**Mitigation:** The MAX_LADDER_WITNESS_SIZE limit of 100,000 bytes per input prevents unbounded growth. Mempool policy can further restrict witness sizes. The fee market naturally discourages witness bloat (larger witnesses cost more in fees). Post-quantum schemes are expected to be used sparingly during a transition period.

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

**Mitigation:** Conditions with unknown block types are policy-non-standard and will not be relayed or mined by default. A miner would have to deliberately include such a transaction. After a future soft fork defines the block type, the evaluator enforces the actual condition.

## 8. Timeline

The following timeline assumes community review begins at publication and proceeds without major objections. All dates are approximate.

| Milestone | Target Date | Duration | Description |
|-----------|-------------|----------|-------------|
| BIP publication | 2026-03-06 | -- | Formal specification published for community review. |
| Reference implementation review | 2026-03 to 2026-06 | 3 months | Code review of `src/rung/` by independent reviewers. Fuzz testing campaigns. |
| Testnet deployment | 2026-06 | -- | Ladder Script activated on signet/testnet. Wallet developers begin integration testing. |
| Signaling start | 2026-09 | -- | BIP-9 signaling begins on mainnet. |
| Activation | 2026-10 to 2026-11 | 1-2 months | Estimated activation assuming 90% miner readiness. |

**Total timeline:** Approximately 8 months from publication to full activation.

**Failure criteria:** If the deployment fails to reach the 90% threshold within its 1-year timeout, it enters FAILED state. A new BIP-9 deployment with a fresh version bit and updated parameters would be required to retry.

### Post-Activation Monitoring

After activation, the following should be monitored:

- **Block validation time:** Ladder evaluation adds computation per v4 input. Monitor for block validation latency increases.
- **Mempool behavior:** Ensure v4 transactions are correctly relayed and that policy enforcement matches expectations.
- **UTXO set growth:** Ladder conditions use PUBKEY_COMMIT (32 bytes) rather than raw public keys, keeping UTXO overhead constant regardless of key size. Monitor growth rate.
- **Reorg behavior:** Verify that v4 transactions are correctly handled during chain reorganizations.
- **Wallet adoption:** Track the percentage of outputs using ladder conditions to gauge ecosystem uptake.
