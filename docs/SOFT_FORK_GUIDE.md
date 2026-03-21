# Ladder Script Soft Fork Activation Guide

## 1. Overview

Ladder Script introduces transaction version 4 (`RUNG_TX`) to Bitcoin, replacing opcode-based Script with typed, structured spending conditions for participating outputs. The soft fork changes the following:

**What changes:**
- Transaction version 4 gains consensus meaning (currently non-standard, treated as anyone-can-spend).
- Outputs with scriptPubKey prefix `0xC2` (MLSC Merkle root) are recognised as ladder conditions and evaluated by the ladder evaluator. Inline `0xC1` is rejected on mainnet (testing only).
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

All 60 block types across 10 families activate as a single deployment. Partial activation of individual block types is not supported - the evaluation engine, wire format, and sighash computation form an interdependent whole.

## 3. Risk by Family

All 60 block types are documented in the BIP and Block Library. This section summarises the risk profile and new capabilities introduced by each family, relevant to activation review.

### Signature, Timelock, and Hash (0x0001-0x02FF) - 11 block types

**Risk:** Low. These map directly to well-understood Script operations running on mainnet for years. HASH_PREIMAGE and HASH160_PREIMAGE are deprecated (rejected at consensus); use HTLC, HASH_SIG, or HASH_GUARDED instead. The new risk surface is the wire format deserialisation and ladder sighash, covered by 444 unit tests and 158 functional tests.

**Enables:** Standard wallets, Lightning HTLCs, timelocked vaults, atomic swaps, post-quantum signatures via the SCHEME field.

### Covenant and Anchor (0x0300-0x05FF) - 9 block types

**Risk:** Moderate. CTV introduces transaction introspection. AMOUNT_LOCK introduces output amount inspection. Vaults introduce time-delay covenant patterns. Anchors introduce protocol-specific semantics.

**Enables:** Non-interactive payment channels, vault custody with cooling periods, protocol-tagged UTXOs, amount-bounded outputs.

### Recursion and PLC (0x0400-0x06FF) - 20 block types

**Risk:** High. Recursive conditions can create permanently unspendable outputs if termination is never met. PLC state machines introduce implicit state across transaction chains. Every RECURSE_* block has a provably reachable terminal state (see BIP Security Considerations).

**Enables:** Self-perpetuating vaults, countdown vaults, rate-limited wallets, multi-step approvals, state machines, fee-governed outputs, time-decaying parameters.

### Compound (0x0700-0x07FF) - 6 block types

**Risk:** Low. Syntactic sugar over primitive block combinations. Each compound evaluator delegates to the same verification routines as the corresponding separate blocks. HTLC and HASH_SIG are the recommended replacements for deprecated pure hash locks.

**Enables:** Compact atomic swaps, payment channel constructions, time-delayed multisig, all with fewer wire bytes.

### Governance (0x0800-0x08FF) - 6 block types

**Risk:** Moderate. Transaction structure introspection (weight, I/O counts, value ratios). ACCUMULATOR introduces Merkle proof verification.

**Enables:** Treasury spending windows, transaction structure enforcement, allowlist-based spending, anti-siphon protection.

### Legacy (0x0900-0x09FF) - 7 block types

**Risk:** Low. These wrap existing Bitcoin transaction types (P2PK, P2PKH, P2SH, P2WPKH, P2WSH, P2TR key-path, P2TR script-path) as typed blocks. Spending semantics are identical to the originals. P2SH/P2WSH/P2TR_SCRIPT inner conditions must be valid Ladder Script - recursion depth limited to 2.

**Enables:** Migration path from legacy transaction types to typed fields. Closes the taproot script-path inscription vector. Legacy users gain access to full Ladder Script composability (timelocks, covenants, PQ schemes) alongside their wrapped legacy spending path.

## 4. Node Upgrade Path

### Upgraded nodes

Upgraded nodes enforce the full ladder evaluation rules for v4 transactions. All block types are standard upon activation.

- Before activation: v4 transactions are non-standard (not relayed, not mined by default). If included in a block by a miner, they are valid (anyone-can-spend semantics).
- After activation: v4 transactions with all block types are standard and relayed.

### Non-upgraded nodes

Non-upgraded nodes do not recognise the `0xC2` prefix or the ladder evaluator. Their behaviour depends on the activation state:

**Before activation:** v4 transactions are non-standard. Non-upgraded nodes neither relay nor mine them. No impact.

**After activation:** Non-upgraded nodes accept blocks containing v4 transactions because:

1. The transaction version 4 is not invalid under existing consensus rules (versions are a 32-bit signed integer; only negative versions are invalid).
2. The `0xC2` scriptPubKey prefix does not match any existing standard output type, so the output is treated as anyone-can-spend.
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

The resulting transaction has `nVersion = 4` and outputs with `scriptPubKey = 0xC2 || conditions_root` (MLSC format). The RPC computes the Merkle root from the conditions and pubkeys (merkle_pub_key).

### Spending Ladder Outputs

Wallets spend ladder-locked outputs using the `signrungtx` RPC:

1. Construct a v4 transaction that spends the ladder-locked UTXO.
2. Call `signrungtx` with the unsigned transaction, the private key(s), and the spent output information (amount, scriptPubKey).
3. The RPC computes the ladder sighash, signs with the appropriate scheme, and assembles the witness.

### Address Format

Ladder Script outputs use the `rung1` human-readable prefix with Bech32m encoding (BIP-350). The address encodes the raw conditions bytes with a 500-character limit to accommodate variable-length conditions. Wallets encode via `bech32::Encode(bech32::Encoding::BECH32M, "rung", data)` and decode by detecting the `rung1` prefix.

### Fee Estimation

Ladder witnesses can be significantly larger than equivalent Script witnesses, particularly when post-quantum signatures are used. Wallets should account for the following witness sizes when estimating fees:

| Scheme | Typical Witness Overhead |
|--------|------------------------|
| Schnorr SIG | ~100 bytes (comparable to P2TR key-path) |
| ECDSA SIG | ~110 bytes (comparable to P2WPKH) |
| FALCON-512 SIG | ~1,600 bytes |
| FALCON-1024 SIG | ~3,100 bytes |
| DILITHIUM3 SIG | ~5,300 bytes |

The MAX_LADDER_WITNESS_SIZE limit of 100,000 bytes applies per input.

## 7. Risk Analysis

### Consensus Split

**Risk:** If the activation threshold is met but a significant minority of hashrate has not upgraded, the network could experience a temporary chain split where non-upgraded miners build on blocks that upgraded miners reject.

**Mitigation:** The 90% threshold ensures overwhelming hashrate agreement before activation. The LOCKED_IN grace period (one retarget period, approximately 2 weeks) provides additional time for stragglers to upgrade.

### Deserialisation Vulnerabilities

**Risk:** The wire format deserialiser is a new attack surface. Malformed ladder witnesses could trigger crashes, memory corruption, or consensus divergence between implementations.

**Mitigation:** The deserialiser performs exhaustive validation: type checks, size bounds, trailing byte rejection, and total size limits. It is covered by 185 unit tests, fuzz testing (`rung_deserialize.cpp`), and functional tests that explicitly test malformed inputs. The MAX_LADDER_WITNESS_SIZE limit prevents memory exhaustion.

### Witness Bloat

**Risk:** Post-quantum signatures are significantly larger than Schnorr signatures. A transaction with a Dilithium3 signature consumes approximately 5.3 KB of witness space per input, compared to 64 bytes for Schnorr.

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

**Risk:** Unknown block types are rejected at consensus during deserialization. This fail-closed design prevents an attacker from crafting conditions with fabricated block types.

**Mitigation:** `IsKnownBlockType()` is checked during deserialization in `serialize.cpp`. Transactions with unknown block types cannot enter the mempool or be included in blocks. New block types require a code update to be recognised.

## 8. Milestones

| Milestone | Description |
|-----------|-------------|
| BIP publication | Formal specification published for community review. |
| Reference implementation review | Code review of `src/rung/` by independent reviewers. Fuzz testing campaigns. |
| Testnet deployment | Ladder Script activated on signet/testnet. Wallet developers begin integration testing. |
| Signalling start | BIP-9 signalling begins on mainnet. |
| Activation | All 60 block types become consensus-enforced and policy-standard. |

**Failure criteria:** If the deployment fails to reach the 90% threshold within its 1-year timeout, it enters FAILED state. A new BIP-9 deployment with a fresh version bit and updated parameters would be required to retry.

### Post-Activation Monitoring

After activation, the following should be monitored:

- **Block validation time:** Ladder evaluation adds computation per v4 input. Monitor for block validation latency increases.
- **Mempool behaviour:** Ensure v4 transactions are correctly relayed and that policy enforcement matches expectations.
- **UTXO set growth:** MLSC outputs are fixed at 40 bytes per entry regardless of script complexity. Monitor overall UTXO count growth from ladder adoption.
- **Reorg behaviour:** Verify that v4 transactions are correctly handled during chain reorganizations.
- **Wallet adoption:** Track the percentage of outputs using ladder conditions.

## 9. Legacy Migration Path

Ladder Script's Legacy family (0x0900-0x09FF) wraps traditional Bitcoin transaction types as typed blocks, preserving their spending semantics while closing arbitrary data surfaces. This enables a phased migration from legacy formats to fully typed conditions.

### Phase 1: Coexistence

Both legacy Bitcoin transaction types (P2PK, P2PKH, P2SH, P2WPKH, P2WSH, P2TR) and Ladder Script v4 transactions are valid on-chain. No existing transaction type is deprecated. Wallets choose which format to use. This is the state at activation.

### Phase 2: Legacy-in-Blocks

After sufficient adoption and stability, a follow-up soft fork restricts new output creation to Ladder Script v4 transactions only. Legacy spending semantics remain available through the Legacy block family - a P2PKH_LEGACY block evaluates identically to a P2PKH script, but all fields are typed and validated. No arbitrary data surfaces exist in the wrapped form. Existing legacy UTXOs remain spendable under their original rules indefinitely.

### Phase 3: Sunset

After the Legacy block family has proven stable and the ecosystem has fully migrated, the Legacy blocks themselves can be deprecated in a further soft fork. At this point all transaction conditions use native Ladder Script block types. The wrapped legacy semantics are no longer needed because the native equivalents (SIG, MULTISIG, HTLC, HASH_SIG, timelocks) cover every spending pattern the legacy types expressed.

Each phase requires its own community review, signalling period, and activation. No phase is contingent on a timeline - each proceeds when the prior phase has demonstrated stability.
