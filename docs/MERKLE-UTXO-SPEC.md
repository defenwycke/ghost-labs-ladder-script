# Merkelised Ladder Script Conditions (MLSC)

## Specification v1.0

### Authors
Ghost Labs

### Status
Final — Consensus-standard

---

## 1. Abstract

Merkelised Ladder Script Conditions (MLSC) is the standard output format for Ladder Script transactions. Each output contains only a 32-byte Merkle root in its scriptPubKey (`0xC2` prefix). Full conditions are revealed only at spend time in the witness, where only the exercised spending path is disclosed. Unspent outputs reveal nothing about their conditions.

**Key properties:**

1. **Zero user-chosen bytes in the UTXO set** — only a 32-byte Merkle root per output
2. **Zero conditions on-chain at creation** — outputs contain only `(value, root)`
3. **Data embedding resistance** — fake conditions are never published (unspendable outputs are never spent, so conditions are never revealed); embedding surface reduced to 32 bytes per output (identical to P2TR/P2WSH)
4. **MAST privacy** — unused spending paths are never revealed; only the satisfied rung is disclosed at spend time
5. **Fixed-size UTXO entries** — 40 bytes per output regardless of script complexity
6. **Witness efficiency** — complex scripts save weight (conditions at 1× witness weight, not 4× output weight)

---

## 2. Design Rationale

### 2.1 The P2WSH Principle

Bitcoin's P2WSH outputs store only a 32-byte script hash. The full script is revealed only at spend time, in the witness. If an output is never spent, the script is never published. This means:

- A spammer who creates an unspendable P2WSH output with embedded data in the script never actually publishes that data — it exists only on their local machine
- The blockchain sees only 32 bytes of hash per output
- Nobody considers this a data embedding vulnerability

MLSC applies the same principle: outputs contain only the Merkle root of their conditions. The full conditions — including all PUBKEY_COMMITs, hash fields, and typed blocks — are revealed only when the output is spent.

### 2.2 Why Merkle Rather Than Flat Hash

A flat hash (like P2WSH) would require revealing all conditions at spend time, including unused rungs. The Merkle tree enables selective disclosure: only the satisfied rung and its relay dependencies are revealed. Unused spending paths remain permanently hidden behind opaque proof hashes.

For a ladder with N rungs, the spending witness includes only O(log N) proof hashes — at most 4 hashes for the maximum 16 rungs.

### 2.3 Design Goals

| Goal | Mechanism |
|------|-----------|
| No user-chosen bytes in UTXO set | Store only Merkle root; conditions never in UTXO |
| No conditions on-chain at creation | Output contains root only; conditions private until spend |
| Data embedding kills itself | Fake conditions → unspendable → never revealed → never on-chain |
| Fixed-size UTXO entries | 40 bytes `(value, root)` regardless of script complexity |
| MAST path privacy | Binary Merkle tree over rungs; unused paths stay hidden |
| Witness size reduction | Reveal only exercised path + O(log N) proof hashes |
| Quantum-safe key hiding | PUBKEY_COMMIT preserved; raw pubkeys never appear until spend |
| Evaluator compatibility | All 52 block evaluators unchanged |

### 2.4 Inline Conditions (`0xC1`)

Ladder Script also supports an inline conditions format where the full conditions are stored directly in the scriptPubKey with a `0xC1` prefix. This is useful for debugging, testing, and cases where conditions privacy is not required. MLSC (`0xC2`) is the standard format for production use.

---

## 3. Specification

### 3.1 Terminology

| Term | Definition |
|------|-----------|
| **Conditions** | The full set of Ladder Script rungs, blocks, and fields that define spending requirements |
| **Rung leaf** | `TaggedHash("LadderLeaf", SerializeRung(rung))` — the tagged hash of a serialised rung |
| **Coil leaf** | `TaggedHash("LadderLeaf", SerializeCoil(coil))` — the tagged hash of serialised coil metadata |
| **Conditions root** | The Merkle root computed over all rung leaves and the coil leaf using tagged interior hashes |
| **Merkle proof** | The sibling hashes needed to prove a leaf belongs to the conditions root |

### 3.2 Output Format (Creating Transaction)

Each output in the creating transaction contains only the value and the Merkle root:

```
Output:
  value:          int64     (8 bytes, satoshis)
  scriptPubKey:   0xC2 || conditions_root    (1 + 32 = 33 bytes)
```

**Total output size: 42 bytes** (8 value + 1 scriptPubKey length + 1 version byte + 32 root).

The `0xC2` version byte identifies MLSC outputs. **There are no conditions in the creating transaction.** The sender computes the Merkle root locally and places only the root in the output. The full conditions exist only in the sender's and recipient's wallets.

### 3.3 UTXO Entry Format

Each unspent output is stored as:

```
{
  value:            int64    (8 bytes, satoshis)
  conditions_root:  uint256  (32 bytes, Merkle root)
}
```

**Total: 40 bytes per UTXO entry**, fixed, regardless of script complexity.

### 3.4 Merkle Tree Construction

The conditions root is computed locally by the transaction creator as a binary Merkle tree over rung leaves and the coil leaf:

```
Merkle tree leaves (in order):
  [rung_leaf[0], rung_leaf[1], ..., rung_leaf[N-1], coil_leaf]
```

**Leaf computation (BIP-341-style tagged hashes):**

```
TaggedHash(tag, data) = SHA256(SHA256(tag) || SHA256(tag) || data)

rung_leaf[i] = TaggedHash("LadderLeaf", SerializeRung(rung[i]))
coil_leaf    = TaggedHash("LadderLeaf", SerializeCoil(coil))
```

Each rung is serialised using the standard wire format:
- Block count (varint)
- For each block:
  - Block type (uint16 LE)
  - Inverted flag (uint8)
  - Field count (varint)
  - For each field:
    - Data type (uint8)
    - Data length (varint)
    - Data (raw bytes)

**Tree construction:**

```
Given M leaves (N rungs + 1 coil): L[0], L[1], ..., L[M-1]

1. If M == 1: conditions_root = L[0]
2. If M > 1:
   a. Pad to next power of 2 with EMPTY_LEAF = TaggedHash("LadderLeaf", "")
   b. Build tree bottom-up:
      For each pair (A, B):
        if A <= B:  parent = TaggedHash("LadderInternal", A || B)
        else:       parent = TaggedHash("LadderInternal", B || A)
   c. conditions_root = tree root
```

**Domain separation (BIP-341 convention):** Leaf nodes use the tag `"LadderLeaf"` and interior nodes use the tag `"LadderInternal"`. The 64-byte tag prefix (`SHA256(tag) || SHA256(tag)`) in each tagged hash ensures cross-domain collisions are computationally infeasible — a valid leaf hash can never be mistaken for a valid interior hash, and vice versa. This follows the same pattern used by BIP-341 (Taproot) for `"TapLeaf"` vs `"TapBranch"`.

**Empty leaf constant:** `EMPTY_LEAF = TaggedHash("LadderLeaf", "")` is a nothing-up-my-sleeve constant used for power-of-2 padding. It uses the same "LadderLeaf" tag as real leaves but with empty data. It cannot collide with any valid rung or coil leaf because valid serialised rungs/coils have minimum length requirements.

**Sorted interior hashing:** Children are sorted lexicographically before hashing. This ensures canonical tree construction consistent with the ACCUMULATOR block convention.

### 3.5 Spending Witness Format

When spending an output, the witness provides the revealed conditions, witness data, Merkle proof, and coil:

```
Spending witness:
  [n_revealed_rungs: varint]              (must be exactly 1 for standard spends)
  for each revealed rung:
    [rung_index: varint]                  (position in original leaf array)
    [serialized_rung: bytes]              (full rung with condition fields)
      [n_blocks: varint]
        for each block:
          [block_type: uint16 LE]
          [inverted: uint8]
          [n_fields: varint]
            for each field:
              [data_type: uint8]          (condition types: PUBKEY_COMMIT, HASH256, etc.)
              [data_len: varint]
              [data: bytes]
    [n_witness_fields: varint]            (witness data for this rung's blocks)
      for each block:
        [n_fields: varint]
          for each field:
            [data_type: uint8]            (witness types: PUBKEY, SIGNATURE, PREIMAGE)
            [data_len: varint]
            [data: bytes]
  [n_relay_reveals: varint]               (relays referenced by the revealed rung)
  for each relay:
    [relay_index: varint]
    [serialized_relay: bytes]
  [serialized_coil: bytes]                (full coil metadata — always revealed)
  [n_proof_hashes: varint]                (Merkle proof sibling hashes)
  for each proof hash:
    [hash: 32 bytes]
```

### 3.6 Spending Verification

```
VerifyMLSCSpend(utxo, witness):

  1. Deserialise spending witness:
     - Extract revealed rung (exactly 1 for standard spends)
     - Extract referenced relays (if any)
     - Extract coil
     - Extract Merkle proof hashes

  2. Validate revealed conditions:
     - All field types and sizes must conform to existing rules
     - Condition-only field types enforced (reject PUBKEY, SIGNATURE, PREIMAGE
       in condition fields)

  3. Compute leaves:
     a. rung_leaf = TaggedHash("LadderLeaf", SerializeRung(revealed_rung))
     b. coil_leaf = TaggedHash("LadderLeaf", SerializeCoil(revealed_coil))
     c. relay_leaf[j] = TaggedHash("LadderLeaf", SerializeRelay(revealed_relay[j]))  (for each)

  4. Verify Merkle proof:
     a. Using computed leaves + proof sibling hashes, reconstruct Merkle root
     b. Assert reconstructed_root == utxo.conditions_root
     c. If mismatch → REJECT

  5. Merge conditions with witness:
     - Pair condition fields (PUBKEY_COMMIT, HASH256, SCHEME, etc.)
       with witness fields (PUBKEY, SIGNATURE, PREIMAGE)

  6. Evaluate:
     a. Evaluate referenced relays first (forward-only dependencies)
     b. Evaluate revealed rung blocks (AND logic — all blocks must be SATISFIED)
     c. If rung is SATISFIED → spend is valid

  7. Evaluate coil constraints (output validation) if present
```

### 3.7 Sighash Computation

The sighash commits to the **conditions_root** from the UTXO:

```
SignatureHashLadder components:
  [epoch: 1 byte]                         (0x00)
  [hash_type: 1 byte]
  [tx.version: 4 bytes]
  [tx.nLockTime: 4 bytes]
  [input hashes...]                       (prevouts, amounts, sequences)
  [output hash...]                        (all outputs)
  [spend_type: 1 byte]                    (0x00)
  [input-specific data...]
  [conditions_root: 32 bytes]             ← direct from UTXO
```

**Rationale:** The conditions_root already commits to all condition data through the Merkle tree. Signers attest to the root, which is binding on all possible spending paths. Using the root directly (rather than hashing it again) is simpler and equally secure — the root is already a SHA256 output.

### 3.8 Relay Handling

Relays are included in the Merkle tree as additional leaves between the rung leaves and the coil leaf:

```
Merkle tree leaves (in order):
  [rung_leaf[0], ..., rung_leaf[N-1], relay_leaf[0], ..., relay_leaf[M-1], coil_leaf]
```

If a revealed rung has `relay_refs = [0, 2]`, the spending witness must include:
- The revealed rung (serialised + witness data)
- Relay 0 and Relay 2 (serialised, with their own witness data if needed)
- Merkle proofs covering all revealed leaves

Relay evaluation follows existing forward-only rules: relay N can only reference relays 0..N-1.

### 3.9 Spending Constraints

**Single rung rule:** A standard spend reveals exactly one rung plus its relay dependencies plus the coil. Multiple rungs MUST NOT be revealed (it harms privacy with no benefit, since evaluation requires only one satisfied rung under OR semantics).

**Exception:** If a future soft fork introduces AND-across-rungs semantics, this rule may be relaxed. The witness format supports multiple revealed rungs for forward compatibility.

---

## 4. Data Embedding Analysis

### 4.1 Attack Surface

| Layer | Data | User-Chosen? | On-Chain? | Persistent? |
|-------|------|-------------|-----------|-------------|
| UTXO set | 32-byte Merkle root | Yes (computed locally) | Yes | Until spent |
| Creating tx output | 32-byte root only | Yes | Yes (in block) | Prunable |
| Conditions (legitimate spend) | Full rung + witness | Yes | Yes (in witness) | Prunable |
| Conditions (fake/spam) | Full rung data | Yes | **NO — never published** | N/A |

### 4.2 Why Fake Conditions Never Appear On-Chain

A spammer who creates an output with fake PUBKEY_COMMITs (arbitrary data instead of real key hashes):

1. Computes Merkle root locally from fake conditions
2. Broadcasts creating transaction with 42-byte output `(value, root)`
3. The fake conditions exist **only on the spammer's machine**
4. The output is unspendable — no private key corresponds to the fake PUBKEY_COMMITs
5. Nobody ever spends it, so the spending witness (which would reveal the fake conditions) is never created
6. The blockchain never sees the fake data — only the 32-byte root

**The spam kills itself.** The spammer burns coins for a 32-byte opaque hash in the UTXO set. Their actual spam data never touches the network.

### 4.3 Residual Embedding Surface

The only user-chosen bytes on-chain are the 32-byte conditions_root per output. This is identical to:
- **Bitcoin P2WSH:** 32-byte script hash per output
- **Bitcoin P2TR:** 32-byte tweaked key per output

Nobody considers P2WSH or P2TR a data embedding vulnerability. The 32 bytes are:
- Fixed size (cannot be inflated)
- One per output (bounded by output count)
- Require burning the output value (economic disincentive)
- Insufficient for meaningful content (32 bytes = ~2 words of text)

### 4.4 Comparison: MLSC vs Inline (`0xC1`)

| Property | Inline (`0xC1`) | MLSC (`0xC2`) |
|----------|----------------|---------------|
| User bytes in UTXO | Up to ~4 KB per output | 32 bytes (root only) |
| User bytes in block data | Up to ~4 KB per output | 32 bytes at creation; conditions at spend only |
| Fake data on-chain | Yes (full conditions in output) | **No** (never revealed for unspendable outputs) |
| Embedding cost | Coin burn + 4× weight on conditions | Coin burn + 4× weight on 33-byte output only |
| Data per output | Variable (scales with script complexity) | Fixed 32 bytes |

---

## 5. Transaction Sizes and Fees

All calculations assume **1-in, 2-out** (payment + change), both outputs single-sig MLSC, at **1 sat/vB** minimum feerate.

### 5.1 Output Size (Creating Transaction)

Every MLSC output is the same size regardless of script complexity:

```
Output: value(8) + scriptPubKey_len(1) + 0xC2(1) + root(32) = 42 bytes
```

This is comparable to Bitcoin P2TR outputs (43 bytes) and identical for all script types.

### 5.2 Spending Transaction Weights

**Non-witness base (identical for all patterns, 4× weight):**

| Component | Bytes |
|-----------|-------|
| nVersion | 4 |
| Input count | 1 |
| Input (prevout + scriptSig_len + sequence) | 41 |
| Output count | 1 |
| Output 1 (single-sig MLSC) | 42 |
| Output 2 (single-sig MLSC change) | 42 |
| nLockTime | 4 |
| **Non-witness total** | **135 B → 540 WU** |

**Witness data (1× weight) by spending pattern:**

| Spending Pattern | Revealed Conditions | Witness Data | Coil | Proof Hashes | Framing | Witness Total |
|-----------------|-------------------|--------------|------|-------------|---------|---------------|
| **Single-sig (SIG)** | 42 B | 101 B | 5 B | 0 (2 leaves, both known) | 3 B | **151 B** |
| **CLTV_SIG** | 45 B | 101 B | 5 B | 0 | 3 B | **154 B** |
| **PTLC** | 79 B | 135 B | 5 B | 0 | 3 B | **222 B** |
| **HTLC (hash path, 2 rungs)** | 81 B | 135 B | 5 B | 32 B (1 hash) | 3 B | **256 B** |
| **4-path (spend path 0)** | 42 B | 101 B | 5 B | 64 B (2 hashes) | 3 B | **215 B** |
| **2-of-3 Multisig** | 113 B | 239 B | 5 B | 0 | 3 B | **360 B** |
| **TIMELOCKED_MULTISIG** | 116 B | 239 B | 5 B | 0 | 3 B | **363 B** |
| **Multisig + recovery (2 rungs)** | 113 B | 239 B | 5 B | 32 B (1 hash) | 3 B | **392 B** |

### 5.3 Total Spending Transaction Weight and Fees

| Spending Pattern | Non-witness (4×) | Witness (1×) | Total WU | vBytes | Fee (1 sat/vB) |
|-----------------|-----------------|-------------|----------|--------|----------------|
| **Single-sig (SIG)** | 540 | 151 | **691** | **173** | **173 sats** |
| **CLTV_SIG** | 540 | 154 | **694** | **174** | **174 sats** |
| **PTLC** | 540 | 222 | **762** | **191** | **191 sats** |
| **HTLC (hash path)** | 540 | 256 | **796** | **199** | **199 sats** |
| **4-path covenant** | 540 | 215 | **755** | **189** | **189 sats** |
| **2-of-3 Multisig** | 540 | 360 | **900** | **225** | **225 sats** |
| **TIMELOCKED_MULTISIG** | 540 | 363 | **903** | **226** | **226 sats** |
| **Multisig + recovery** | 540 | 392 | **932** | **233** | **233 sats** |

### 5.4 Comparison with Bitcoin (1-in, 2-out)

| Type | MLSC | Bitcoin Equivalent | Bitcoin vBytes | Delta |
|------|------|-------------------|----------------|-------|
| Single-sig | 173 vB | P2TR keypath | ~154 vB | +12% |
| Single-sig | 173 vB | P2WPKH | ~141 vB | +23% |
| 2-of-3 Multisig | 225 vB | P2WSH 2-of-3 | ~201 vB | +12% |
| HTLC (2 paths) | 199 vB | P2TR scriptpath | ~175 vB | +14% |

MLSC is **12–23% heavier** than equivalent Bitcoin transactions. This overhead comes from typed fields, block headers, and coil metadata — the cost of Ladder Script's richer expressiveness (52 block types, PQ support, covenants, recursion, PLC blocks).

### 5.5 Creating Transaction Savings

MLSC outputs are dramatically smaller than inline (`0xC1`) outputs:

| Script Pattern | Inline Output | MLSC Output | Savings |
|----------------|--------------|-------------|---------|
| Single-sig | ~61 B | 42 B | −31% |
| 2-of-3 Multisig | ~120 B | 42 B | −65% |
| HTLC | ~119 B | 42 B | −65% |
| 4-path covenant | ~328 B | 42 B | −87% |
| 15-of-15 Multisig | ~538 B | 42 B | −92% |

Since outputs are at 4× weight, these savings are significant. A 2-of-3 multisig output drops from 480 WU to 168 WU — saving **312 WU per output** in the creating transaction.

### 5.6 UTXO Set Impact

| Script Pattern | Inline UTXO Size | MLSC UTXO Size | Savings |
|----------------|-----------------|----------------|---------|
| Single-sig | ~52 B | 40 B | −23% |
| 2-of-3 Multisig | ~112 B | 40 B | −64% |
| HTLC | ~111 B | 40 B | −64% |
| 4-path covenant | ~320 B | 40 B | −88% |
| 15-of-15 Multisig | ~530 B | 40 B | −92% |

Every UTXO is 40 bytes. A 15-of-15 multisig covenant with 16 rungs takes the same space as a single-sig.

### 5.7 Net Weight Assessment (Full Lifecycle)

For outputs that are eventually spent, the total lifecycle weight (create + spend) under MLSC vs inline:

| Pattern | Inline Create+Spend | MLSC Create+Spend | Delta |
|---------|---------------------|-------------------|-------|
| Single-sig | 244 WU + 115 WU = 359 WU | 168 WU + 151 WU = **319 WU** | **−11%** |
| 2-of-3 Multisig | 480 WU + 252 WU = 732 WU | 168 WU + 360 WU = **528 WU** | **−28%** |
| 4-path covenant | 1312 WU + 115 WU = 1427 WU | 168 WU + 215 WU = **383 WU** | **−73%** |

MLSC is cheaper across the full lifecycle for every transaction type. The savings come from moving conditions out of the 4× output weight into the 1× witness weight.

---

## 6. Security Analysis

### 6.1 Quantum Resistance

- Raw pubkeys never appear at creation time — output contains only the 32-byte root
- `PUBKEY_COMMIT = SHA256(pubkey)` is preserved in the conditions (private until spend)
- Pubkey revealed only at spend time in witness
- PQ migration via SCHEME field (FALCON512, FALCON1024, DILITHIUM3, SPHINCS_SHA) is orthogonal and unaffected
- The quantum threat model is identical to P2TR: pubkeys are hidden until the spending transaction is broadcast

### 6.2 Merkle Tree Security

- **Second preimage resistance:** Leaf nodes use `TaggedHash("LadderLeaf", ...)` and interior nodes use `TaggedHash("LadderInternal", ...)`. The 64-byte domain prefix in each tagged hash (BIP-341 convention) makes cross-domain collisions computationally infeasible — a valid leaf hash can never be interpreted as a valid interior node, and vice versa
- **Empty leaf attacks:** `EMPTY_LEAF = TaggedHash("LadderLeaf", "")` cannot collide with valid serialised rungs/coils (minimum length constraints, plus the tagged hash domain prefix prevents any raw-data collision)
- **Proof soundness:** Sorted interior hashing ensures canonical tree construction — no ambiguity in proof verification
- **Consistency with ACCUMULATOR:** Uses the same sorted binary tree convention implemented for the ACCUMULATOR block evaluator

### 6.3 Sighash Binding

The sighash commits to `conditions_root`, which transitively commits to all condition data through the Merkle tree. A signature is valid only for the specific set of conditions (all rungs, all blocks, all fields, coil) that produce the committed root. Changing any field in any rung changes the root and invalidates all signatures.

### 6.4 Wallet Theft Prevention

A malicious sender cannot construct a different set of conditions that hashes to the same root (SHA256 collision resistance). The recipient computes their own root from the conditions they expect and verifies it matches the output before accepting payment.

---

## 7. Wallet Protocol

### 7.1 Receiving Funds

1. Recipient constructs their desired conditions (rungs, blocks, fields, coil)
2. Recipient computes the Merkle root locally
3. Recipient gives the sender the 32-byte root (analogous to giving a Bitcoin address)
4. Sender creates an output: `value + 0xC2 + root`
5. Recipient stores the full conditions in their wallet alongside the UTXO reference

### 7.2 Spending Funds

1. Wallet retrieves stored conditions for the UTXO being spent
2. Wallet selects which rung to satisfy
3. Wallet constructs the spending witness:
   - Serialised rung conditions
   - Witness data (pubkey, signature, preimage)
   - Coil data
   - Merkle proof (sibling hashes for unrevealed leaves)
4. Wallet broadcasts the spending transaction

### 7.3 Condition Recovery

If a wallet loses its stored conditions, the UTXO cannot be spent — the root in the UTXO set provides no way to recover the conditions (preimage resistance of SHA256).

**Fallback mechanisms:**
- Wallet backup (recommended)
- Recipient can request conditions from the sender (out-of-band)
- Conditions can be derived deterministically from a seed phrase using a standard derivation path (implementation-specific)

This matches Bitcoin's P2WSH model, where losing the redeemScript makes the output unspendable. It is a well-understood trade-off accepted by the Bitcoin ecosystem.

---

## 8. Implementation

### 8.1 Source Files

| File | Purpose |
|------|---------|
| `src/rung/types.h` | `0xC2` version byte constant (`RUNG_MLSC_PREFIX`) |
| `src/rung/serialize.cpp` | `ComputeRungLeaf()`, `ComputeCoilLeaf()` |
| `src/rung/conditions.cpp` | `ComputeConditionsRoot()`, binary Merkle tree builder |
| `src/rung/conditions.h` | `conditions_root` field in `RungConditions` |
| `src/rung/evaluator.cpp` | Merkle proof verification in `VerifyRungTx()` |
| `src/rung/sighash.cpp` | Sighash uses `conditions_root` directly |
| `src/coins.h` / `src/coins.cpp` | UTXO entry format: `(value, conditions_root)` |
| `src/validation.cpp` | Output validation: accepts `0xC2 + root` format, stores root in UTXO |
| `src/script/interpreter.cpp` | Recognises `0xC2` prefix, routes to MLSC verification |

### 8.2 Core Functions

**Merkle tree builder:**
```cpp
uint256 ComputeRungLeaf(const Rung& rung);
uint256 ComputeCoilLeaf(const RungCoil& coil);
uint256 ComputeRelayLeaf(const Relay& relay);
uint256 ComputeConditionsRoot(const RungConditions& conditions);
bool VerifyMerkleProof(const uint256& leaf, uint32_t index,
                       const std::vector<uint256>& proof,
                       const uint256& root);
```

**Witness deserialiser:**
```cpp
bool DeserializeMLSCWitness(const std::vector<uint8_t>& data,
                            Rung& revealed_rung,
                            uint32_t& rung_index,
                            std::vector<RungField>& witness_fields,
                            std::vector<Relay>& revealed_relays,
                            RungCoil& coil,
                            std::vector<uint256>& proof_hashes);
```

### 8.3 Evaluator Impact

**None.** All 52 block evaluators operate on deserialised `RungBlock` and `RungField` structs. These structs are populated identically whether the source is inline conditions (`0xC1`) or revealed conditions from a spending witness (`0xC2`). The evaluation functions receive the same in-memory structures and produce the same results. No evaluator modifications are needed.

### 8.4 Inline Compatibility

Both output formats coexist:
- **`0xC2` (MLSC):** Standard format. UTXO stores `(value, root)`. Spending requires Merkle proof.
- **`0xC1` (inline):** Full conditions in scriptPubKey. UTXO stores full conditions. No Merkle proof required at spend time. Useful for debugging and testing.

### 8.5 Interaction with Wire Format Optimisations

| Optimisation | Compatibility |
|-------------|--------------|
| **Varint NUMERIC** | Fully compatible — affects rung serialisation format, which feeds into leaf computation |
| **Micro-header + Implicit Fields** | Fully compatible — encoding optimisations reduce the serialised rung size, producing smaller witness data |
| **RUNG_TEMPLATE_INHERIT** | Compatible — template references are resolved to full conditions before Merkle root computation; the root always reflects fully expanded conditions |

---

## 9. Worked Example

### 9.1 Setup

A 2-of-3 multisig with a CSV timelock recovery fallback (2 rungs):

```
Rung 0: [MULTISIG(2-of-3, keys A/B/C)]         ← primary spending path
Rung 1: [SIG(key D) + CSV(1008 blocks)]         ← recovery path
Coil:   UNLOCK, INLINE attestation, SCHNORR
```

### 9.2 Output Creation

**Recipient computes Merkle root locally:**

```
Rung 0 conditions:
  MULTISIG (0x0002), inverted=false
    PUBKEY_COMMIT: SHA256(pubkey_A)    = 0xaa11...  (32 B)
    PUBKEY_COMMIT: SHA256(pubkey_B)    = 0xbb22...  (32 B)
    PUBKEY_COMMIT: SHA256(pubkey_C)    = 0xcc33...  (32 B)
    NUMERIC (threshold): 2             (1 B)
    SCHEME: 0x01 (Schnorr)             (1 B)

Rung 1 conditions:
  Block 0: SIG (0x0001), inverted=false
    PUBKEY_COMMIT: SHA256(pubkey_D)    = 0xdd44...  (32 B)
    SCHEME: 0x01                        (1 B)
  Block 1: CSV (0x0101), inverted=false
    NUMERIC (blocks): 1008             (2 B)

Coil:
  coil_type=UNLOCK, attestation=INLINE, scheme=SCHNORR, address=[], conditions=[]
```

**Compute leaves (using BIP-341-style tagged hashes):**

```
rung_leaf[0] = TaggedHash("LadderLeaf", SerializeRung(rung_0))  = 0xR0R0...
rung_leaf[1] = TaggedHash("LadderLeaf", SerializeRung(rung_1))  = 0xR1R1...
coil_leaf    = TaggedHash("LadderLeaf", SerializeCoil(coil))     = 0xCOIL...
```

**Build Merkle tree (3 leaves → pad to 4):**

```
         conditions_root
            /          \
       H(R0,R1)     H(COIL,EMPTY)
       /      \       /        \
   rung_0  rung_1  coil_leaf  EMPTY_LEAF
```

```
conditions_root = 0xMRMR...  (32 bytes)
```

**Recipient provides root to sender. Sender creates output:**

```
Output: value=50000, scriptPubKey = 0xC2 || 0xMRMR...
```

**UTXO stores:** `{ value: 50000, conditions_root: 0xMRMR... }`

**Nothing about the multisig, the keys, the recovery path, or the timelock is on-chain.**

### 9.3 Spending via Rung 0 (Multisig)

**Spending witness:**

```
Revealed rungs: 1
  Rung index: 0
  Rung conditions:
    MULTISIG block: PUBKEY_COMMIT[A,B,C], threshold=2, scheme=SCHNORR
  Witness data:
    PUBKEY: pubkey_A (33 B), pubkey_B (33 B), pubkey_C (33 B)
    SIGNATURE: sig_A (64 B), sig_B (64 B), (empty for C)

Coil: UNLOCK, INLINE, SCHNORR

Merkle proof: 1 sibling hash
  rung_leaf[1]  = 0xR1R1...     (recovery path — opaque hash)

  (COIL and EMPTY are computed by the verifier since coil is revealed
   and EMPTY_LEAF is a known constant)
```

**Node verification:**

```
1. Deserialise revealed rung 0, coil, and witness data
2. Compute rung_leaf[0] = TaggedHash("LadderLeaf", SerializeRung(revealed_rung_0))  = 0xR0R0...
3. Compute coil_leaf = TaggedHash("LadderLeaf", SerializeCoil(revealed_coil))  = 0xCOIL...
4. Reconstruct Merkle root:
   H(R0,R1) using R0R0... and proof hash R1R1...
   H(COIL,EMPTY) using COIL... and known EMPTY_LEAF
   root = H(H(R0,R1), H(COIL,EMPTY))
   → 0xMRMR...  matches UTXO.conditions_root  ✓
5. Merge conditions + witness:
   SHA256(pubkey_A) == 0xaa11...  ✓
   SHA256(pubkey_B) == 0xbb22...  ✓
   SHA256(pubkey_C) == 0xcc33...  ✓
   Verify sig_A against pubkey_A  ✓
   Verify sig_B against pubkey_B  ✓
   Valid sigs: 2 >= threshold 2  ✓
6. Rung 0 SATISFIED → spend valid
```

**Rung 1 (recovery path) was never revealed.** An observer sees one 32-byte sibling hash in the proof but cannot determine the recovery path's structure, keys, or timelock value.

---

## 10. Design Decisions

| Decision | Resolution | Rationale |
|----------|-----------|-----------|
| **Coil positioning** | Inside the Merkle tree (final leaf) | Keeps UTXO at 40 bytes; coil proof hash is minimal overhead |
| **Tree type** | Binary Merkle | Cheapest for common case (single-sig: 0 proof hashes); max 4 hashes for 16 rungs |
| **Conditions at creation** | Not included — output is root only (P2WSH model) | Eliminates fake conditions from ever appearing on-chain |
| **Pruning / recovery** | Wallet responsibility | Same as P2WSH redeemScript — well-understood trade-off |
| **Multi-rung reveals** | Single rung + relays only (consensus enforced) | Maximises privacy; no benefit to revealing unused paths |
| **Field hardening** | Not needed | Merkle root already makes UTXO opaque; fake conditions are never published; double-hashing adds complexity without benefit |

---

## 11. Summary

Merkelised Ladder Script Conditions (MLSC) is the standard Ladder Script output format. Outputs contain only a 32-byte Merkle root. The full conditions — including all PUBKEY_COMMITs, hash fields, timelocks, thresholds, and coil metadata — exist only in the wallets of the transaction participants. They are revealed on-chain only when the output is spent, in the spending witness, which is prunable.

Fake conditions (arbitrary data disguised as PUBKEY_COMMITs) produce unspendable outputs. Since these outputs are never spent, the fake conditions are never revealed. The blockchain sees only 32 bytes of opaque Merkle root — identical to Bitcoin P2WSH and P2TR.

**The result:**

- **UTXO set:** 40 bytes per entry, fixed, zero user-chosen data
- **Block data at creation:** 42-byte outputs (value + root), no conditions
- **Block data at spend:** Conditions in witness, prunable, only the used path
- **Fake data:** Never touches the network — dies with the spammer
- **Privacy:** Unused paths permanently hidden behind Merkle proof hashes
- **Weight:** 12–23% heavier than Bitcoin equivalents; 11–73% lighter than inline Ladder Script over full lifecycle
- **Evaluators:** All 52 block types unchanged
- **Quantum resistance:** Preserved — pubkeys hidden until spend time
