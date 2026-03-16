# Ladder Script Engine Guide

The Ladder Script Engine is a single-page web application for building, simulating,
and deploying Ladder Script transactions on Ghost signet. It runs entirely client-side
with no build step -- open `tools/ladder-engine/index.html` in a browser.

For the block type reference, see [BLOCK_LIBRARY.md](BLOCK_LIBRARY.md). For
terminology, see [GLOSSARY.md](GLOSSARY.md).

---

## Table of Contents

1. [Tabs](#1-tabs)
2. [Toolbar](#2-toolbar)
3. [Block Palette](#3-block-palette)
4. [Building Ladders](#4-building-ladders)
5. [Right Panel](#5-right-panel)
6. [Simulation](#6-simulation)
7. [Convert](#7-convert)
8. [Send](#8-send)
9. [Spend](#9-spend)
10. [Review](#10-review)
11. [Navigation](#11-navigation)
12. [Import / Export](#12-import--export)
13. [Examples Library](#13-examples-library)
14. [Status Bar](#14-status-bar)
15. [Visual Reference](#15-visual-reference)

---

## 1. Tabs

The engine has six tabs in the main header:

### 1.1 Build

The default tab. Full editing: drag blocks from the palette, configure fields, manage
rungs, assign transaction inputs and outputs. The right panel shows **Properties**,
**TX**, and **RPC** sub-tabs.

### 1.2 Simulate

Step through rung evaluation visually. Power flows left to right through blocks in
each rung. The palette is locked (read-only).

- Click rung labels to step to a specific rung.
- Alt+click any block to cycle its forced state: AUTO -> FORCED ON -> FORCED OFF -> AUTO.
- The scan bar provides playback controls (reset, step back, play/pause, step forward)
  with adjustable speed from 100ms to 2000ms per step.
- Blocks show pass/fail states with colour highlighting: green for passed, red for
  failed, amber for energised.
- When all blocks in a rung pass, an **EXECUTE** button appears on the coil. Clicking
  it marks the rung as SPENT.
- The **Context** sub-tab replaces TX, showing simulation state: block height, fee
  rate, available keys, and known preimages.

### 1.3 Convert

Paste RPC JSON output to convert back into a visual ladder diagram. Works offline --
no signet connection needed. Accepts three JSON formats: `decoderung` output,
`createrungtx` format, and `decoderawtransaction` output. Click **VIEW AS LADDER**
to load the parsed result into Build mode.

### 1.4 Send

Create and fund Ladder Script outputs on Ghost signet. Build a ladder diagram in
Build mode, then switch to Send to fund it with real signet coins, sign, broadcast,
and mine. See [Section 8](#8-send) for full details.

### 1.5 Spend

Spend existing RUNG outputs on signet. Loads saved records from previous Send
operations, lets you select which condition path to satisfy, and handles signing,
timelocks, covenants, and recursion automatically. See [Section 9](#9-spend) for
full details.

### 1.6 Review

Review fund and spend JSON for all transactions created during the session. Each
entry tracks the full UTXO lifecycle: the `createrungtx` payload that funded the
output (left panel) and the `createrungtx` payload that spent it (right panel).
See [Section 10](#10-review) for full details.

---

## 2. Toolbar

### 2.1 Main Header

| Control | Description |
|---------|-------------|
| **EXAMPLES** | Opens a modal with 39 pre-built example programs. Click any card to load it into the builder. |
| **IMPORT** | Paste `createrungtx` JSON from the clipboard to load a ladder. |
| **COPY JSON** | Copies the current ladder as `createrungtx` wire-format JSON to the clipboard. |
| **PRINT** | Render the ladder diagram to PDF for printing. |
| Tab bar | **BUILD** · **SIMULATE** · **CONVERT** · **SEND** · **SPEND** · **REVIEW** |

### 2.2 Ladder Toolbar (Build Mode)

| Control | Description |
|---------|-------------|
| **− / level / +** | Zoom controls. Click the level display to reset to 100%. Mouse wheel also zooms (0.1 increments). Ctrl+wheel for fine zoom (0.05 steps). |
| **⌂ Reset View** | Zoom to 100% and centre the diagram. |
| **⫷ Justify Left** | Pack all blocks to the left of their rungs, removing gaps. |
| **+ RUNG** | Add a new empty rung at the bottom. |
| **CLEAR** | Delete all rungs. Prompts for confirmation. |
| **⊞ / ⊡ Fullscreen** | Toggle fullscreen view. Also bound to F11. |

### 2.3 Scan Bar (Simulate Mode)

| Control | Description |
|---------|-------------|
| **⏮ Reset** | Return to the start of the scan and clear all forced states. |
| **⏪ Step Back** | Move to the previous evaluation step. |
| **▶ Play / ⏸ Pause** | Start or pause automatic scanning. |
| **⏩ Step Forward** | Advance one evaluation step. |
| **Position** | Displays the current evaluation point: `R##.B#` (rung/block), `R##.OUT` (coil), or `READY` / `COMPLETE`. |
| **Step Counter** | Shows current step out of total steps. |
| **Speed Slider** | Adjustable scan interval from 100ms (fast) to 2000ms (slow). |
| **RESET SIM** | Clear all forced block states and spent rungs. |

---

## 3. Block Palette

The palette is organised into 10 families matching the Ladder Script block type
system. Click any family header to collapse or expand its section. Drag a block from
the palette onto a rung slot or the "+ ADD RUNG" drop area.

| Family | Blocks |
|--------|--------|
| **Signature** | SIG, MULTISIG, ADAPTOR_SIG, MUSIG_THRESHOLD, KEY_REF_SIG |
| **Timelock** | CSV, CSV_TIME, CLTV, CLTV_TIME |
| **Hash** | TAGGED_HASH |
| **Covenant** | CTV, VAULT_LOCK, AMOUNT_LOCK |
| **Recursion** | RECURSE_SAME, RECURSE_MODIFIED, RECURSE_UNTIL, RECURSE_COUNT, RECURSE_SPLIT, RECURSE_DECAY |
| **Anchor** | ANCHOR, ANCHOR_CHANNEL, ANCHOR_POOL, ANCHOR_RESERVE, ANCHOR_SEAL, ANCHOR_ORACLE, DATA_RETURN |
| **PLC** | HYSTERESIS_FEE, HYSTERESIS_VALUE, TIMER_CONTINUOUS, TIMER_OFF_DELAY, LATCH_SET, LATCH_RESET, COUNTER_DOWN, COUNTER_PRESET, COUNTER_UP, COMPARE, SEQUENCER, ONE_SHOT, RATE_LIMIT, COSIGN |
| **Compound** | TIMELOCKED_SIG, HTLC, HASH_SIG, PTLC, CLTV_SIG, TIMELOCKED_MULTISIG |
| **Governance** | EPOCH_GATE, WEIGHT_LIMIT, INPUT_COUNT, OUTPUT_COUNT, RELATIVE_VALUE, ACCUMULATOR |
| **Legacy** | P2PK_LEGACY, P2PKH_LEGACY, P2SH_LEGACY, P2WPKH_LEGACY, P2WSH_LEGACY, P2TR_LEGACY, P2TR_SCRIPT_LEGACY |

59 block types total (HASH_PREIMAGE and HASH160_PREIMAGE are deprecated -- use HTLC
or HASH_SIG instead). For detailed documentation on each, see
[BLOCK_LIBRARY.md](BLOCK_LIBRARY.md) or the [Block Reference](../tools/block-docs/).

---

## 4. Building Ladders

### 4.1 Adding Rungs

Click **+ RUNG** in the toolbar or drag a block to the empty area below existing rungs.
Maximum 16 rungs per ladder. Rungs are evaluated with OR logic: first satisfied rung
wins.

### 4.2 Adding Blocks

Drag a block from the palette to a rung slot. Each rung holds a maximum of 8 blocks.
Blocks within a rung are evaluated with AND logic: all must pass.

### 4.3 Rung Controls

| Action | Method |
|--------|--------|
| **Reorder** | Hover over the rung number to reveal ▲/▼ arrows, or drag the rung number. |
| **Delete** | Click the ✕ on hover. |
| **Rename** | Double-click the rung number. Press Enter to save, Escape to cancel. |
| **Right-click** | Context menu: RENAME, INSPECT, CLEAR INPUTS, CLEAR OUTPUT. |

### 4.4 Block Interactions

| Action | Method |
|--------|--------|
| **Select** | Click a block to edit its properties in the right panel. |
| **Rename** | Double-click the block label, or right-click ->RENAME. |
| **Configure** | Click the block or right-click ->INSPECT to open the full modal. |
| **Invert** | Right-click -> INVERT (NOT). Toggles the inverted flag. Key-consuming blocks (SIG, MULTISIG, etc.) cannot be inverted. |
| **Duplicate** | Right-click ->DUPLICATE. |
| **Delete** | Click ✕ on hover, right-click ->DELETE, or press Delete/Backspace. |
| **Reorder** | Drag blocks left/right within a rung, or across rungs. |

### 4.5 Coil Configuration

Click the coil at the right end of a rung to configure it.

**Visual coil types** (diagram display):

| Type | Symbol | Meaning |
|------|--------|---------|
| Standard | `( )` | Standard unlock |
| Latch | `(L)` | Latch set |
| Unlatch | `(U)` | Unlatch |
| Retentive | `(M)` | Retentive memory |
| Negated | `(/)` | Negated output |
| Relay | `◇R` | Internal reference --other rungs reference via input contacts |

**Wire-level coil types** (RPC output, under "C++ RPC coil settings"):

| Type | Code | Meaning |
|------|------|---------|
| UNLOCK | 0x01 | Standard spend, no constraints |
| UNLOCK_TO | 0x02 | Spend to a specific destination address |
| COVENANT | 0x03 | Constrain the spending transaction's outputs |

Additional wire-level fields: **attestation** (default INLINE) and **scheme**
(default SCHNORR).

### 4.6 Input Configuration

Click the input contact at the left end of a rung to assign TX inputs (UTXO
references) and relay references from other rungs. A ⚠ badge appears when inputs
are unassigned.

---

## 5. Right Panel

The right panel contains tabbed sections that change based on the current tab and
selection.

### 5.1 Properties (Build)

Visible when a block is selected:

- Block name / label input field.
- **Inverted (NOT)** checkbox.
- Field values editor with type-specific inputs (public keys, hashes, integers, etc.).
- Info section showing the block's family name and type ID hex code.
- Expand button to open the full configuration modal.

### 5.2 TX (Build)

Manages the raw transaction structure:

- **Inputs:** add/remove, configure UTXO references (txid, vout), amounts, sequences.
- **Outputs:** add/remove, configure amounts and destination addresses.
- **Locktime** field.

### 5.3 Context (Simulate)

Replaces TX during simulation. Displays and allows editing of:

- Block height (manual entry).
- Fee rate.
- Available signing keys.
- Known hash preimages.
- Available UTXOs.

### 5.4 RPC (All Tabs)

Displays the current ladder as `createrungtx` wire-format JSON, updating live as the
ladder is edited. Warnings shown for unassigned outputs and configuration issues.

In Simulate mode, JSON entries are colour-highlighted: green for executed rung, red
for blocked, amber for currently stepping.

---

## 6. Simulation

### 6.1 Stepping Through Execution

1. Switch to **SIMULATE**.
2. Press **▶** to auto-scan, or **⏩** to step one block at a time.
3. Watch power flow left to right. Each block lights green (passed) or red (failed).
4. When all blocks in a rung pass, the coil energises with an amber glow.
5. The position indicator shows `R##.B#` for the current point, `R##.OUT` at the coil,
   or `COMPLETE` when the scan finishes.

### 6.2 Force States

Alt+click any block to cycle:

| State | Indicator | Behaviour |
|-------|-----------|----------|
| **AUTO** | Default | Evaluates normally. |
| **FORCED ON** | Green highlight | Always SATISFIED. |
| **FORCED OFF** | Red highlight | Always UNSATISFIED. |

### 6.3 Execute and Spend

When a rung is fully energised, an **EXECUTE** button appears on the coil. Clicking
it marks the rung as SPENT (green indicator). Spending cascades to shared inputs.

### 6.4 Reset

- **RESET SIM** clears all forced states and spent rungs.
- **⏮** returns to the beginning of the scan without clearing forces.

---

## 7. Convert

The Convert tab provides offline JSON-to-ladder conversion:

1. Paste JSON into the text area.
2. Click **VIEW AS LADDER** to parse and load into Build mode.
3. **PASTE FROM CLIPBOARD** fills the text area from the system clipboard.
4. **CLEAR** empties the text area.

Accepted formats:
- `decoderung` RPC output
- `createrungtx` JSON
- `decoderawtransaction` output (v4 transactions with `rung_conditions`)

---

## 8. Send

The Send tab creates and funds Ladder Script outputs on Ghost signet. Build your
ladder in Build mode, then switch to Send to deploy it.

### 8.1 Connection

The engine connects to Ghost signet via an API proxy. The proxy URL is determined
automatically: `localhost:8801` for local development, `bitcoinghost.org` for
production. Connection status shows **GHOST SIGNET ONLINE** (green) or **SIGNET
OFFLINE** (red), with current block height and mempool info.

### 8.2 Wallet

| Feature | Description |
|---------|-------------|
| **Balance** | tBTC and sats display, unconfirmed balance, TX count, REFRESH button. |
| **Address** | GENERATE NEW ADDRESS button with copy. |
| **Faucet** | Input a signet address + REQUEST 0.001 tBTC button. |
| **UTXOs** | LOAD button shows available spendable outputs (txid, vout, amount, confirmations). |

### 8.3 Build & Broadcast

The pipeline uses the current ladder diagram from Build mode:

1. **Select scheme** --dropdown: SCHNORR, ECDSA, FALCON-512, FALCON-1024,
   DILITHIUM-3, SPHINCS+. Auto-detected from diagram blocks when possible.
2. **FUND FROM WALLET** --replaces example inputs with real wallet UTXOs, generates
   keypairs (supports PQ schemes), computes change output automatically.
3. **Creates** the v4 RUNG_TX via `createrungtx` RPC.
4. **Signs** all inputs via `signrawtransaction`.
5. **Broadcasts** via `sendrawtransaction`.
6. **Mines** a block to confirm (optional).

After broadcast, the output record (keys, txid, conditions) is saved to localStorage
so the Spend tab can find it. The fund JSON is also saved to the session log for the
Review tab.

### 8.4 Additional Tools

| Tool | Description |
|------|-------------|
| **TX LOOKUP** | Fetch any transaction by txid with detailed output display. |
| **DECODE RAW TX** | Paste raw hex to decode. |
| **VALIDATE RUNG TX** | Paste raw hex to validate against consensus rules. |
| **RECENT BLOCKS** | Shows recent block data. |
| **TX HISTORY** | Session log of broadcast transactions with confirmation tracking. |

All COPY buttons show green "✓ COPIED" confirmation feedback.

---

## 9. Spend

The Spend tab consumes existing RUNG outputs on signet.

### 9.1 Saved Records

Lists all RUNG outputs saved by previous Send operations (from localStorage). Each
record shows txid, scheme, amount, timestamp, rung count, and key count. Records can
be deleted individually.

### 9.2 Manual Lookup

Enter a txid (64 hex chars) + vout number and click **LOAD**. If the output matches
a saved record, keys are auto-loaded.

### 9.3 Spending an Output

After selecting a record or loading a txid:

1. **Select output** --if the transaction has multiple vouts, choose which to spend.
2. **Select condition path** --if the output has multiple rungs (OR paths), choose
   which rung to satisfy. The conditions display shows all rungs with block types and
   highlights the active path with "SPENDING THIS".
3. **Signing keys** --shows pubkey/privkey pairs stored with the record.
4. **Destination address** --enter an address, or leave blank to auto-generate one.
   UNLOCK_TO coils force a specific destination.
5. **SIGN & SPEND** --executes the full spending workflow:
   - Plans the spend (signer blocks, timelocks, output classification).
   - Looks up the UTXO on-chain.
   - Computes fees (accounts for PQ witness overhead).
   - Handles COSIGN co-inputs, CTV children, RECURSE outputs, ACCUMULATOR proofs.
   - Signs, broadcasts, and optionally mines.

A real-time **SPEND LOG** shows each step of the process. On success, the confirmed
txid is displayed.

### 9.4 URL Parameters

The Spend tab supports direct linking: `?spend_txid=...&spend_vout=...` pre-loads
the specified output.

---

## 10. Review

The Review tab shows fund and spend JSON side by side for every transaction created
during the session. Each entry represents one UTXO lifecycle.

### 10.1 Session Log

The left sidebar lists all session transactions. Each entry shows:

- **FUND / SPEND badges** -- green when that JSON is recorded, dim when not yet available.
- **Fund txid** -- the transaction that created the RUNG output.
- **Timestamp** -- relative time since the transaction was created.

Entries are created automatically when you broadcast from the Send tab. When you
later spend that output from the Spend tab, the spend JSON is attached to the same
entry.

### 10.2 JSON Panels

Select an entry to view two side-by-side panels:

| Panel | Content |
|-------|---------|
| **FUND JSON** (left) | The `createrungtx` payload that created the output. Inputs, outputs, conditions, relays. |
| **SPEND JSON** (right) | The `createrungtx` payload that spent the output. Inputs referencing the fund txid, destination outputs. |

Each panel has a **COPY** button. The header bar shows both txids (fund and spend)
with individual copy buttons.

### 10.3 Controls

| Control | Description |
|---------|-------------|
| **REFRESH** | Reload the session log from localStorage. |
| **CLEAR** | Delete all session log entries. |

Session data persists across page reloads (stored in localStorage under
`ghost_session_txlog`). Maximum 50 entries.

---

## 11. Navigation

### 10.1 Mouse

| Input | Action |
|-------|--------|
| Scroll wheel | Zoom in/out (0.1 increments). |
| Ctrl + scroll wheel | Fine zoom (0.05 increments). |
| Shift + scroll wheel | Horizontal pan. |
| Middle-click drag | Pan the view. |
| Right-click drag | Pan the view. |
| Shift + left-click drag | Pan the view. |

### 10.2 Keyboard

| Key | Action |
|-----|--------|
| Delete / Backspace | Delete the selected block. |
| Escape | Deselect or close modals. |
| Enter | Save field edits or confirm. |
| F11 | Toggle fullscreen. |

---

## 12. Import / Export

### 12.1 Import JSON

Click **IMPORT** in the header. Paste `createrungtx` JSON. The engine parses and
populates the ladder. The current diagram is replaced.

### 12.2 Export JSON

Click **COPY JSON** in the header. The current ladder is serialised to `createrungtx`
format and copied to the clipboard. The RPC sub-tab shows the live JSON for manual
inspection.

### 12.3 Print

Click **PRINT** to render the ladder diagram as a PDF.

---

## 13. Examples Library

Click **EXAMPLES** in the header. The library contains 39 pre-built examples covering:

- Single-sig and multisig patterns
- HTLCs, PTLCs, and atomic swaps
- Covenant chains and recursion
- Post-quantum anchor patterns
- Governance gates and spending controls
- DCA vaults and streaming payments
- State machines (latches, counters, sequencers)
- Legacy block wrapping
- MLSC Merkle root outputs

Click any example card to load it into the builder (replaces the current ladder).

---

## 14. Status Bar

| Element | Description |
|---------|-------------|
| **Rung count** | Number of rungs (16 max). |
| **Block count** | Total blocks (8/rung max). |
| **Energised count** | (Simulate) Currently energised rungs. |
| **Warnings** | Unassigned rungs, missing OUTPUT_REF assignments. |
| **Validation** | VALID or error/warning count. |
| **Tooltip toggle** | `? ON` / `? OFF` --context-sensitive help tooltips. |
| **Version** | GHOST LADDER v2.0 |

---

## 15. Visual Reference

### Block States

| State | Colour | Meaning |
|-------|--------|---------|
| Normal | Grey | Not yet evaluated. |
| Energised | Amber | Condition satisfied. |
| Passed | Green | Passed during simulation step. |
| Failed | Red | Failed during simulation step. |
| Selected | White border | Selected for editing. |
| Forced ON | Green highlight | Override: always SATISFIED. |
| Forced OFF | Red highlight | Override: always UNSATISFIED. |

### Wire States

| State | Colour | Meaning |
|-------|--------|---------|
| De-energised | Grey | No power flow. |
| Energised | Amber | Power flowing. |
| Stepping | Green | Currently being evaluated. |

### Coil States

| State | Colour | Meaning |
|-------|--------|---------|
| Unassigned | Grey | No TX output linked. |
| TX assigned | Cyan | Linked to a transaction output. |
| Energised | Amber glow | All blocks satisfied. |
| Relay | Dashed amber border | Internal reference coil. |
| Referenced | Green | Another rung references this coil. |
| Spent | Green "SPENT" label | Executed in simulation. |
