# Ladder Script Engine Guide

The Ladder Script Engine is a single-page application for building, simulating, and
deploying Ladder Script transactions. It provides a visual ladder diagram editor with
drag-and-drop block placement, step-through simulation, signet integration, and full
JSON import/export.

This guide documents every feature of the engine. For the block type reference, see
[BLOCK_LIBRARY.md](BLOCK_LIBRARY.md). For terminology, see [GLOSSARY.md](GLOSSARY.md).

---

## Table of Contents

1. [Modes](#1-modes)
2. [Toolbar](#2-toolbar)
3. [Block Palette](#3-block-palette)
4. [Building Ladders](#4-building-ladders)
5. [Right Panel](#5-right-panel)
6. [Simulation](#6-simulation)
7. [Navigation](#7-navigation)
8. [Import / Export](#8-import--export)
9. [Examples Library](#9-examples-library)
10. [Signet Integration](#10-signet-integration)
11. [Status Bar](#11-status-bar)
12. [Visual Reference](#12-visual-reference)

---

## 1. Modes

The engine has four modes, selectable via the tabs in the main header. **Build** and
**Simulate** are the primary modes; Watch is a passive monitor with limited utility,
and Signet connects to a live node for transaction deployment.

### 1.1 Build Mode

The default mode. Full editing is available: drag blocks from the palette, configure
field values, manage rungs, and assign transaction inputs and outputs. The right panel
shows the **Properties**, **TX**, and **RPC** tabs.

### 1.2 Simulate Mode

Step through rung evaluation visually. Power flows left to right through blocks in each
rung. The palette is locked (read-only).

- Click rung labels to step to a specific rung.
- Alt+click any block to cycle its forced state: AUTO → FORCED ON → FORCED OFF → AUTO.
- The scan bar provides playback controls (reset, step back, play/pause, step forward)
  with adjustable speed from 100ms to 2000ms per step.
- Blocks show pass/fail states with colour highlighting: green for passed, red for
  failed, amber for energised.
- When all blocks in a rung pass, an **EXECUTE** button appears on the coil. Clicking
  it marks the rung as SPENT.
- The **Context** tab replaces the TX tab, showing simulation state variables: block
  height, fee rate, available keys, and known preimages.

### 1.3 Watch Mode

> **Note:** Watch mode has limited utility in its current form — all rungs evaluate
> simultaneously against the live block height rather than stepping through individually.
> It is primarily a passive monitor.

Watch mode polls the signet proxy for the current block height and updates the
simulation context automatically. The palette is locked. A **LIVE** indicator is
displayed when the signet connection is active, along with the live height.

### 1.4 Signet Mode

Submit transactions to Ghost signet via the RPC proxy. Provides:

- **Wallet integration:** balance display, address generation, and a faucet button
  (Request 0.001 tBTC).
- **UTXO management:** load and select spendable outputs.
- **Transaction workflow:** CREATERUNGTX → SIGNRUNGTX → BROADCAST.
- **Inspection tools:** DECODE LADDER (parse ladder witness hex), DECODE RAW TX (parse
  any raw transaction hex).
- **VALIDATE:** structural validation against signet consensus rules.
- Connection status shows **GHOST SIGNET ONLINE** (green) or **SIGNET OFFLINE**.

---

## 2. Toolbar

### 2.1 Main Header

| Control | Description |
|---------|-------------|
| **EXAMPLES** | Opens a modal with 30 pre-built example programs. Click any card to load it into the builder (replaces the current ladder). |
| **IMPORT** | Paste `createrungtx` JSON from the clipboard to load a ladder. |
| **COPY JSON** | Copies the current ladder as `createrungtx` wire-format JSON to the clipboard. |
| **PRINT** | Render the ladder diagram to PDF for printing. |
| Mode tabs | **BUILD** · **SIMULATE** · **WATCH** · **SIGNET** |

### 2.2 Ladder Toolbar (Build Mode)

| Control | Description |
|---------|-------------|
| **− / level / +** | Zoom controls. Click the level display to reset to 100%. Mouse wheel also zooms (0.1 increments). Ctrl+wheel for fine zoom (0.05 steps). |
| **⌂ Reset View** | Zoom to 100% and centre the diagram. |
| **⫷ Justify Left** | Pack all blocks to the left of their rungs, removing gaps. |
| **+ RUNG** | Add a new empty rung at the bottom. |
| **CLEAR** | Delete all rungs. Prompts for confirmation. |
| **⊞ / ⊡ Fullscreen** | Toggle fullscreen view. Also bound to F11. |

### 2.3 Scan Bar (Simulate and Watch Modes)

| Control | Description |
|---------|-------------|
| **⏮ Reset** | Return to the start of the scan and clear all forced states. |
| **⏪ Step Back** | Move to the previous evaluation step. |
| **▶ Play / ⏸ Pause** | Start or pause automatic scanning. |
| **⏩ Step Forward** | Advance one evaluation step. |
| **Position** | Displays the current evaluation point: `R##.B#` (rung/block), `R##.OUT` (coil), or `READY` / `COMPLETE`. |
| **Step Counter** | Shows current step out of total steps. |
| **Speed Slider** | Adjustable scan interval from 100ms (fast) to 2000ms (slow). |
| **RESET SIM** | Clear all forced block states and spent rungs without leaving simulate mode. |

---

## 3. Block Palette

The palette is organised into families. Click any family header to collapse or expand
its section. Drag a block from the palette onto a rung slot or the "+ ADD RUNG" drop
area to simultaneously create a rung and place the block.

| Category | Blocks |
|----------|--------|
| **Signatures** | SIG, MULTISIG, ADAPTOR_SIG, MUSIG_THRESHOLD |
| **Timelocks** | CSV, CSV_TIME, CLTV, CLTV_TIME |
| **Hash Proofs** | HASH_PREIMAGE, HASH160_PREIMAGE, TAGGED_HASH |
| **Covenants** | CTV, VAULT_LOCK, AMOUNT_LOCK |
| **Recursive** | RECURSE_SAME, RECURSE_MODIFIED, RECURSE_UNTIL, RECURSE_COUNT, RECURSE_SPLIT, RECURSE_DECAY |
| **Anchors** | ANCHOR, ANCHOR_CHANNEL, ANCHOR_POOL, ANCHOR_RESERVE, ANCHOR_SEAL, ANCHOR_ORACLE |
| **Hysteresis** | HYSTERESIS_FEE, HYSTERESIS_VALUE |
| **Timers** | TIMER_CONTINUOUS, TIMER_OFF_DELAY |
| **Latches** | LATCH_SET, LATCH_RESET |
| **Counters** | COUNTER_DOWN, COUNTER_PRESET, COUNTER_UP |
| **Operations** | COMPARE, SEQUENCER, ONE_SHOT, RATE_LIMIT |
| **Composite** | COSIGN, TIMELOCKED_SIG, HTLC, HASH_SIG, PTLC, CLTV_SIG, TIMELOCKED_MULTISIG |
| **Protocol** | EPOCH_GATE, WEIGHT_LIMIT, INPUT_COUNT, OUTPUT_COUNT, RELATIVE_VALUE, ACCUMULATOR |

For detailed documentation on each block type, see [BLOCK_LIBRARY.md](BLOCK_LIBRARY.md).

---

## 4. Building Ladders

### 4.1 Adding Rungs

Click **+ RUNG** in the toolbar or drag a block to the empty area below existing rungs.
The maximum is 16 rungs per ladder. Rungs are evaluated with OR logic: the first
satisfied rung wins.

### 4.2 Adding Blocks

Drag a block from the palette to a rung slot. Each rung holds a maximum of 8 blocks.
Blocks within a rung are evaluated with AND logic: all must pass for the rung to be
satisfied.

### 4.3 Rung Controls

| Action | Method |
|--------|--------|
| **Reorder** | Hover over the rung number to reveal ▲/▼ arrows. Click to move up or down. Alternatively, drag the rung number to reposition. |
| **Delete** | Click the ✕ that appears on hover. |
| **Rename** | Double-click the rung number to enter a custom label. Press Enter to save or Escape to cancel. |
| **Right-click** | Context menu with RENAME, INSPECT, CLEAR INPUTS, and CLEAR OUTPUT options. |

### 4.4 Block Interactions

| Action | Method |
|--------|--------|
| **Select** | Click a block to view and edit its properties in the right panel. |
| **Rename** | Double-click the block label, or right-click → RENAME. |
| **Configure** | Click the block or right-click → INSPECT to open the full configuration modal. |
| **Invert** | Right-click → INVERT (NOT). Toggles the block's inverted flag so that SATISFIED becomes UNSATISFIED and vice versa. |
| **Duplicate** | Right-click → DUPLICATE. |
| **Delete** | Click the ✕ on hover, right-click → DELETE, or select the block and press Delete or Backspace. |
| **Reorder** | Drag blocks left/right within a rung, or drag across rungs. |

### 4.5 Coil (Output) Configuration

Click the coil at the right end of a rung to configure it.

- **Coil Type:** UNLOCK (standard spend) or RELAY (internal reference for other rungs).
- **TX Output assignment:** link the rung to a specific transaction output.
- **Right-click menu:** RENAME, INSPECT, CLEAR OUTPUT.

Visual indicators:

- Relay coils display a dashed amber border.
- TX-assigned coils display a cyan border.

### 4.6 Input Configuration

Click the input contact at the left end of a rung. From here you can assign TX inputs
(UTXO references) and relay references from other rungs. A ⚠ badge is shown when
inputs are unassigned.

---

## 5. Right Panel

The right panel occupies the right side of the screen and contains tabbed sections that
change based on the current mode and selection.

### 5.1 Properties Tab (Build Mode)

Visible when a block is selected. Contains:

- Block name / label input field.
- **Inverted (NOT)** checkbox to toggle the block's inversion flag.
- Field values editor with type-specific inputs (public keys, hashes, integers, etc.).
- Info section showing the block's family name and type ID hex code.
- Expand button to open the full configuration modal.

### 5.2 TX Tab (Build Mode)

Manages the raw transaction structure:

- **Transaction inputs:** add/remove inputs, configure UTXO references (`txid`, `vout`),
  amounts, and sequence numbers.
- **Transaction outputs:** add/remove outputs, configure amounts and destination
  addresses.
- **Locktime** field.

### 5.3 Context Tab (Simulate and Watch Modes)

Replaces the TX tab during simulation. Displays and allows editing of the simulation
state:

- Block height (manual or auto-incrementing in Watch mode).
- Fee rate.
- Available signing keys.
- Known hash preimages.
- Available UTXOs.

### 5.4 RPC Tab (All Modes)

Displays the current ladder as wire-format JSON in `createrungtx` format. This view
updates live as the ladder is edited. Warnings are shown for unassigned outputs and
configuration issues.

In simulate mode, JSON entries are colour-highlighted:

- Green: executed rung.
- Red: blocked rung.
- Amber: currently stepping.

---

## 6. Simulation

### 6.1 Stepping Through Execution

1. Switch to **SIMULATE** mode using the mode tabs.
2. Press **▶** to auto-scan, or **⏩** to step one block at a time.
3. Watch power flow left to right through each block. Each block lights green (passed)
   or red (failed) as it is evaluated.
4. When all blocks in a rung pass, the coil energises with an amber glow.
5. The position indicator in the scan bar shows `R##.B#` for the current evaluation
   point, `R##.OUT` when evaluating a coil, or `COMPLETE` when the scan finishes.

### 6.2 Force States

Alt+click any block to cycle through forced states:

| State | Indicator | Behaviour |
|-------|-----------|----------|
| **AUTO** | Default | Block evaluates normally based on its field values. |
| **FORCED ON** | Green highlight | Block always returns SATISFIED regardless of fields. |
| **FORCED OFF** | Red highlight | Block always returns UNSATISFIED regardless of fields. |

Use forced states to test alternative execution paths without modifying field values.

### 6.3 Execute and Spend

When a rung is fully energised (all blocks pass), an **EXECUTE** button appears on the
coil. Clicking EXECUTE marks the rung as SPENT, shown with a green "SPENT" indicator.

Spending cascades: if a spent rung's inputs are shared with other rungs, those inputs
are consumed. Other rungs referencing the same inputs will reflect the change.

### 6.4 Reset

- **RESET SIM** clears all forced states and spent rungs.
- **⏮** returns to the beginning of the scan without clearing forces.

---

## 7. Navigation

### 7.1 Mouse

| Input | Action |
|-------|--------|
| Scroll wheel | Zoom in/out (0.1 increments). |
| Ctrl + scroll wheel | Fine zoom (0.05 increments). |
| Shift + scroll wheel | Horizontal pan. |
| Middle-click drag | Pan the view. |
| Right-click drag | Pan the view. |
| Shift + left-click drag | Pan the view. |

### 7.2 Keyboard

| Key | Action |
|-----|--------|
| Delete / Backspace | Delete the selected block (when focus is not in a text input). |
| Escape | Deselect the current selection or close open modals. |
| Enter | Save field edits or confirm modal actions. |
| F11 | Toggle fullscreen. |

---

## 8. Import / Export

### 8.1 Import JSON

Click **IMPORT** in the main header. Paste `createrungtx` JSON into the dialog. The
engine parses the JSON and populates rungs, blocks, field values, and transaction
assignments. The current ladder is replaced.

### 8.2 Export JSON

Click **COPY JSON** in the main header. The current ladder is serialised to
`createrungtx` wire format and copied to the clipboard. The RPC tab always shows the
live JSON representation and can be used for manual inspection before copying.

### 8.3 Print

Click **PRINT** to render the ladder diagram as a PDF suitable for documentation or
review.

---

## 9. Examples Library

Click **EXAMPLES** in the main header to open the examples modal. The library contains
30 pre-built example programs covering all major Ladder Script patterns:

- Simple P2PKH spends
- Multisig vaults
- HTLCs and PTLCs
- Covenant chains
- Post-quantum anchor patterns
- Governance gates
- DCA (dollar-cost averaging) vaults
- State machines
- And more

Click any example card to load it into the builder. The current ladder is replaced
entirely.

---

## 10. Signet Integration

### 10.1 Connection

Switch to **SIGNET** mode. The engine connects to Ghost signet via the RPC proxy.
Connection status is displayed: **GHOST SIGNET ONLINE** (green) when connected, or
**SIGNET OFFLINE** when the proxy is unreachable.

### 10.2 Wallet

The signet wallet provides:

- **Balance display** showing the current tBTC balance.
- **Address generation** for receiving funds.
- **Faucet** button to request 0.001 tBTC for testing.
- **LOAD UTXOs** to fetch available spendable outputs from the wallet.

### 10.3 Transaction Workflow

1. Build your ladder in **BUILD** mode.
2. Switch to **SIGNET** mode.
3. Click **CREATERUNGTX** to construct the transaction from the current ladder.
4. Click **SIGNRUNGTX** to sign with available keys.
5. Click **BROADCAST** to submit the signed transaction to the signet.

### 10.4 Decoding and Validation

| Control | Description |
|---------|-------------|
| **DECODE LADDER** | Parse ladder witness hex back into a human-readable ladder structure. |
| **DECODE RAW TX** | Parse any raw transaction hex for inspection. |
| **VALIDATE** | Check structural validity of the current ladder against signet consensus rules. Reports any violations. |

---

## 11. Status Bar

The bottom bar displays contextual information that varies by mode:

| Element | Description |
|---------|-------------|
| **Rung count** | Number of rungs in the ladder, with the 16-rung maximum noted. |
| **Block count** | Total blocks, with per-rung 8-block maximum noted. |
| **Energised count** | (Simulate mode) Number of currently energised rungs. |
| **Height display** | (Watch mode) Signet live height and local simulation height. |
| **Warnings** | Alerts for unassigned rungs, missing OUTPUT_REF assignments, and other issues. |
| **Tooltip toggle** | `? ON` / `? OFF` — enables or disables context-sensitive help tooltips on hover. |
| **Version** | Displays the current version (GHOST LADDER v1.0). |

---

## 12. Visual Reference

### Block States

| State | Colour | Meaning |
|-------|-------|---------|
| Normal | Grey | De-energised, not yet evaluated. |
| Energised | Amber | Condition satisfied during evaluation. |
| Passed (step) | Green | Block passed during step-through simulation. |
| Failed (step) | Red | Block failed during step-through simulation. |
| Selected | White border | Currently selected for editing in the properties panel. |
| Forced ON | Green highlight | Force-overridden to always return SATISFIED. |
| Forced OFF | Red highlight | Force-overridden to always return UNSATISFIED. |

### Wire States

| State | Colour | Meaning |
|-------|-------|---------|
| De-energised | Grey | No power flow through this segment. |
| Energised | Amber | Power flowing through the wire. |
| Stepping | Green | Currently being evaluated by the scanner. |

### Coil States

| State | Colour | Meaning |
|-------|-------|---------|
| Unassigned | Grey | No transaction output linked. |
| TX assigned | Cyan | Linked to a specific transaction output. |
| Energised | Amber glow | All blocks in the rung are satisfied. |
| Relay | Dashed amber border | Internal reference coil (not a direct spend). |
| Referenced | Green | Another rung references this coil as an input. |
| Spent | Green "SPENT" label | Rung has been executed in simulation. |
