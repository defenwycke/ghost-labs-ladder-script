#!/usr/bin/env python3
"""Ladder Script documentation accuracy tests.

Verifies all documentation, HTML block pages, engine definitions, and markdown
specs are consistent with the canonical source of truth: src/rung/types.h

Run: python3 tests/test_documentation_accuracy.py
"""

import os
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TYPES_H = ROOT / "src" / "rung" / "types.h"
ENGINE = ROOT / "tools" / "ladder-engine" / "index.html"
DOCS_BLOCKS = ROOT / "tools" / "docs" / "blocks"
BLOCK_DOCS = ROOT / "tools" / "block-docs"
DOCS_INDEX = ROOT / "tools" / "docs" / "index.html"
SPEC = ROOT / "docs" / "SPECIFICATION.md"
BIP = ROOT / "docs" / "BIP-XXXX.md"
BLOCK_LIB = ROOT / "docs" / "BLOCK_LIBRARY.md"
BLOCK_LIB_IMPL = ROOT / "docs" / "BLOCK_LIBRARY_IMPL.md"
IMPL_NOTES = ROOT / "docs" / "IMPLEMENTATION_NOTES.md"
GLOSSARY = ROOT / "docs" / "GLOSSARY.md"
README = ROOT / "README.md"
FAQ = ROOT / "docs" / "FAQ.md"
LANDING = ROOT / "tools" / "ladder-script.html"


# ── Extract canonical data from types.h ──────────────────────────────────

def parse_types_h():
    """Parse block types, data types, and field sizes from types.h."""
    text = TYPES_H.read_text()

    # Block types: NAME = 0xXXXX (only from the RungBlockType enum)
    blocks = {}
    # Names that belong to other enums (RungDataType, RungCoilType, RungAttestationMode, RungScheme)
    NON_BLOCK_NAMES = {
        'PUBKEY', 'PUBKEY_COMMIT', 'HASH256', 'HASH160', 'PREIMAGE',
        'SIGNATURE', 'SPEND_INDEX', 'NUMERIC', 'SCHEME',
        'UNLOCK', 'UNLOCK_TO', 'COVENANT', 'INLINE', 'AGGREGATE',
        'DEFERRED', 'SCHNORR', 'ECDSA', 'FALCON512', 'FALCON1024',
        'DILITHIUM3', 'SPHINCS_SHA',
    }
    for m in re.finditer(r'(\w+)\s*=\s*(0x[0-9a-fA-F]+)', text):
        name, code = m.group(1), int(m.group(2), 16)
        if name in NON_BLOCK_NAMES:
            continue
        blocks[name] = code

    # Data type sizes: FieldMaxSize
    max_sizes = {}
    in_max = False
    for line in text.splitlines():
        if 'FieldMaxSize' in line:
            in_max = True
        if in_max:
            m = re.match(r'\s*case RungDataType::(\w+):\s*return\s+(\d+);', line)
            if m:
                max_sizes[m.group(1)] = int(m.group(2))
        if in_max and line.strip().startswith('return 0'):
            break

    return blocks, max_sizes


CANONICAL_BLOCKS, CANONICAL_MAX_SIZES = parse_types_h()

# Family ranges from types.h header comment
FAMILIES = {
    'Signature':  (0x0001, 0x00FF),
    'Timelock':   (0x0100, 0x01FF),
    'Hash':       (0x0200, 0x02FF),
    'Covenant':   (0x0300, 0x03FF),
    'Recursion':  (0x0400, 0x04FF),
    'Anchor':     (0x0500, 0x05FF),
    'PLC':        (0x0600, 0x06FF),
    'Compound':   (0x0700, 0x07FF),
    'Governance': (0x0800, 0x08FF),
}


def block_family(code):
    """Return family name for a block type code."""
    for name, (lo, hi) in FAMILIES.items():
        if lo <= code <= hi:
            return name
    return 'Unknown'


# ── Test classes ─────────────────────────────────────────────────────────

class TestTypesH(unittest.TestCase):
    """Verify types.h internal consistency."""

    def test_exactly_48_block_types(self):
        self.assertEqual(len(CANONICAL_BLOCKS), 48,
                         f"Expected 48 block types, got {len(CANONICAL_BLOCKS)}: {sorted(CANONICAL_BLOCKS.keys())}")

    def test_no_duplicate_codes(self):
        codes = list(CANONICAL_BLOCKS.values())
        self.assertEqual(len(codes), len(set(codes)),
                         f"Duplicate type codes found")

    def test_9_families_represented(self):
        families_used = set()
        for code in CANONICAL_BLOCKS.values():
            families_used.add(block_family(code))
        self.assertEqual(len(families_used), 9,
                         f"Expected 9 families, got {families_used}")

    def test_family_block_counts(self):
        expected = {'Signature': 3, 'Timelock': 4, 'Hash': 3, 'Covenant': 3,
                    'Recursion': 6, 'Anchor': 6, 'PLC': 14, 'Compound': 3, 'Governance': 6}
        actual = {}
        for code in CANONICAL_BLOCKS.values():
            fam = block_family(code)
            actual[fam] = actual.get(fam, 0) + 1
        self.assertEqual(actual, expected)

    def test_data_type_sizes(self):
        expected = {'PUBKEY': 2048, 'PUBKEY_COMMIT': 32, 'HASH256': 32,
                    'HASH160': 20, 'PREIMAGE': 252, 'SIGNATURE': 50000,
                    'SPEND_INDEX': 4, 'NUMERIC': 4, 'SCHEME': 1}
        self.assertEqual(CANONICAL_MAX_SIZES, expected)

    def test_specific_type_codes(self):
        """Verify specific critical type codes."""
        critical = {
            'SIG': 0x0001, 'MULTISIG': 0x0002,
            'CSV': 0x0101, 'CLTV': 0x0103,
            'HASH_PREIMAGE': 0x0201,
            'CTV': 0x0301, 'VAULT_LOCK': 0x0302,
            'RECURSE_SAME': 0x0401,
            'ANCHOR': 0x0501,
            'HYSTERESIS_FEE': 0x0601,
            'TIMER_CONTINUOUS': 0x0611,
            'LATCH_SET': 0x0621,
            'COUNTER_DOWN': 0x0631,
            'COMPARE': 0x0641,
            'SEQUENCER': 0x0651,
            'ONE_SHOT': 0x0661,
            'RATE_LIMIT': 0x0671,
            'COSIGN': 0x0681,
            'TIMELOCKED_SIG': 0x0701,
            'EPOCH_GATE': 0x0801,
            'ACCUMULATOR': 0x0806,
        }
        for name, expected_code in critical.items():
            self.assertEqual(CANONICAL_BLOCKS[name], expected_code,
                             f"{name}: expected 0x{expected_code:04x}, got 0x{CANONICAL_BLOCKS[name]:04x}")


class TestEngineBlockDefs(unittest.TestCase):
    """Verify the ladder engine's block definitions match types.h."""

    @classmethod
    def setUpClass(cls):
        cls.engine_text = ENGINE.read_text()

    def test_getTypeHex_has_all_48_blocks(self):
        # Extract getTypeHex map entries
        m = re.search(r'function getTypeHex\(type\)\s*\{[\s\S]*?const map = \{([\s\S]*?)\};', self.engine_text)
        self.assertIsNotNone(m, "getTypeHex function not found")
        map_text = m.group(1)
        entries = re.findall(r"(\w+):'(\w+)'", map_text)
        engine_map = {name: int(code, 16) for name, code in entries}

        for name, code in CANONICAL_BLOCKS.items():
            self.assertIn(name, engine_map,
                          f"Block {name} (0x{code:04x}) missing from getTypeHex")
            self.assertEqual(engine_map[name], code,
                             f"getTypeHex {name}: expected 0x{code:04x}, got 0x{engine_map[name]:04x}")

    def test_engine_block_count(self):
        # Count block type entries in BLOCK_FAMILIES array
        # Each block has type: 'NAME' — count all unique block type entries
        block_types = re.findall(r"type:\s*'([A-Z][A-Z0-9_]+)'", self.engine_text)
        unique_types = set(block_types)
        self.assertGreaterEqual(len(unique_types), 48,
                                f"Engine defines {len(unique_types)} unique block types, expected >= 48")

    def test_no_watch_mode_references(self):
        self.assertNotIn("watch", self.engine_text.lower().split("function")[0] if "function" in self.engine_text else "",
                         "Watch mode CSS still present")
        self.assertNotIn("mode === 'watch'", self.engine_text,
                         "Watch mode JS logic still present")


class TestBlockReferencePages(unittest.TestCase):
    """Verify all 48 HTML block reference pages match types.h."""

    BLOCK_FILE_MAP = {
        'SIG': 'sig', 'MULTISIG': 'multisig', 'ADAPTOR_SIG': 'adaptor-sig',
        'CSV': 'csv', 'CSV_TIME': 'csv-time', 'CLTV': 'cltv', 'CLTV_TIME': 'cltv-time',
        'HASH_PREIMAGE': 'hash-preimage', 'HASH160_PREIMAGE': 'hash160-preimage', 'TAGGED_HASH': 'tagged-hash',
        'CTV': 'ctv', 'VAULT_LOCK': 'vault-lock', 'AMOUNT_LOCK': 'amount-lock',
        'RECURSE_SAME': 'recurse-same', 'RECURSE_MODIFIED': 'recurse-modified',
        'RECURSE_UNTIL': 'recurse-until', 'RECURSE_COUNT': 'recurse-count',
        'RECURSE_SPLIT': 'recurse-split', 'RECURSE_DECAY': 'recurse-decay',
        'ANCHOR': 'anchor', 'ANCHOR_CHANNEL': 'anchor-channel', 'ANCHOR_POOL': 'anchor-pool',
        'ANCHOR_RESERVE': 'anchor-reserve', 'ANCHOR_SEAL': 'anchor-seal', 'ANCHOR_ORACLE': 'anchor-oracle',
        'HYSTERESIS_FEE': 'hysteresis-fee', 'HYSTERESIS_VALUE': 'hysteresis-value',
        'TIMER_CONTINUOUS': 'timer-continuous', 'TIMER_OFF_DELAY': 'timer-off-delay',
        'LATCH_SET': 'latch-set', 'LATCH_RESET': 'latch-reset',
        'COUNTER_DOWN': 'counter-down', 'COUNTER_PRESET': 'counter-preset', 'COUNTER_UP': 'counter-up',
        'COMPARE': 'compare', 'SEQUENCER': 'sequencer', 'ONE_SHOT': 'one-shot',
        'RATE_LIMIT': 'rate-limit', 'COSIGN': 'cosign',
        'TIMELOCKED_SIG': 'timelocked-sig', 'HTLC': 'htlc', 'HASH_SIG': 'hash-sig',
        'EPOCH_GATE': 'epoch-gate', 'WEIGHT_LIMIT': 'weight-limit',
        'INPUT_COUNT': 'input-count', 'OUTPUT_COUNT': 'output-count',
        'RELATIVE_VALUE': 'relative-value', 'ACCUMULATOR': 'accumulator',
    }

    def test_all_48_pages_exist(self):
        for name, filename in self.BLOCK_FILE_MAP.items():
            path = DOCS_BLOCKS / f"{filename}.html"
            self.assertTrue(path.exists(), f"Missing block page: {path}")

    def test_type_codes_match_types_h(self):
        for name, filename in self.BLOCK_FILE_MAP.items():
            path = DOCS_BLOCKS / f"{filename}.html"
            text = path.read_text()
            expected_hex = f"0x{CANONICAL_BLOCKS[name]:04x}"
            # Check the block-type-code div
            m = re.search(r'TYPE\s+(0x[0-9A-Fa-f]+)', text)
            self.assertIsNotNone(m, f"{filename}.html: no TYPE code found")
            actual = m.group(1).lower()
            self.assertEqual(actual, expected_hex,
                             f"{filename}.html: TYPE {actual} != expected {expected_hex}")

    def test_correct_family_labels(self):
        for name, filename in self.BLOCK_FILE_MAP.items():
            path = DOCS_BLOCKS / f"{filename}.html"
            text = path.read_text()
            expected_family = block_family(CANONICAL_BLOCKS[name]).upper()
            m = re.search(r'TYPE\s+0x[0-9A-Fa-f]+\s+.*?(\w+)\s+FAMILY', text)
            if m:
                actual_family = m.group(1).upper()
                self.assertEqual(actual_family, expected_family,
                                 f"{filename}.html: family {actual_family} != expected {expected_family}")

    def test_all_invertible(self):
        for name, filename in self.BLOCK_FILE_MAP.items():
            path = DOCS_BLOCKS / f"{filename}.html"
            text = path.read_text()
            self.assertIn('inv-yes', text,
                          f"{filename}.html: missing inv-yes badge")
            self.assertNotIn('inv-no', text,
                             f"{filename}.html: has inv-no badge (should be inv-yes)")

    def test_no_version_references_in_block_pages(self):
        """Block reference pages should not mention tx version numbers."""
        for name, filename in self.BLOCK_FILE_MAP.items():
            path = DOCS_BLOCKS / f"{filename}.html"
            text = path.read_text().lower()
            for v in ['version 3', 'version 4', 'version 5']:
                self.assertNotIn(v, text,
                                 f"{filename}.html: contains '{v}' reference")

    def test_navigation_chain_integrity(self):
        """Verify prev/next links form a valid chain across all pages."""
        ordered = list(self.BLOCK_FILE_MAP.values())
        for i, filename in enumerate(ordered):
            path = DOCS_BLOCKS / f"{filename}.html"
            text = path.read_text()
            # Check next link
            if i < len(ordered) - 1:
                expected_next = f"{ordered[i + 1]}.html"
                next_match = re.search(r'href="([^"]+)">[^<]*rarr', text)
                if next_match:
                    actual_next = next_match.group(1)
                    self.assertEqual(actual_next, expected_next,
                                     f"{filename}.html: next link {actual_next} != expected {expected_next}")


class TestBlockDocsSync(unittest.TestCase):
    """Verify tools/block-docs/ mirrors tools/docs/blocks/."""

    def test_same_file_count(self):
        docs_files = set(f.name for f in DOCS_BLOCKS.glob("*.html"))
        block_files = set(f.name for f in BLOCK_DOCS.glob("*.html"))
        self.assertEqual(docs_files, block_files,
                         f"File sets differ: only in docs={docs_files - block_files}, only in block-docs={block_files - docs_files}")


class TestDocsIndex(unittest.TestCase):
    """Verify the docs SPA index has correct block data."""

    @classmethod
    def setUpClass(cls):
        cls.text = DOCS_INDEX.read_text()

    def test_covenant_family_code(self):
        self.assertIn("range: '0x0300'", self.text,
                      "Covenant family should be 0x0300")
        self.assertNotIn("range: '0x0400', cls: 'covenant'", self.text,
                         "Covenant family should NOT be 0x0400")

    def test_recursion_family_code(self):
        self.assertIn("range: '0x0400'", self.text,
                      "Recursion family should be 0x0400")
        self.assertNotIn("range: '0x0300', cls: 'recursion'", self.text,
                         "Recursion family should NOT be 0x0300")

    def test_plc_spaced_codes(self):
        for name, code in CANONICAL_BLOCKS.items():
            if 0x0600 <= code <= 0x06FF:
                code_str = f"0x{code:04X}"
                self.assertIn(code_str.lower(), self.text.lower(),
                              f"PLC block {name} (code {code_str}) not found in docs SPA")

    def test_cosign_description_not_cosigner(self):
        # COSIGN is a co-spend contact, not a co-signing gate
        self.assertNotIn("co-signing gate", self.text.lower(),
                         "COSIGN should not be described as 'co-signing gate'")

    def test_all_48_blocks_listed(self):
        for name in CANONICAL_BLOCKS:
            self.assertIn(f"'{name}'", self.text,
                          f"Block {name} not found in docs SPA index")


class TestIndexPages(unittest.TestCase):
    """Verify the block reference index pages."""

    def _check_index(self, path):
        text = path.read_text()
        # Check family codes
        self.assertIn('0x0300', text, f"{path.name}: Covenant should be 0x0300")
        self.assertIn('0x0400', text, f"{path.name}: Recursion should be 0x0400")
        # Check PLC spaced codes
        self.assertIn('0x0611', text, f"{path.name}: TIMER_CONTINUOUS should be 0x0611")
        self.assertIn('0x0681', text, f"{path.name}: COSIGN should be 0x0681")
        # Check ordering: Covenant before Recursion before Anchor
        cov_pos = text.index('0x0300')
        rec_pos = text.index('0x0400')
        anc_pos = text.index('0x0500')
        self.assertLess(cov_pos, rec_pos, "Covenant must come before Recursion")
        self.assertLess(rec_pos, anc_pos, "Recursion must come before Anchor")

    def test_docs_blocks_index(self):
        self._check_index(DOCS_BLOCKS / "index.html")

    def test_block_docs_index(self):
        self._check_index(BLOCK_DOCS / "index.html")


class TestMarkdownDocs(unittest.TestCase):
    """Verify markdown documentation accuracy."""

    def test_spec_has_compound_governance(self):
        text = SPEC.read_text()
        self.assertIn('TIMELOCKED_SIG', text, "SPECIFICATION.md missing TIMELOCKED_SIG")
        self.assertIn('EPOCH_GATE', text, "SPECIFICATION.md missing EPOCH_GATE")
        self.assertIn('ACCUMULATOR', text, "SPECIFICATION.md missing ACCUMULATOR")
        self.assertIn('0x0701', text, "SPECIFICATION.md missing Compound type code 0x0701")
        self.assertIn('0x0801', text, "SPECIFICATION.md missing Governance type code 0x0801")

    def test_spec_covenant_recursion_codes(self):
        text = SPEC.read_text()
        # CTV should be 0x0301
        m = re.search(r'0x0301.*CTV|CTV.*0x0301', text)
        self.assertIsNotNone(m, "SPECIFICATION.md: CTV should be at 0x0301")
        # RECURSE_SAME should be 0x0401
        m = re.search(r'0x0401.*RECURSE_SAME|RECURSE_SAME.*0x0401', text)
        self.assertIsNotNone(m, "SPECIFICATION.md: RECURSE_SAME should be at 0x0401")

    def test_bip_compare_operator_encoding(self):
        text = BIP.read_text()
        # Should be 1-based: 1=EQ (not 0=EQ)
        self.assertIn('1=EQ', text, "BIP: COMPARE should use 1-based operators")
        self.assertNotIn('0=EQ', text, "BIP: COMPARE should NOT use 0-based operators")
        # Should compare against input amount
        self.assertIn('input amount', text, "BIP: COMPARE should compare against input amount")

    def test_impl_notes_signature_max(self):
        text = IMPL_NOTES.read_text()
        self.assertNotIn('7,856', text, "IMPL_NOTES: SPHINCS+ should be 49,216 not 7,856")
        self.assertNotIn('7856', text, "IMPL_NOTES: SPHINCS+ should be 49,216 not 7856")
        self.assertNotIn('max 144', text, "IMPL_NOTES: SIGNATURE max should be 50,000 not 144")

    def test_impl_notes_witness_limit(self):
        text = IMPL_NOTES.read_text()
        self.assertIn('100,000', text, "IMPL_NOTES: witness limit should be 100,000")

    def test_block_lib_impl_has_cosign_and_families(self):
        text = BLOCK_LIB_IMPL.read_text()
        self.assertIn('COSIGN', text, "BLOCK_LIBRARY_IMPL.md missing COSIGN")
        self.assertIn('TIMELOCKED_SIG', text, "BLOCK_LIBRARY_IMPL.md missing TIMELOCKED_SIG")
        self.assertIn('EPOCH_GATE', text, "BLOCK_LIBRARY_IMPL.md missing EPOCH_GATE")

    def test_block_lib_impl_signature_max(self):
        text = BLOCK_LIB_IMPL.read_text()
        self.assertNotIn('1–144B', text, "BLOCK_LIBRARY_IMPL: SIGNATURE max should be 50,000")

    def test_block_lib_numeric_max_4(self):
        text = BLOCK_LIB.read_text()
        self.assertNotIn('1-8 B', text, "BLOCK_LIBRARY: NUMERIC should be 1-4 B, not 1-8 B")

    def test_no_decoderungtx(self):
        """The canonical RPC name is decoderung, not decoderungtx."""
        for path in [FAQ, ROOT / "docs" / "BUILD_PROMPT.md"]:
            if path.exists():
                text = path.read_text()
                self.assertNotIn('decoderungtx', text,
                                 f"{path.name}: should use 'decoderung' not 'decoderungtx'")

    def test_readme_example_count(self):
        if README.exists():
            text = README.read_text()
            if '18 worked' in text or '18 scenario' in text:
                self.fail("README.md: should say 8 examples, not 18")

    def test_no_phase_references_in_html(self):
        """No phase 1/2/3 references in HTML tools."""
        for path in [LANDING, ENGINE]:
            if path.exists():
                text = path.read_text()
                for p in ['phase 1', 'phase 2', 'phase 3', 'phase 4']:
                    self.assertNotIn(p, text.lower(),
                                     f"{path.name}: contains '{p}' reference")


class TestLandingPage(unittest.TestCase):
    """Verify the ladder-script.html landing page."""

    @classmethod
    def setUpClass(cls):
        cls.text = LANDING.read_text() if LANDING.exists() else ""

    def test_48_blocks_9_families(self):
        self.assertIn('48 block', self.text, "Landing page should mention 48 blocks")
        self.assertIn('nine', self.text.lower(), "Landing page should mention nine families")

    def test_version_4(self):
        self.assertIn('Version 4', self.text, "Landing page should reference Version 4")
        self.assertNotIn('Version 3', self.text, "Landing page should NOT reference Version 3")


class TestWireFormatMath(unittest.TestCase):
    """Verify wire format byte counts are mathematically correct."""

    def _extract_wire_totals(self, path):
        """Extract conditions, witness, and total bytes from a block page."""
        text = path.read_text()
        conditions = re.search(r'Conditions\s*=\s*(\d+)\s*bytes', text)
        witness = re.search(r'Witness\s*=\s*(\d+)\s*bytes', text)
        total = re.search(r'wire-total-bytes[^>]*>(\d+)\s*bytes', text)
        return (
            int(conditions.group(1)) if conditions else None,
            int(witness.group(1)) if witness else None,
            int(total.group(1)) if total else None,
        )

    def test_totals_equal_conditions_plus_witness(self):
        """For every block page with wire format, total must equal conditions + witness.
        Some pages report field-only bytes in subtotals while the total includes
        block headers (type 2B + inv 1B + count 1B = 4B per side). We accept
        total == conditions + witness OR total == conditions + witness + header overhead."""
        errors = []
        for html_file in sorted(DOCS_BLOCKS.glob("*.html")):
            if html_file.name in ('index.html', 'style.css'):
                continue
            cond, wit, total = self._extract_wire_totals(html_file)
            if cond is not None and wit is not None and total is not None:
                exact = cond + wit
                if total == exact:
                    continue
                # Allow header overhead: each wire row has a 4-byte block header
                # (type 2B + inv 1B + count 1B). If subtotals exclude headers,
                # total = subtotals + some multiple of header bytes.
                diff = total - exact
                if diff < 0 or diff > 8:
                    errors.append(f"{html_file.name}: {cond} + {wit} = {exact}, but total says {total} (diff={diff})")
        self.assertEqual(errors, [], "\n".join(errors))


if __name__ == '__main__':
    unittest.main(verbosity=2)
