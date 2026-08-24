# Detecting EvilFontTool and Remapped-Glyph Document Attacks

## Threat model

EvilFontTool is a public red-team project that intentionally makes the
machine-readable characters in a document differ from the characters rendered
to a human.

Do not build detection around the repository name or a single filename.

Use four independent evidence layers.

---

# Layer 1 — representation anomaly

Preserve:

```text
original SHA-256
machine-extracted text
independently rendered/vision-derived visible text
parser/rendering software and version
```

Run:

```bash
python representation_differential.py \
  --machine machine_text.txt \
  --visible visible_text.txt \
  --machine-source "document parser" \
  --visible-source "independent page rendering / vision" \
  --out representation_differential.json
```

A significant difference establishes a **representation anomaly**.

It does not by itself identify the specific tool.

---

# Layer 2 — generic font geometry

Run:

```bash
python evil_font_forensics.py suspicious.docx \
  --out evil_font_analysis.json
```

or:

```bash
python evil_font_forensics.py suspicious.ttf \
  --out font_analysis.json
```

The generic detector examines printable-character mappings and glyph geometry.

High-value signals include:

```text
font_glyph_outline_collapse
font_mass_blank_glyph_mapping
remapped_font_with_layout_tables_removed
```

A normal font generally has many visually distinct printable glyphs.

A deception font may map many unrelated Unicode characters onto the same
outline.

This is deliberately tool-agnostic.

---

# Layer 3 — EvilFontTool-style structural indicators

These are supporting IOCs, not required proof.

## DOCX

Preserve the complete ZIP package before parsing.

Relevant OOXML artifacts:

```text
word/document.xml
word/fontTable.xml
word/_rels/fontTable.xml.rels
word/settings.xml
word/fonts/*.fntdata
```

Inspect:

- number of embedded font families;
- one-character Word runs;
- font changes on nearly every character;
- all run font slots (`ascii`, `hAnsi`, `eastAsia`, `cs`);
- embedded-font `fontKey`;
- deobfuscated embedded font SHA-256;
- TTF name table;
- cmap;
- glyph outlines;
- hmtx;
- GSUB/GPOS/GDEF/kern presence.

EvilFontTool-style family names may end in:

```text
<font prefix> <UTF-8 hex bytes>
```

and a suffix:

```text
<font prefix> 0
```

can indicate a stealth/blank representation.

v1.2 reports:

```text
per_character_font_switching
machine_visible_text_disagreement_via_font_mapping
stealth_font_machine_only_characters
evilfonttool_style_font_family_pattern
```

The naming signal is intentionally lower-confidence than glyph geometry.

## HTML

Preserve:

```text
raw HTML
linked local CSS
local WOFF/TTF files
network requests used to obtain fonts
```

Look for:

```text
many single-character spans
font-family changing per character
large number of local custom fonts
hex-suffixed family names
family suffix 0
```

v1.2 also analyzes referenced **local** font files without contacting remote
servers.

## PDF

Preserve both:

```text
PDF source structure
page-visible rendering
```

Potential indicators:

```text
PDF text render mode 3 (invisible)
image-dominant page plus substantial selectable/extracted text
embedded remapped fonts
visible/machine representation divergence
```

Do not assume all invisible PDF text is malicious: OCR text layers in scanned
documents are common.

The evidence becomes stronger when an otherwise normal document contains
isolated invisible text or the extracted text materially disagrees with the
visible page.

---

# Layer 4 — incident causation

After technical detection, determine whether the representation affected AI
behavior.

Collect:

```text
upload/request ID
document SHA-256
ingestion parser
machine text supplied to model
vision/OCR input if separately used
prompt assembly
model request ID
agent session
tool calls
approval decisions
downstream target audit
consequences
```

The strongest finding is not:

> EvilFontTool was found.

It is:

> The acquired document contains a verified human/machine representation
> divergence produced by remapped glyphs. The AI ingestion pipeline consumed the
> machine-readable representation, and the resulting decision is causally linked
> to the questioned downstream action.

---

# Confidence ladder

## Level 1 — Representation anomaly

Human-visible and machine-readable content materially disagree.

## Level 2 — Structural/font anomaly

The document contains abnormal per-character fonts, invisible text layers or
font geometry consistent with remapping.

## Level 3 — Mechanism attribution

Generic glyph analysis plus supporting tool-specific structural IOCs establish
an EvilFont-style mechanism.

## Level 4 — Incident attribution

Ingestion and downstream execution evidence link that mechanism to the incident.

---

# Analyst collection checklist

For every suspected EvilFont-style case collect:

```text
[ ] original file + SHA-256
[ ] email/upload/download source
[ ] filesystem/acquisition metadata
[ ] all embedded fonts
[ ] font hashes
[ ] OOXML/PDF structural inventory
[ ] machine-extracted text
[ ] independent human-visible representation
[ ] representation differential
[ ] application/model ingestion logs
[ ] agent/harness trace
[ ] tool calls/results
[ ] approval events
[ ] target-system audit
[ ] downstream consequences
```

Do not discard the original document after rendering or sanitization.
