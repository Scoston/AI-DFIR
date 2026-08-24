# GitHub Research Incorporated into AI-DFIR v1.2

Research verified 2026-08-24.

The purpose of this review was not to copy offensive tooling. It was to identify
forensic surfaces and defensive detection concepts missing from AI-DFIR.

## DoctorEww/EvilFontTool

Repository:
https://github.com/DoctorEww/EvilFontTool

Defensive lesson:

```text
character code != glyph appearance
machine-readable text != human-visible text
```

Incorporated:

- glyph-outline collapse analysis,
- blank-glyph analysis,
- DOCX embedded-font inspection,
- per-character font-switch detection,
- EvilFont-style family-name indicators,
- PDF invisible-text/two-layer signals,
- HTML custom-font analysis,
- human-vs-machine representation differential,
- dedicated Evidence Pack.

## tobycmurray/phantom-lint

Repository:
https://github.com/tobycmurray/phantom-lint

Defensive lesson:

Heuristic hidden-text detection is not enough. Compare independently rendered
visible content with extracted machine-readable content.

Incorporated:

- method-agnostic representation differential,
- separate human-visible vs machine-readable evidence requirements.

AI-DFIR does not bundle an OCR engine; investigators can supply independently
derived visible text/vision evidence.

## wppoland/hidden-text-detector

Repository:
https://github.com/wppoland/hidden-text-detector

Defensive lesson:

Useful fast structural indicators include:

- PDF invisible render mode,
- opacity/contrast,
- off-page text,
- DOCX hidden runs/tiny fonts,
- Unicode tag/variation/bidi/invisible codepoints.

Important research gap:

The project explicitly notes that **remapped glyphs are not detected**.

AI-DFIR v1.2 specifically adds remapped-glyph geometry analysis.

## Ayubjon/glyphguard

Repository:
https://github.com/Ayubjon/glyphguard

Defensive lesson:

Invisible/dangerous Unicode deserves a dedicated representation layer rather
than ordinary text scanning.

Incorporated:

- Unicode tag blocks,
- tag payload decoding,
- bidi controls,
- zero-width/invisible characters,
- variation selectors,
- private-use characters,
- basic homoglyph/confusable indicators,
- NFKC comparison.

## bountyyfi/invisible-prompt-injection

Repository:
https://github.com/bountyyfi/invisible-prompt-injection

Defensive lesson:

Markdown has separate raw-source and human-rendered representations.

Incorporated:

- HTML comments,
- Markdown reference definitions,
- collapsed `<details>`,
- hidden CSS,
- alt/ARIA source channels,
- representation-parity evidence.

The project calls this a preprocessing failure rather than necessarily a model
alignment failure; AI-DFIR models it as a representation/evidence problem.

## Mindgard/ai-ide-vuln-patterns

Repository:
https://github.com/Mindgard/ai-ide-vuln-patterns

Defensive lesson:

AI coding agents inherit a very broad execution surface outside the model.

Incorporated or expanded in v1.2:

- LSP configuration inventory,
- MCP/tool/skill/hook auto-load inventory,
- IDE workspace configuration,
- adversarial path names,
- approval/trust TOCTOU,
- session-history tampering,
- DNS exfiltration,
- ANSI/OSC terminal deception,
- renderer external-resource channels,
- archive path traversal/symlink detection,
- packaged agent auto-load control files.

Already covered in earlier versions:

- MCP poisoning,
- tool shadowing,
- confused deputy,
- browser/WebSocket paths,
- model provider routing,
- symlink/root escape,
- cross-agent authority,
- memory persistence.

## prompt-injection-screen

Defensive lesson from public two-stage intake designs:

Separate deterministic representation screening from optional semantic
classification.

AI-DFIR v1.2 does not allow an untrusted document to be sent automatically to a
privileged classifier.

Instead:

```text
deterministic content intake
       |
       +--> PASS / REVIEW / QUARANTINE
       |
       +--> optional isolated classifier
               |
               +--> hash-bound verdict only
```

`semantic_verdict_ingest.py` accepts only bounded verdict metadata.

## A2A v1.0

A2A v1.0 adds signed Agent Cards using JWS with JSON canonicalization.

Current AI-DFIR gap:

v1.1/v1.2 record signature-validation results, but do not yet independently
implement the complete JCS/JWS trust-store verification stack.

Recommended next addition:

```text
trusted JWKS / X.509
       |
       v
RFC 8785 canonicalization
       |
       v
JWS verification
       |
       v
Agent Card identity policy
```

This should be implemented with a standards-conformant canonicalization library,
not an approximate JSON serializer.

---

# Features deliberately not copied

AI-DFIR does not include:

- malicious-font generation,
- prompt-injection payload generation,
- command-filter bypass generation,
- DNS exfiltration tooling,
- archive traversal generation,
- session-history forgery,
- exploit automation.

The project uses those public techniques only to define defensive evidence,
detections and reconstruction paths.
