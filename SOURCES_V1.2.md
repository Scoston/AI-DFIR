# AI-DFIR v1.2 Research Sources

Verified 2026-08-24.

## EvilFontTool
https://github.com/DoctorEww/EvilFontTool

Used to understand the defensive artifacts of remapped-glyph deception across
HTML, DOCX and PDF.

## PhantomLint
https://github.com/tobycmurray/phantom-lint

Used for the method-agnostic concept of comparing machine-extracted text with an
independent rendered/OCR representation.

## Hidden Text Detector
https://github.com/wppoland/hidden-text-detector

Used for structural hidden-text and Unicode coverage. Its documented remapped-
glyph limitation helped identify the v1.1 font-forensics gap.

## GlyphGuard
https://github.com/Ayubjon/glyphguard

Used as a reference for Unicode representation-smuggling categories.

## Invisible Prompt Injection
https://github.com/bountyyfi/invisible-prompt-injection

Used for raw-Markdown vs rendered-Markdown representation analysis.

## Mindgard AI IDE Vulnerability Patterns
https://github.com/Mindgard/ai-ide-vuln-patterns

Used to survey attack surfaces around:

- LSP/config auto-load,
- tools/skills/hooks,
- terminal control sequences,
- DNS/rendering exfiltration,
- TOCTOU,
- session-history state,
- archive extraction,
- agent protocol/local-service boundaries.

## A2A v1.0
https://github.com/a2aproject/A2A

Used for the review of signed Agent Cards, JWS and JSON canonicalization.

v1.2 documents full independent Agent Card signature verification as a remaining
standards-integration gap rather than implementing an approximate verifier.
