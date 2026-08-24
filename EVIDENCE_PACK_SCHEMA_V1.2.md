# AI-DFIR Evidence Pack Schema v1.2

v1.2 retains the v1.1 evidence-quality ladder and strengthens the acquisition
trust boundary.

## Default mandatory-artifact rule

A mandatory artifact requires a hash-bound acquisition record by default.

```text
artifact present
   +
parse/semantic validation
   +
acquisition SHA-256 match
   =
VALIDATED
```

An Evidence Pack may explicitly set:

```json
{"validation":{"allow_unhashed":true}}
```

only for evidence classes where acquisition hashing cannot reasonably apply.

## Signed acquisition trust

An acquisition record may claim:

```json
{
  "authoritative": true,
  "corroborated": true
}
```

but those claims do not raise evidence quality unless:

```text
ACQUISITION_TRUST.json
manifest_signature_verified = true
valid = true
```

This prevents an unsigned metadata file from self-declaring evidence authority.

## Quality states

```text
MISSING
PRESENT_UNVALIDATED
VALIDATED
CORRELATED
AUTHORITATIVE

CONFLICTING
STALE
INCOMPLETE
```

## Representation evidence

v1.2 packs may separately require:

```text
source bytes
machine-readable text
human-visible text
representation differential
font/document structural analysis
AI ingestion trace
```

This avoids treating a parser output as a faithful representation of what a
human saw.

## Conclusion gate

Example:

```json
{
  "id": "font_deception_present",
  "title": "Font/glyph deception is established",
  "logic": "all",
  "min_quality": "VALIDATED",
  "requires": [
    "original_document",
    "font_analysis",
    "representation_diff",
    "independent_visible"
  ]
}
```
