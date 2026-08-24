# Critical Analysis of AI-DFIR v1.1

## Executive assessment

v1.1 materially improved the platform by moving beyond model forensics into
execution integrity. Its strongest ideas are:

- evidence quality rather than presence alone,
- source-to-sink taint,
- harness forensics,
- effective tool identity,
- browser/computer-use evidence,
- MCP/A2A/cache/router analysis,
- containment-aware outstanding work,
- streamed evidence storage.

The critical review for v1.2 found that the remaining highest-risk gap was
**representation integrity**: the platform could preserve raw text and rendered
HTML evidence but still assume that the characters an AI parser extracts mean
the same thing a human sees.

EvilFontTool demonstrates that this assumption is false.

---

## P0 — fixed in v1.2

### 1. Human-visible != machine-readable was not a first-class forensic proposition

v1.1 could find conventional hidden HTML and Unicode signals, but not prove that
a DOCX/PDF/HTML/font presents one semantic string to a human and another to an
AI/text-extraction pipeline.

Impact:

```text
human approves benign-looking content
AI consumes different machine representation
tool/action occurs
```

without the v1.1 evidence model explicitly identifying the representation split.

v1.2 fix:

- `evil_font_forensics.py`
- `representation_differential.py`
- `generic.evil_font_glyph_deception`
- `generic.hidden_document_representation`

### 2. Evidence authority could be self-asserted by an unsigned manifest

v1.1 allowed an acquisition entry with:

```json
{"authoritative": true}
```

to receive AUTHORITATIVE quality after file checks, even if the manifest itself
had not been cryptographically verified.

That is too weak for forensic custody.

v1.2 fix:

- `acquisition_manifest_v12.py`
- signed acquisition manifests
- `ACQUISITION_TRUST.json`
- AUTHORITATIVE/CORRELATED promotion requires valid signed acquisition trust.

### 3. Legacy Evidence Packs did not universally require acquisition hash binding

v1.1 made quality validation possible, but older packs could still validate a
non-empty/parseable mandatory artifact without an acquisition SHA-256 if the
pack did not explicitly request one.

v1.2 fix:

```text
mandatory artifact
  -> acquisition SHA-256 required by default
```

unless an Evidence Pack explicitly opts out.

This intentionally hardens the old evidence contract.

### 4. Basename fallback could bind evidence to the wrong acquisition record

Two separate artifacts named:

```text
events.json
```

could create ambiguous acquisition binding.

v1.2 fix:

- exact relative-path binding is preferred;
- basename fallback is accepted only when unique;
- ambiguous mapping is insufficient evidence.

---

## P1 — substantially improved in v1.2

### 5. Font/glyph remapping

Added generic glyph-outline analysis rather than relying solely on known
EvilFontTool names.

This matters because an attacker can fork or reimplement the technique.

Detection can now use:

```text
cmap
glyph outlines
blank glyph ratio
layout tables
font embedding
per-character font switching
machine-visible disagreement
```

### 6. Hidden source vs rendered source

v1.1 rendering coverage focused on active HTML.

v1.2 adds:

- HTML comments
- Markdown reference-only channels
- collapsed details
- hidden CSS
- alt/ARIA source channels
- Unicode tags / bidi / zero-width / variation selectors
- confusables
- terminal ANSI/OSC
- document two-layer representation.

### 7. Approval TOCTOU

A human may approve:

```text
/path/config.json
```

while the content or real path changes afterward.

v1.2 binds approval analysis to:

```text
approved SHA-256
approved realpath
current SHA-256
current realpath
```

### 8. Session-history tampering

Resumable agent history can itself become an authority/persistence mechanism.

v1.2 adds signed line-level session checkpoints and detects divergence,
including approval/authorization semantics appearing after divergence.

### 9. AI IDE auto-load surface

The old workspace analyzer was useful but broad.

v1.2 adds dedicated inventory/diff for:

- MCP configuration,
- LSP settings,
- tools/skills,
- hooks,
- prompt templates,
- IDE settings,
- automation,
- adversarial path names,
- workspace auto-approval.

### 10. DNS/rendering exfiltration channels

The platform can now flag:

- data-like DNS labels,
- high unique-subdomain fan-out,
- agent/renderer traffic to unapproved domains,
- explicit linkage between a sensitive-source hash and DNS activity.

### 11. Archive/package intake

AI IDE extensions, cloned workspaces and packaged tools may arrive as archives.

v1.2 statically identifies:

- path traversal,
- symlink entries,
- extreme compression ratios,
- nested archives,
- agent auto-load control files.

---

## P1 — still incomplete after v1.2

### A2A Agent Card JWS verification

v1.1/v1.2 preserve Agent Card hashes and signature-validation observations, but
the forensic tool does not yet implement full independent RFC 8785 JCS + JWS
verification against an investigator-controlled trust store.

Recommended next step:

```text
Agent Card
  -> RFC 8785 canonicalization
  -> detached JWS verification
  -> trusted JWKS / x509 / pinned key
  -> identity policy
```

Do not equate "signature cryptographically valid" with "agent trustworthy."

### Taint edge semantics

Current taint propagation deliberately uses explicit parent/cause edges, which
is safer than time-based correlation. However, not every parent edge means
content was copied.

Future event schemas should distinguish:

```text
caused_by
derived_from
contains_content_from
authorized_by
scheduled_by
correlated_with
```

### Prompt-replication scaling

`prompt_replication.py` is appropriate for case-scale analysis but performs
pairwise fuzzy comparisons.

Fleet-scale implementation should use:

- normalized fingerprints,
- shingled MinHash,
- LSH indexing,
- time/tenant partitions.

### Browser identity

Origin allowlists are useful but production analysis should add:

- redirect chains,
- DNS resolution history,
- SNI/certificate identity,
- IP ownership,
- iframe/subframe provenance,
- WebSocket handshake identity.

### Semantic prompt-intent analysis

Deterministic representation scanning can prove hiding/deception but cannot
always determine malicious semantic intent.

v1.2 therefore provides `semantic_verdict_ingest.py`, but intentionally does
not run an LLM inside the privileged analysis path.

A future deployment may run an isolated classifier in a separate trust domain
and return only a hash-bound verdict.

---

## P2 — enterprise production gaps

These remain outside the single-node reference implementation:

- HA transactional database
- immutable replicated/object-lock evidence storage
- KMS/HSM
- per-tenant KEK / per-object DEK
- automated key rotation
- enterprise IdP integration
- mTLS service identity
- real provider-native collectors
- storage lifecycle validation
- cross-region disaster recovery
- external timestamp authority / transparency service.

---

## World-class design principle introduced in v1.2

For AI evidence, preserve at least three representations whenever relevant:

```text
SOURCE BYTES
     |
     +--> MACHINE-READABLE REPRESENTATION
     |
     +--> HUMAN-VISIBLE REPRESENTATION
```

Then preserve:

```text
TRANSFORMATION / PARSER
VERSION
HASH
TIME
IDENTITY
```

for each path.

The forensic question is no longer only:

> What did the file contain?

It is:

> What did each participant in the decision actually perceive?
