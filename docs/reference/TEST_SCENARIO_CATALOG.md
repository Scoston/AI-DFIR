# Test Scenario Catalog — AI-DFIR v1.6

AI-DFIR ships two complementary synthetic validation layers:

1. **Evidence Pack matrix fixtures** — one hash-bound synthetic case per Evidence Pack, validating artifact discovery, evidence-quality rules, mandatory gates, and pack completeness.
2. **High-fidelity detector scenarios** — fabricated but structurally realistic logs/documents that exercise detector logic rather than only filename/schema matching.

## Rebuild all test logs

```bash
python tests/generate_test_corpus.py
```

Generated content is written under `tests/fixtures/` and contains no production credentials or customer data.

## Validate every Evidence Pack

```bash
python tests/test_evidence_pack_matrix.py
```

Expected release result: **111/111 PASS**. Each fixture includes an acquisition manifest with the exact SHA-256 of generated artifacts, so the test exercises v1.6 evidence-quality hash binding.

## Run high-fidelity scenarios

```bash
python tests/run_synthetic_scenarios.py
```

Expected release result: **19/19 detector domains PASS**.

## High-fidelity domains

- EvilFont-style DOCX glyph deception
- Unicode tag/bidi/zero-width representation smuggling
- Terminal ANSI/OSC deception
- Hidden markup/source channels
- Browser/WebSocket computer-use control
- DNS/rendered-output exfiltration signals
- AI cache poisoning
- Model router/provider drift
- Workload identity
- Credential lineage
- Temporal authority
- Signed/versioned memory integrity
- Agent skill supply-chain drift
- MCP 2026-07-28 execution integrity
- OpenTelemetry GenAI normalization
- Typed causal graph
- A2A execution/delegation binding
- Provider export normalization
- Collector health/evidence gaps

## Evidence Pack fixtures

The generated matrix currently covers **111 Evidence Packs**. The authoritative generated inventory is `tests/fixtures/EVIDENCE_PACK_FIXTURE_MANIFEST.json`; the result is `tests/fixtures/EVIDENCE_PACK_MATRIX_RESULT.json`.

For an individual pack:

```bash
# regenerate all deterministic fixtures first
python tests/generate_test_corpus.py

# inspect a pack fixture
find tests/fixtures/evidence_packs/<pack-id> -maxdepth 2 -type f -print

# then run the complete quality/gate matrix
python tests/test_evidence_pack_matrix.py
```

## What these fixtures prove

- Artifact patterns can be satisfied by deterministic, hash-bound evidence.
- Mandatory Evidence Pack gates evaluate correctly.
- Evidence quality uses acquisition hashes rather than file presence alone.
- High-fidelity scenarios trigger the expected detector families.
- Generated cases can be used for analyst training and Workbench walkthroughs.

## What they do **not** prove

- A provider API has been configured correctly in your organization.
- Production retention/logging is complete.
- An alert proves malicious intent.
- A synthetic causal chain is equivalent to real-world attribution.
- Production scale/HA/KMS/Object Lock/IdP controls are working.

Use `production_readiness_v16.py`, provider collection-health evidence, DR restore validation, and organization-specific integration tests before production release.
