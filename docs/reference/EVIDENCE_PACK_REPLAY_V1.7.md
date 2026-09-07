# Recorded Evidence Pack conclusion-gate replay

This unreleased development profile adds a third fixed adapter to
[investigation replay](INVESTIGATION_REPLAY_V1.7.md). Published v1.7.0 assets are
unchanged. It answers one question: do the exact retained Evidence Pack rules and
recorded artifact-quality ratings reproduce the preserved conclusion-gate summary?

The adapter shares the pure `evidence_quality.evaluate_gates()` calculation with
the existing assessment engine. It does not rescan files, parse source telemetry,
authenticate acquisition claims, consult the latest catalog, or execute a pack's
collection guidance. No model, external tool, or network service is invoked.

## Separate the claims

| Result | What it establishes |
| --- | --- |
| Case integrity `PASS` | Existing signature, inventory, ledger, checkpoint, and configured trust gates passed |
| Gate replay `PASS` | The retained rules and ratings reproduce the recorded summary |
| A reproduced gate is `supported` | Those recorded ratings satisfy that retained rule |
| Actual evidence sufficiency or incident conclusion | Requires separate validation, corroboration, and analyst judgment |

A replay can pass while reproducing a `not_supported` gate. An intact signed case
can also contain an incorrectly calculated assessment: integrity can pass while
replay fails. A recorded `AUTHORITATIVE` rating is still an input claim here. A
successful comparison does not authenticate that rating, prove source truth,
establish who ran the original assessment, or authorize closure/containment.

## Preserve the original assessment and rules

Retain the exact Evidence Pack JSON used for the assessment and its original
assessment JSON. Supported assessment schemas are
`ai-dfir/evidence-assessment/v1.1` and
`ai-dfir/evidence-quality-assessment/v1.2`. The pack ID/title and each artifact's
ID/priority must agree with the retained pack. Every pack artifact must have one
explicit quality state, including `MISSING`; missing rows are not inferred.

Prepare a new input snapshot without changing the assessment:

```bash
python pack_replay_v17.py prepare \
  --pack retained-pack.json --assessment retained-assessment.json \
  --case CASE-001 --out pack-replay-input.json
```

`PREPARED` means the inputs were captured. It does not mean the recorded gate
result is correct. The command preserves existing output files and never repairs
an incorrect assessment. It reports the canonical input and pack digests; retain
the approved pack digest with the investigation records.

The snapshot has exactly these fields:

| Field | Meaning |
| --- | --- |
| `schema` | `ai-dfir/evidence-pack-replay-input/v1.7` |
| `case_id` | Explicit case identity, checked against the signed ledger during reconstruction |
| `pack` | Exact retained pack definition as JSON data |
| `pack_sha256` | RFC 8785/SHA-256 identity of that complete pack definition |
| `quality_states` | Complete list of `{id, quality}` records, normalized into pack artifact order |

The Python `prepare_replay_input()` helper also accepts a pack returned by
`load_packs()`, removing only that loader's `_path` discovery field before hashing.
A retained snapshot containing `_path` is rejected. Pack formatting and object-key
order do not affect the canonical identity; rule order and content do.

Run an explicit comparison with the retained pack digest:

```bash
python pack_replay_v17.py verify \
  --input pack-replay-input.json --assessment retained-assessment.json \
  --case CASE-001 --expected-pack-sha256 <retained-canonical-pack-digest>
```

The digest is required and is not automatically adopted from the snapshot.
Matching a digest establishes content identity, not organizational pack approval.
Standalone comparison does not verify case signatures or independently establish
that an assessment belongs to a case; use signed-case reconstruction for those
existing evidence/lineage bindings.

## Bind the inputs into signed case reconstruction

Preserve the replay snapshot as the parent artifact and the original assessment
as the child artifact. Bind both artifact records and their relationship to the
investigation ledger before creating the signed checkpoint. With an existing
case, ledger, authorized export setup, and validated `snapshot`:

```python
from v17_integrity import EvidenceArtifact, EvidenceRelationship
from v17_provenance import bind_record, wrap_record

for artifact_id, filename in (
    ("PACK-INPUT", "pack-replay-input.json"),
    ("PACK-ASSESSMENT", "retained-assessment.json"),
):
    artifact = EvidenceArtifact.from_bytes(
        case_id=ledger.case_id, artifact_id=artifact_id,
        content=(case_root / filename).read_bytes(),
        acquired_at=recorded_at, media_type="application/json",
    )
    row = wrap_record("artifacts", artifact, path=filename)
    profile["artifacts"].append(row)
    bind_record(ledger, "artifacts", row, timestamp=recorded_at, actor=analyst_id)

relationship = EvidenceRelationship(
    case_id=ledger.case_id, parent_artifact_id="PACK-INPUT",
    child_artifact_id="PACK-ASSESSMENT", relationship_type="derived-from",
    transformation="evidence_quality.evaluate_gates", transformation_version="1.7",
    created_at=recorded_at, metadata={"pack_sha256": snapshot["pack_sha256"]},
)
row = wrap_record("relationships", relationship)
profile["relationships"].append(row)
bind_record(ledger, "relationships", row, timestamp=recorded_at, actor=analyst_id)
# Sign the completed ledger checkpoint and export with provenance=profile.
```

Then use the existing explicit replay command:

```bash
python replay_case_v17.py --zip case.zip --export-public-key export.pub.pem \
  --tenant TENANT-001 --case CASE-001 --replay-transforms
```

The verifier uses the same open, authenticated archive and rechecks artifact
digests. It does not extract members or accept a pack-selected Python import.
Relationship metadata must contain only `pack_sha256`; unknown transform versions
remain `UNSUPPORTED`. Existing key-policy, timestamp, history, and case-integrity
requirements still gate the returned reconstruction.

## Exact comparison and limits

The replay compares the RFC 8785 digest of these six fields against a fresh pure
gate calculation: `mandatory_min_quality`, `mandatory_qualified`,
`mandatory_total`, `mandatory_percent`, `conclusion_gates`, and `quality_scale`.
The complete gate rules, order, status, missing requirements, and insufficient
quality details are included. Recorded quality states must match the input
snapshot before comparison; they cannot be replaced with newly inferred ratings.

Absolute assessment paths, match-level parser findings, collection receipts,
rendered prose, and other full-assessment details are outside this calculation.
Their bytes remain covered by the case inventory when included in the signed
case. Artifact-state order may differ, but the complete unique ID set and ratings
must agree. Gate array order is preserved and compared.

The bounded profile accepts current catalog schemas v0.8, v0.9, and v1.1–v1.6.
Pack/input snapshots are limited to 2 MiB; assessments to 16 MiB. A pack must have
1–256 uniquely identified artifacts and 1–128 uniquely identified nonempty gates.
Each requirement/alias list has at most 256 unique IDs, and total gate references
are capped at 4096. IDs are 1–128 ASCII letters/digits/`.`/`_`/`-`, beginning with
a letter or digit. Unknown structural fields, duplicate JSON keys, non-finite
numbers, malformed inputs, and ambiguous identities fail.

Supported logic is `all` or `any`. Optional aliases and per-requirement minimums
retain existing engine behavior. Undeclared references remain missing unless an
explicit retained alias satisfies them. Aliases do not fill missing mandatory
inventory rows. `CONFLICTING`, `STALE`, and `INCOMPLETE` never satisfy a gate.
Allowed minimums range from `PRESENT_UNVALIDATED` through `AUTHORITATIVE`; replay
preserves even a weak retained threshold without endorsing its sufficiency.

## Reports, compatibility, and acceptance

`ai-dfir/evidence-pack-gate-replay/v1.7` reports separate recorded/replayed summary
digests, case and pack identity, the quality-state digest, and reproduced gate
results. It explicitly reports `recorded_quality_only: true`,
`raw_evidence_revalidated: false`, `pack_approval_verified: false`, and
`closure_authorized: false`. Errors do not echo raw inputs or backend exceptions.

The standalone CLI exits 0 for `PREPARED`/matching `PASS`, 1 for invalid inputs,
conflicting output destinations, or mismatched results, and 2 for argparse usage
errors. Existing case replay exits nonzero for `FAIL` or `INCOMPLETE`, even if
case integrity itself passes. Plain case verification never requests this
calculation implicitly.

All 111 current catalog packs fit this profile. The Kubernetes exposure pack
previously had two `network` artifact IDs. Its conditional entry is now
`network_context`; the mandatory `network` entry and external-access gate retain
their binding. Updated synthetic fixtures reflect that distinct identity.
Historical snapshots with duplicate IDs are rejected. Do not rewrite a signed
historical assessment to make it fit this profile; retain any corrected execution
as a separately identified record with its own exact rules and provenance.

The synthetic acceptance and 96 regressions cover intact versus incorrect
recorded summaries, all current packs, negative quality states, rule/identity
ambiguities, bounds, offline signed-case use, independent case gates, and CLI
preservation. Both source and extracted-package release gates require these
results. A separate [pinned raw-evidence adapter](RAW_EVIDENCE_REASSESSMENT_V1.7.md)
now recomputes bounded byte/parse/literal/field checks without changing the ratings
used by this gate profile. Deeper quality validation and live comparison
orchestration remain future work. See [Testing](../../TESTING.md).
