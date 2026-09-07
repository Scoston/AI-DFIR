# Investigation provenance and recorded replay

This unreleased extension completes the reference-validation and recorded-replay
path described in `V1.7_ARCHITECTURE.md`. The published v1.7.0 assets are unchanged.

The forensic proposition is narrow: the preserved records, their evidence
references, and the signed investigation history are internally consistent.
Reconstruction displays those recorded observations and human decisions. It does
not establish that an upstream provider was truthful, that an analyst's identity
was independently authenticated, or that an undocumented causal link existed.

## Run the synthetic acceptance case

```bash
python v17_provenance_selftest.py
python -m pytest tests/test_v17_provenance_replay.py -q
```

The case preserves a synthetic raw provider export and normalized result, records
a model invocation, links a tool call and an analyst disposition, signs a ledger
checkpoint, exports the case, and verifies and reconstructs it offline. It also
rejects modified provenance. Keys and case bytes are created in a temporary
directory and removed after the check.

## Build the profile

`v17_provenance.new_provenance(case_id)` creates the default `references-only`
profile. Add `wrap_record(kind, typed_record, path=...)` entries to these arrays:

| Array | Record type | Reference semantics |
|---|---|---|
| `artifacts` | `EvidenceArtifact` | Unique artifact ID and package-relative path; SHA-256 must match exported bytes |
| `relationships` | `EvidenceRelationship` | Both endpoints must exist; self-links and directed cycles fail |
| `ai_records` | `AIProvenanceRecord` | Evidence and retrieval references point to artifacts; tool calls point to reciprocal tool records |
| `tool_records` | `ToolActivityRecord` | Links an AI invocation, tool name, actor, arguments digest, evidence and output references |
| `analyst_decisions` | `AnalystDecisionRecord` | Targets a preserved artifact, AI invocation, or tool activity; retains a separate human disposition |

Finding targets can be represented by preserved finding artifacts. This profile
does not silently resolve arbitrary external finding IDs.

Each row has a type-specific schema and RFC 8785/SHA-256 `record_hash`. The hash
covers the complete wrapper, including the artifact path and any recorded output
digest. It is domain-separated from other record types and from the legacy
`integrity_id` properties; the existing v1.7 hashes and signatures are unchanged.

For example, with an existing case, ledger, and authorized signing setup:

```python
from v17_integrity import EvidenceArtifact
from v17_provenance import new_provenance, wrap_record, bind_record

profile = new_provenance(ledger.case_id)
artifact = EvidenceArtifact.from_bytes(
    case_id=ledger.case_id,
    artifact_id="RAW-001",
    content=(case_root / "raw.json").read_bytes(),
    acquired_at="2026-09-06T00:00:00Z",
)
row = wrap_record("artifacts", artifact, path="raw.json")
profile["artifacts"].append(row)
bind_record(ledger, "artifacts", row,
            timestamp="2026-09-06T00:00:00Z", actor="collector:example")
# Bind the other records, then create/sign the completed ledger checkpoint.
# Pass provenance=profile to case_export_v17.export_case(...).
```

Bind each row exactly once with `bind_record` before checkpoint signing. Missing,
duplicate, altered, incorrectly typed, or cross-case commitments fail. Model,
tool, and analyst record timestamps must match their ledger events. UTC timestamps
are required; the validator does not infer a timezone. Actor bindings must match
where the record contains an actor or analyst ID.

The profile is stored at
`00_case/v17/investigation_provenance.json` in the signed export. The exporter
validates the staged copy and never writes provenance into the original case.
An existing profile at that path is automatically validated. Evidence omitted by
the export selection cannot satisfy a profile reference. Use `--include-evidence`
when an authorized export needs evidence from the otherwise omitted directories.

## Privacy and uncertainty

`references-only` permits evidence references and tool-argument digests, with no
inline structured model output or analyst rationale. An absent/empty structured
output has `output_sha256: null`; it is not treated as a preserved model response.

To include reviewed structured output or rationale, explicitly select
`content_policy: "reviewed-content"` and provide
`content_review: {"reviewer": "...", "reviewed_at": "...Z"}`. The reviewer marker
is a recorded claim, not authentication. Review the content before adding it.
Known prompt, credential, and private-reasoning field names are rejected in both
modes. This check cannot detect all secrets or personal data hidden in arbitrary
text or evidence bytes. Existing acquisition, access, redaction, and retention
procedures still govern those artifacts.

Tool status is one of `succeeded`, `failed`, or `unknown`; a recorded success is
not independent corroboration of the downstream effect. Analyst dispositions are
`confirmed`, `rejected`, `accepted_with_qualification`, `escalated`,
`containment_approved`, `containment_denied`, or `closed`. Recording a disposition
does not perform that action or satisfy other closure/approval gates.

## Verify and reconstruct

```bash
python verify_case_v17.py --zip case.zip --export-public-key export.pub.pem \
  --tenant TENANT-001 --case CASE-001 --require-provenance

python replay_case_v17.py --zip case.zip --export-public-key export.pub.pem \
  --tenant TENANT-001 --case CASE-001 --out reconstruction.json

python replay_case_v17.py --zip case.zip --export-public-key export.pub.pem \
  --replay-transforms --out replay.json
```

Obtain the export public key independently. Provenance is interpreted only after
the outer signature, exact file inventory, evidence bytes, ledger, and signed
checkpoint pass. Reconstruction uses the same open archive and validated record
snapshot, never an unverified re-opened copy. No archive members are extracted.

Older v1.7 packages without provenance remain verifiable with
`provenance_integrity: "NOT_PRESENT"`. `--require-provenance` and reconstruction
fail if it is missing. A ledger with provenance commitments always requires the
profile, so removal cannot silently downgrade it to legacy verification.

The timeline follows ledger sequence. Other historical ledger events remain
visible with `record_id: null`, and `unbound_event_count` reports how many lack a
typed provenance record. No ordering or causality is invented from timestamps.

## Deterministic replay and comparison

The fixed local transform registry supports:

| Transformation | Version | Required preserved input | Comparison |
|---|---|---|---|
| `RFC8785` | `1` | Strict JSON | Exact canonical output bytes |
| `provider_normalizer.normalize` | `1.4` | JSON array of provider-event objects; relationship metadata `{"provider":"openai"}` or another supported adapter | Canonical JSON output with content inclusion disabled |
| `evidence_quality.evaluate_gates` | `1.7` | Retained pack/quality snapshot and original assessment; metadata `{"pack_sha256":"<canonical retained pack digest>"}` | Canonical gate summary using recorded quality states |
| `v17_cloudtrail.normalize` | `1.7` | Native CloudTrail export and recorded projection; metadata `{"input_format":"records"}` or `{"input_format":"lookup-events"}` | Canonical projection including exact raw input digest |

The profile is limited to 10,000 total records and 16 MiB of metadata. Each
deterministic replay input/output is limited to 16 MiB. Duplicate JSON keys,
non-finite numbers, invalid structures, and exceeded limits fail. Unknown
transform names or versions are `UNSUPPORTED`; evidence can never select an
arbitrary Python import, shell command, model invocation, or external tool.
The [Evidence Pack gate adapter](EVIDENCE_PACK_REPLAY_V1.7.md) additionally limits
its input snapshot to 2 MiB, requires complete unique artifact identities, and
distinguishes reproduced calculations from underlying evidence sufficiency.
The [native CloudTrail adapter](CLOUDTRAIL_REPLAY_V1.7.md) limits input/output to
8 MiB and at most 2,000 events, checks wrapper consistency, and preserves recorded
order and identity distinctions. Other parsers and raw-evidence reassessment
adapters remain future work.

Integrity verification and reproduction of a transformation are separate
results. A correctly preserved but incorrect normalization can have integrity
`PASS` and deterministic replay `FAIL`. Requested replay with any unsupported
transform returns `INCOMPLETE`. Both conditions produce CLI exit code `1`.
Other exits follow the verifier contract: `0` success, `1` verification failure,
`2` malformed/unsupported package, `3` runtime/configuration failure.

To compare a separately recorded execution, preserve it as another AI record and
add `{"original":"AI-001","comparison":"AI-002"}` to `comparisons`. Both
invocations must be present and committed; a comparison cannot predate its
original. Results compare model/configuration identifiers, the digests of
referenced input evidence, and retained structured output when available.
Unknown output equality is `null`. Matching outputs never establish deterministic
reproduction of a stochastic model. This workflow does not make a new live call.

## Acceptance and remaining boundaries

The quick release gate runs the synthetic self-test. The full gate additionally
runs the provenance/replay regression suite alongside the original 56 v1.7 tests,
111 Evidence Packs, 19 synthetic detector domains, and historical compatibility
suites. Packaging requires these files and acceptance results in the extracted
package. Historical published v1.7.0 release verification remains supported.

[Checkpoint key policy](CHECKPOINT_KEY_POLICY_V1.7.md),
[authenticated policy updates](CHECKPOINT_POLICY_UPDATES_V1.7.md), and
[external checkpoint timestamps](CHECKPOINT_TIMESTAMPS_V1.7.md) are separate,
implemented development profiles that also gate reconstruction. Live comparison
orchestration, more replay adapters, and deployment certification remain future
work. This profile provides no new model detector coverage and makes no
claim of legal admissibility, hardware-backed keys, or production certification.
