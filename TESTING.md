# Testing AI-DFIR

AI-DFIR ships complementary validation layers. All bundled fixtures are synthetic and must not contain production credentials or customer evidence.

## 1. Current acceptance suite

```bash
python v16_selftest.py --out /tmp/aidfir-v16
```

Historical suites are retained for compatibility regression.

## 2. Evidence Pack fixture matrix

Generate deterministic synthetic case files and acquisition hashes for **every current Evidence Pack**:

```bash
python tests/generate_test_corpus.py
python tests/test_evidence_pack_matrix.py
```

Expected v1.6.0 release result:

```text
111 / 111 PASS
```

The matrix validates evidence discovery, acquisition-hash binding, minimum evidence quality, and mandatory conclusion gates. Generic fixtures do not claim that placeholder content represents a real attack.

## 3. High-fidelity synthetic scenarios

```bash
python tests/run_synthetic_scenarios.py
```

Expected v1.6.0 release result:

```text
19 / 19 detector domains PASS
```

These fabricated scenarios exercise representative detector logic including EvilFont-style representation attacks, Unicode/markup/terminal channels, browser control, DNS exfiltration, cache/router drift, workload identity, credentials, temporal authority, memory, skills, MCP, OpenTelemetry GenAI, typed causality, A2A binding, provider normalization, and collection health.

## 4. GitHub/repository checks

```bash
python scripts/github_repo_check_v16.py
```

This validates the expected GitHub/community surface and detects stale release documentation or unsafe unresolved repository placeholders.

## 5. Release gates

```bash
python scripts/release_check.py --quick
python scripts/release_check.py --full
```

`--full` includes major historical compatibility suites and is the gate used for release packaging.

## 6. Production deployment validation

Software tests do not prove an enterprise deployment is production-ready. After deployment, collect the required HA, identity, WORM, KMS, provider-certification, DR, chaos/failover, SLO, independent-assessment, and upgrade/rollback artifacts and run:

```bash
python production_readiness_v16.py \
  --config config/production_readiness_v16.example.json \
  --out production_readiness_v16.json
```

See `PRODUCTION_READINESS_V1.6.md`.

## 7. Demo and analyst training

See `docs/demo/README.md` and `docs/reference/TEST_SCENARIO_CATALOG.md` for a reproducible synthetic walkthrough.


## 8. v1.7 offline verification assurance

The v1.7 line includes a separate assurance layer for third-party verification of signed case exports. Run:

```bash
python -m pytest tests/test_v17_verification_assurance.py -q
python v17_verification_assurance_selftest.py
```

The assurance self-test invokes `verify_case_v17.py` from a detached working directory with a network guard, validates both text and JSON reports, and checks the verifier exit-code contract: `0` verified, `1` verification failure, `2` malformed/unsupported package, and `3` runtime/configuration error.

See `docs/reference/OFFLINE_VERIFICATION_V1.7.md`.

## 9. v1.7 release-candidate hardening

The release-candidate layer adds version-aware packaging, committed-HEAD-only staging, source-commit binding, packaged-artifact verification, and a deterministic known-answer test:

```bash
python -m pytest tests/test_v17_release_candidate.py -q
python v17_release_candidate_selftest.py
```

The published v1.7 integrity/release baseline contains **56 tests**. To exercise
packaging of committed development changes under a local candidate version:

```bash
AI_DFIR_RELEASE_TAG=v1.7.1-rc1 python scripts/package_release.py \
  --out-dir /tmp/AI-DFIR-v1.7.1-rc1-release
python scripts/verify_release_candidate_v17.py \
  --release-dir /tmp/AI-DFIR-v1.7.1-rc1-release \
  --version 1.7.1-rc1
```

The packaged ZIP is extracted and subjected to the full release gate. The v1.7 release verifier independently validates `SHA256SUMS`, the package manifest, source-commit binding, SBOM application version, release-validation metadata, and release-candidate assurance metadata.

See `docs/reference/RELEASE_ASSURANCE_V1.7.md`.

### Published GitHub release surface

The packager-generated `SHA256SUMS` covers the packager-owned release assets. GitHub's SLSA provenance job subsequently adds `multiple.intoto.jsonl`, so published-release verification treats that exact filename as a separately scoped external provenance sidecar.

The verifier still rejects arbitrary unlisted files, malformed provenance JSONL, missing checksum entries, and modified checksummed assets. The release workflow re-downloads the complete published v1.7 release and verifies that final surface after asset publication.

## 10. Unreleased investigation provenance and replay

```bash
python v17_provenance_selftest.py
python -m pytest tests/test_v17_provenance_replay.py -q
```

The quick gate includes the self-test. The full gate additionally requires all
30 provenance/replay regressions (86 integrity/provenance tests). Cases cover broken
references, record modification, cross-case substitution, missing ledger
commitments, cyclic lineage, UTC timestamps, sensitive-context controls,
duplicate JSON keys, omitted profiles, offline reconstruction, recorded comparison,
and failed/unsupported deterministic replay. The extracted-package gate requires
the same acceptance results. See
[Investigation replay](docs/reference/INVESTIGATION_REPLAY_V1.7.md).

## 11. Unreleased checkpoint key lifecycle policy

```bash
python v17_key_policy_selftest.py
python -m pytest tests/test_v17_key_policy.py -q
```

The quick gate includes the offline acceptance self-test. The full gate adds 57
focused key-policy tests, bringing the pre-timestamp v1.7 total to 143. They cover active/retired/
revoked keys, rotation overlap, exact validity boundaries, inconsistent signing
time claims, current clock evaluation, tenant/case scope, pinned-policy rollback
attempts, embedded-policy rejection, missing required policy, bounded strict
parsing, export refusal, and enforcement across all verification CLIs.

Negative cases require valid signatures to remain distinguishable from denied
key trust, require reconstruction to stop on policy failure, and verify that a
passing policy cannot override invalid evidence or manifest signer trust.
New extracted release packages must carry the same test and self-test results.
See [Checkpoint key policy](docs/reference/CHECKPOINT_KEY_POLICY_V1.7.md).

## 12. Unreleased external checkpoint timestamps

Install the default Python requirements and a maintained OpenSSL 3 executable.
The timestamp profile adds `asn1crypto` for ASN.1 parsing. Existing verification
with no timestamp options does not invoke OpenSSL.

```bash
python v17_timestamp_selftest.py
python -m pytest tests/test_v17_timestamps.py -q
```

The quick gate generates ephemeral CA/TSA keys and issues a real RFC 3161
response using OpenSSL in temporary storage. No live authority is contacted.
The timestamp milestone adds 68 tests, for a pre-policy-update total of 211: 56 integrity, 30
provenance/replay, 57 key-policy, and 68 timestamps. Tests include correctly
signed hostile cases, wrong imprints/nonces/pins, unavailable crypto tooling,
exclusive timestamp certificate purpose, expiry and future times, incorrect
CA roots, input bounds, and external trust enforcement across every CLI.
Positive controls verify that the modified synthetic certificates/tokens are
cryptographically valid before testing rejected purposes and time windows.

Case tests require timestamp failure to block reconstruction and export, while
preserving existing destinations and separate signature/key-policy results.
Published older package contracts remain supported; new extracted releases
must include the timestamp files and their acceptance results. See
[Checkpoint timestamps](docs/reference/CHECKPOINT_TIMESTAMPS_V1.7.md).

## 13. Unreleased authenticated checkpoint policy updates

```bash
python v17_policy_distribution_selftest.py
python -m pytest tests/test_v17_policy_distribution.py -q
python scripts/release_check.py --full
```

The self-test is part of the quick and full gates. That milestone adds 66 tests,
bringing the pre-quorum v1.7 total to 277. Coverage includes issuer authority and rotation,
key separation, signature/scope tampering, current-clock expiry, persisted
rollback rejection, equal-revision conflicts, concurrent updates, failed
transactions, malformed or missing stores, and all affected CLIs. A backup
recovery test demonstrates that replacing the entire store with an older valid
copy requires an independently retained minimum revision to detect the rollback.

Case tests keep authentication separate from evidence integrity and checkpoint
signature validity, block reconstruction after revocation, preserve export
destinations on failure, and compose with timestamp requirements. The tests use
ephemeral keys and local files; they deploy no authority or update service.
Packaging requires all profile files and repeats the full gate on extracted
committed source. See [Authenticated policy updates](docs/reference/CHECKPOINT_POLICY_UPDATES_V1.7.md).

## 14. Unreleased checkpoint policy issuer quorum

```bash
python v17_policy_quorum_selftest.py
python -m pytest tests/test_v17_policy_quorum.py -q
python scripts/release_check.py --full
```

The quick gate runs a synthetic two-of-three approval and revocation case. The
quorum milestone adds 67 tests, for a pre-governance total of 344. Tests reject partial quorum,
duplicate votes, mixed revisions, altered governance configurations, untrusted
or invalid extra signatures, and fallback to single-issuer approval. They also
cover the maximum issuer set, strict input bounds, current-clock validity,
rotation/migration with the existing revision floor, concurrent updates,
stored-signature reauthentication, all affected CLIs, destination preservation,
and composition with timestamp and evidence-integrity checks.

Tests use ephemeral synthetic keys and make no live authority requests. They
establish distinct-key approval, not independent human or organizational custody.
Packaging requires the new module, self-test, regression suite, reference, and
their passing extracted-source assurance. See
[Policy issuer quorum](docs/reference/CHECKPOINT_POLICY_QUORUM_V1.7.md).

## 15. Unreleased signed issuer-root governance

```bash
python v17_policy_governance_selftest.py
python -m pytest tests/test_v17_policy_governance.py -q
python scripts/release_check.py --full
```

The quick gate runs a dual-quorum rotation and atomic activation self-test. The
full gate adds 87 tests, bringing the v1.7 total to 431. Tests verify the entire
retained chain from an independent anchor; reject partial, duplicate, altered,
wrong-role, skipped-version, and forked approvals; and exercise concurrent
rotations, failed writes, migration rollback, expired-root/policy recovery,
strict input bounds, whole-store rollback with independent floors, and all
affected CLIs. Case tests preserve destinations and require evidence integrity,
current key policy, and configured timestamps in addition to valid governance.

All fixtures are synthetic and temporary. No live authority is contacted.
Packaging repeats the full gate on extracted committed source and requires the
new profile's files and assurance results. See
[Signed issuer governance](docs/reference/CHECKPOINT_POLICY_GOVERNANCE_V1.7.md).
