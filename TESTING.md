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
full gate adds 87 tests, bringing the pre-delivery v1.7 total to 431. Tests verify the entire
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

## 16. Unreleased online policy and issuer-root delivery

```bash
python v17_policy_delivery_selftest.py
python -m pytest tests/test_v17_policy_delivery.py -q
python scripts/release_check.py --full
```

The quick gate uses a temporary loopback HTTPS server and ephemeral synthetic
CA/private keys to deliver a signed rotation and policy, reject a tampered
download, and then verify the case with network calls blocked. The full gate
adds 139 tests, for a pre-history total of 570 v1.7 regression tests alongside all 111 Evidence Packs,
19 synthetic domains, and historical compatibility checks.

Tests cover complete-chain catch-up, expired intermediate/local state recovery,
preserved prefixes and revision floors, rollback after both database writes,
competing online updates, local preflight and post-download state checks,
TLS trust/hostname/expiry failures, redirects, proxy environment isolation,
strict URL and HTTP framing, malformed or truncated JSON, slow headers/bodies,
CLI preparation/sync, output preservation, and offline verification afterward.

No public service or real authority is contacted. Local loopback sockets must
be available to the test process. Packaging requires every delivery file and
passing source/extracted regression and self-test assurance. Older published
releases keep their original verification contract. See
[Online policy delivery](docs/reference/CHECKPOINT_POLICY_DELIVERY_V1.7.md).

## 17. Unreleased timestamped historical key-trust records

```bash
python v17_key_trust_history_selftest.py
python -m pytest tests/test_v17_key_trust_history.py -q
python scripts/release_check.py --full
```

The synthetic offline acceptance case timestamps an authenticated policy/root
record, verifies it with independent trust, and then proves that a later current
revocation blocks reconstruction. The full gate adds 85 tests, bringing the
pre-mTLS v1.7 total to 655 alongside the 111 Evidence Packs and 19 synthetic detector domains.

Correctly signed adversarial TSA responses exercise policy/root/key validity
boundaries, subsecond accuracy, absent accuracy, interior decision changes, and
future capture claims. Other cases cover modified or validly reissued policies,
root quorum tampering, scope/checkpoint substitution, independent pins, nonce
mixing, ordinary-checkpoint timestamp separation, and expired historical authority.
Case/export/replay tests preserve current-policy, signer-trust, evidence-integrity,
and checkpoint-timestamp gates; rejected exports preserve existing destinations.
Strict bounded input parsing, partial configuration, empty explicit paths,
capture/prepare/verify commands, and exclusive output creation are also covered.

All authorities and signatures are synthetic; no external service is contacted.
Packaging repeats the full gate on extracted committed source and requires all
profile files and assurance fields, while keeping earlier published release
contracts intact. See
[Historical key-trust records](docs/reference/CHECKPOINT_KEY_TRUST_HISTORY_V1.7.md).

## 18. Unreleased policy delivery client certificate authentication

```bash
python v17_delivery_identity_selftest.py
python -m pytest tests/test_v17_delivery_identity.py -q
python scripts/release_check.py --full
```

The quick acceptance case runs a synthetic loopback endpoint that requires a
trusted client certificate, rejects an anonymous connection, and accepts an
encrypted PKCS8 client key. It then rejects a tampered signed policy and verifies
the case offline. No production PKI or public endpoint is contacted.

The full gate adds 80 focused tests, for 735 v1.7 regression tests alongside all
111 Evidence Packs, 19 synthetic detector domains, and compatibility checks.
Tests cover untrusted clients, server CA/hostname/expiry checks, no certificate
forwarding on redirect, independent policy authority/floors, bounded credential
files, malformed PEM rejected within a subprocess deadline, strict certificate purpose, key/password matching, private snapshot loading
and cleanup, redacted failures, no TLS secret logging, CLI partial inputs, and
unchanged store bytes on rejection. POSIX-specific permission/FIFO cases run on
the Linux release gate and are explicitly skipped on unsupported platforms.

The certificate and private keys exist only in temporary fixture storage.
Release packaging requires the module, acceptance case, tests, guide, and their
source/extracted results. Existing published release contracts remain intact.
See [Client certificate authentication](docs/reference/POLICY_DELIVERY_MTLS_V1.7.md).

## 19. Unreleased controlled policy synchronization scheduling

```bash
python v17_policy_sync_selftest.py
python -m pytest tests/test_v17_policy_sync.py -q
python scripts/release_check.py --full
```

The acceptance case runs an encrypted mTLS identity against a temporary loopback
publisher, checks configuration without network access, accepts an authenticated
update, rejects tampered policy through repeated retries, and recovers without
resetting the governed store. It then verifies the case offline.

The full gate adds 85 focused tests, bringing the v1.7 total to 820. Coverage
includes independent anchor pins and revision floors, strict bounded/owned
configuration, duplicate store aliases, monotonic completion deadlines, capped
backoff/jitter, per-job failure isolation, configuration snapshots, credential
revalidation, disabled jobs, restart behavior, nonoverlapping rounds, immediate
attempt output, interrupted waits, and CLI result/exit semantics. POSIX file-mode
and signal cases are explicitly skipped where those facilities are unsupported.

All authorities, client keys, and endpoints are synthetic and temporary. No
production schedule or external service is started. Release packaging requires
the scheduler, CLI, self-test, tests, guide, and matching source/extracted-package
assurance; earlier published package contracts remain valid. See
[Policy synchronization scheduling](docs/reference/POLICY_SYNC_SCHEDULING_V1.7.md).

## 20. Unreleased recorded Evidence Pack conclusion-gate replay

```bash
python v17_pack_replay_selftest.py
python -m pytest tests/test_v17_pack_replay.py -q
python scripts/release_check.py --full
```

The synthetic signed-case acceptance reproduces supported and unsupported gates
from retained rules/ratings, then detects an incorrectly recorded gate result
despite intact case integrity. No network, model, external tool, archive extraction,
or raw-evidence quality reassessment is performed during replay.

The 96 focused regressions bring the v1.7 total to 916. They cover all 111 current
catalog packs, aliases and per-requirement thresholds, negative quality states,
complete unique artifact bindings, case/pack pins, bounded input/reference counts,
strict JSON, CLI preservation and error codes, signed archive tampering, and
independent case gates. The Kubernetes exposure pack's conditional network entry
now has a distinct ID; its mandatory external-access gate remains unchanged.

Source and extracted-package gates require the module, CLI, self-test, tests,
guide, shared evaluator, and matching assurance. Earlier published package
contracts remain supported. See
[Evidence Pack gate replay](docs/reference/EVIDENCE_PACK_REPLAY_V1.7.md).

## 21. Unreleased native CloudTrail import and replay

```bash
python v17_cloudtrail_selftest.py
python -m pytest tests/test_v17_cloudtrail.py -q
python scripts/release_check.py --full
```

The 130 focused regressions bring the v1.7 total to 1,046. They cover native
Records and LookupEvents envelopes, wrapper contradictions, version/identity
handling, missing/null/present payload digests, raw-byte versus canonical-event
binding, preserved order and duplicate IDs, pagination uncertainty, malformed
JSON/Unicode/numbers, resource limits, and exclusive output creation.

Synthetic signed cases replay offline with socket/DNS/subprocess/extraction
guards. Validly signed incorrect projections fail replay while remaining
integrity-valid; required trust/timestamp failures block reconstruction, and
unverified archives never reach the parser. CLI tests cover redacted errors,
input preservation, successful comparisons, and failure exit status.

Source and extracted-package gates require the same self-test and all 130
regressions. Release manifests require the parser, CLI, self-test, tests, guide,
and existing provenance support. Independent archive verification activates
these requirements when any new CloudTrail profile file is present, preserving
the historical v1.7.0 verification contract. See
[Native CloudTrail replay](docs/reference/CLOUDTRAIL_REPLAY_V1.7.md).

## 22. Unreleased Google Cloud Audit import and replay

```bash
python v17_gcp_audit_selftest.py
python -m pytest tests/test_v17_gcp_audit.py -q
python scripts/release_check.py --full
```

The 163 focused regressions bring the v1.7 total to 1,209. Native API response
and array profiles cover nanosecond timestamps and offsets, distinct caller and
delegation identities, preserved delegation/permission order, missing/redacted
principals, explicit permission/status uncertainty, duplicate IDs, payload digest
states, incomplete/empty exports, hostile JSON, and bounded resource use.

Synthetic signed cases replay with network/DNS/subprocess/extraction guards.
An integrity-valid incorrect permission projection fails replay, an invalid
archive never reaches the parser, and independent required trust/timestamp gates
block reconstruction. CLI tests verify input preservation and failure exit codes.

Source and extracted-package gates require the same 163 regressions, self-test,
parser, CLI, guide, and provenance support. Independent package verification
requires the complete profile and matching assurance when any of its new files
is present, preserving the historical v1.7.0 contract. See
[Google Cloud Audit replay](docs/reference/GCP_AUDIT_REPLAY_V1.7.md).

## 23. Unreleased Azure Activity Log import and replay

```bash
python v17_azure_activity_selftest.py
python -m pytest tests/test_v17_azure_activity.py -q
python scripts/release_check.py --full
```

The 207 focused regressions bring the v1.7 total to 1,416. Native REST response
and EventData array fixtures replay from verified signed cases with network,
command execution, and extraction disabled. Coverage preserves fractional
timestamps, invariant/translated labels, caller/claim aliases, event/operation
distinctions, duplicate IDs, and recorded order without attributing a human or
inferring model invocation, effects, or complete collection.

Negative cases cover mixed/Log Analytics envelopes, partial errors, wrong typed
fields, absent required values, hostile JSON, opaque continuation URLs, combined
input/output budgets, exclusive output creation, symlinks, FIFO intake, and
unverified archives. Validly signed incorrect projections fail replay separately
from integrity. Unknown versions and required trust/timestamp failures retain
their existing outcomes; evidence cannot supply a parser import or command.

Source and extracted-package gates require the same 207 regressions, self-test,
and profile files. The independent candidate verifier requires the complete new
profile and matching assurance when any Azure Activity Log profile file is
present, preserving historical v1.7.0 candidate verification. See
[Azure Activity Log replay](docs/reference/AZURE_ACTIVITY_REPLAY_V1.7.md).

## 24. Unreleased Log Analytics query-result import and replay

```bash
python v17_log_analytics_selftest.py
python -m pytest tests/test_v17_log_analytics.py -q
python scripts/release_check.py --full
```

The 224 focused regressions bring the v1.7 total to 1,640. Native results with and
without PartialError replay from verified signed cases with network/DNS,
subprocess execution, and archive extraction disabled. Tests preserve typed
column/value binding, fractional timestamps, null/empty/false distinctions,
separate opaque string/dynamic columns, duplicate table names/rows, and recorded
order. The existing Azure collector and serialized receipt also retain
incomplete/unknown collection status without changing the preserved response.

Negative cases cover duplicate columns, wrong row widths, unsupported or coerced
cell types, fatal/malformed errors, mixed/batch envelopes, hostile JSON, combined
global budgets, unverified archives, exclusive output creation, symlinks, and FIFO
intake. A valid signature does not make an incorrect projection replay correctly.
Partial query results can reproduce exactly while collection remains incomplete;
the query is never run, and no source, scope, or underlying event count is inferred.

Source and extracted-package gates require the same regressions, self-test, and
profile files. Independent candidate verification requires complete new-profile
support and matching assurance when any new Log Analytics profile file is
present, while preserving historical v1.7.0 verification. See
[Log Analytics replay](docs/reference/LOG_ANALYTICS_REPLAY_V1.7.md).

## 25. Unreleased Log Analytics retained request-context replay

```bash
python v17_log_analytics_context_selftest.py
python -m pytest tests/test_v17_log_analytics_context.py -q
python scripts/release_check.py --full --json-out release-check.json
```

The 171 focused regressions bring the v1.7 total to 1,811. Synthetic acceptance
binds response, context, and projection as separate signed artifacts and replays
without network/DNS, process execution, or archive extraction. Altering a query,
workspace, time-range observation, option header, or response request ID fails
comparison even when the substituted evidence has valid signatures.

Negative cases cover exact response digest/size mismatches, ambiguous or missing
context references, multi-input lineage cycles, unknown versions, unsupported
endpoint/method/status variants, credential/unknown headers, strict JSON and
Unicode, byte/structure budgets, preserved outputs, and independent trust gates.
CLI coverage checks exclusive creation, protected source/context/symlink targets,
FIFO rejection, private error redaction, and integrity-valid replay-failure exits.
A self-consistent new assertion can replay successfully without proving actual
query execution, effective scope, or collection completeness.

Quick/full gates require the new self-test; full source and extracted-package
gates require all 171 regressions. New-profile files and matching assurance are
required conditionally by independent candidate verification, preserving older
release compatibility. The 111 Evidence Packs and 19 synthetic components remain
mandatory. See [retained query context](docs/reference/LOG_ANALYTICS_CONTEXT_V1.7.md).

## 26. Unreleased automatic Log Analytics acquisition-context capture

```bash
python v17_log_analytics_capture_selftest.py
python -m pytest tests/test_v17_log_analytics_capture.py -q
python scripts/release_check.py --full --json-out release-check.json
```

The 114 focused regressions bring the v1.7 total to 1,925. Synthetic acquisition
automatically produces response/context/projection files that can be separately
ledger-bound, signed, and replayed offline. Exact response bytes, the prepared
request, and different request-ID header names are preserved without manual
context editing. No live provider credentials or network access are required.

Negative cases cover changed prepared requests, strict parameter profiles,
credential contamination, environment credential/proxy isolation, TLS settings,
actual HTTP-adapter redirect/preload/decoding controls, body and header limits,
stream failures, HTTP/unsupported/partial/empty results, and source substitution.
File tests cover exclusive output directories, symlink targets, private POSIX
modes, member-write failures, interrupted/partial output, and receipt conflicts.
CLI tests verify parameter-file support, digest-only reports, incomplete-result
exit 2, failure exit 1, interruption exit 130, and legacy receipt compatibility.

Quick/full gates require the self-test; full source and extracted-package gates
require all 114 regressions. New-profile package files and matching assurance are
conditional in historical candidate verification. The 111 Evidence Packs and
19 synthetic components remain mandatory. See
[automatic query capture](docs/reference/LOG_ANALYTICS_CAPTURE_V1.7.md).

## 27. Unreleased Log Analytics workspace GET context replay

```bash
python v17_log_analytics_get_selftest.py
python -m pytest tests/test_v17_log_analytics_get.py -q
python scripts/release_check.py --full --json-out release-check.json
```

The 160 focused regressions bring the v1.7 total to 2,085. Synthetic acceptance
binds the response, retained GET context, and projection as separate signed
artifacts, then compares them offline with network, process execution, and
archive extraction disabled. Exact URL spelling/order, percent-decoded parameters,
partial results, and unknown completeness remain distinct observations.

Negative tests cover duplicate names including encoded aliases, parameter
injection, invalid UTF-8 and percent escapes, ambiguous plus/form decoding,
unsupported endpoints and parameters, absent-body assertions, credential/header
rejection, URL/decoded-query budgets, and response digest/size checks before
parsing. Signed query, time-range, workspace, header, and URL-encoding substitutions
retain integrity PASS but fail replay. Lineage references/cycles, unknown versions,
unverified archive content, CLI redaction/exits, FIFO input, and existing file or
symlink protection are covered. Reviewed POST projection digests are fixed
compatibility vectors; the existing POST/capture regressions remain required.

Quick/full gates require the self-test. Full source and extracted-package gates
require all 160 regressions alongside the 111 Evidence Packs and 19 synthetic
components. Conditional GET package completeness and matching assurance preserve
historical release verification. See the
[GET context guide](docs/reference/LOG_ANALYTICS_GET_CONTEXT_V1.7.md).

## 28. Unreleased automatic Log Analytics workspace GET capture

```bash
python v17_log_analytics_get_capture_selftest.py
python -m pytest tests/test_v17_log_analytics_get_capture.py -q
python scripts/release_check.py --full --json-out release-check.json
```

The 143 focused regressions bring the v1.7 total to 2,228. Synthetic GET
acquisition automatically records the prepared URL, absent body, selected
headers, exact response bytes, and compatible replay projection. The three
artifacts are separately ledger-bound and signed, then replayed with network,
process execution, and archive extraction forbidden. No live provider or real
incident evidence is used.

Negative cases cover method/scope restrictions, unsupported parameters, strict
JSON, URL expansion and decoded-query limits, malformed values, credential
contamination including percent-encoded bearer characters, prepared/observed
request substitution, response headers/encoding/lengths, transport error URL
redaction, redirects and HTTP 414 without POST fallback, partial/unknown results,
existing outputs/symlinks, private modes, interrupted/member writes, and CLI
argument/exit behavior. Signed query, workspace, timespan, encoding, request-ID,
and response substitutions fail replay even with valid integrity. Golden
digests preserve the reviewed default/explicit POST capture artifacts.

Quick/full gates require the new self-test. Full source and extracted-package
gates require all 143 regressions alongside the existing 111 Evidence Packs and
19 synthetic components. Independent package verification conditionally requires
all GET capture files, their replay/capture dependencies, and matching assurance
while preserving historical release compatibility. See the
[GET capture guide](docs/reference/LOG_ANALYTICS_GET_CAPTURE_V1.7.md).

## 29. Unreleased resource-scoped Log Analytics capture and replay

```bash
python v17_log_analytics_resource_selftest.py
python -m pytest tests/test_v17_log_analytics_resource.py -q
python scripts/release_check.py --full --json-out release-check.json
```

The 142 focused regressions bring the v1.7 total to 2,370. Synthetic POST/GET
acquisition records exact resource URLs, selected headers and response bytes;
signed multi-input replay runs with network/process execution/extraction
forbidden. Resource, subscription, case spelling, query, permission, response,
and header substitutions retain integrity PASS but fail replay.

Negative cases cover unsupported resource paths/endpoints/parameters, scope
selection, malformed permission observations, configured credential retention,
observed request changes, HTTP failure without method fallback, and CLI behavior.
Golden digests preserve reviewed workspace POST/GET capture artifacts. The prior
GET metadata rejection vector now uses unsupported `resource-put`, because
`resource-get` is an implemented profile. Its test count remains unchanged.

Quick/full gates require the self-test; full source and extracted-package gates
require all 142 regressions alongside 111 Evidence Packs and 19 synthetic
components. Conditional package requirements and matching assurance preserve
historical releases. See the
[resource guide](docs/reference/LOG_ANALYTICS_RESOURCE_V1.7.md).

## 30. Unreleased form GET and additional workspace lists

```bash
python v17_log_analytics_form_selftest.py
python -m pytest tests/test_v17_log_analytics_form.py -q
python scripts/release_check.py --full --json-out release-check.json
```

The 123 focused regressions bring the v1.7 total to 2,493. Synthetic workspace
and resource GET capture produces separately signed replay inputs. Tests cover
literal plus versus percent-encoded plus, single UTF-8 decoding, double encoding,
URL spelling/order, malformed or duplicate parameters, workspace identity/list
boundaries and injection, byte budgets, configured credential contamination,
explicit scope/profile binding, failure behavior, and CLI capture/normalize/compare.

Re-signed plus/space, workspace/order, encoded-key, and profile substitutions keep
integrity PASS but fail replay. The original percent-only GET profiles continue
to reject new forms. Existing workspace/resource capture and golden artifact
tests remain required. No real credentials or live provider acquisition are used.

Quick/full gates require the self-test. Full source and extracted-package gates
require all 123 regressions alongside 111 Evidence Packs and 19 synthetic
components. Independent package checks conditionally require all new paths,
their capture/replay dependencies and matching assurance, preserving historical
releases. See the [form guide](docs/reference/LOG_ANALYTICS_GET_FORM_V1.7.md).

## 31. Unreleased lossless Log Analytics numeric replay

```bash
python v17_log_analytics_lossless_selftest.py
python -m pytest tests/test_v17_log_analytics_lossless.py -q
python scripts/release_check.py --full --json-out release-check.json
```

The 171 focused regressions bring the v1.7 total to 2,664. Synthetic signed
replay preserves full signed 64-bit bounds, precise decimals, real token text,
numeric strings, negative zero and opaque wide numeric metadata. Collision tests
distinguish all JSON kinds and tag-shaped evidence; numerically similar lexical
forms remain separately bound. Decimal acceptance is independent of ambient
precision. Partial/unknown results and unverified scope/origin remain explicit.

Negative tests cover numeric syntax/range/coercion, UTF-8/surrogates, duplicate
keys, byte and structure expansion, table/row/type/error envelopes, unverified
archives, unknown transform versions, and CLI output protection. Re-signed
digit/rounding/wire-kind/zero/row-value/type changes retain integrity PASS but
fail replay. Two reviewed original projection hashes remain unchanged.

Quick/full gates require the self-test. Full source and extracted-package gates
require all 171 regressions alongside 111 Evidence Packs and 19 synthetic
components. Conditional package paths and matching assurance preserve historical
releases. See the [lossless guide](docs/reference/LOG_ANALYTICS_LOSSLESS_V1.7.md).

## 32. Unreleased Google Cloud Logging capture and context replay

```bash
python v17_gcp_logging_capture_selftest.py
python -m pytest tests/test_v17_gcp_logging_capture.py -q
```

The 228 focused regressions bring the v1.7 total to 2,892. Synthetic acceptance
acquires populated and empty pages, with and without continuation, binds exact
request/response artifacts, exports a signed case, verifies it offline, and
detects re-signed filter substitution. The native Audit Log projection is retained.

Negative tests cover scope/order/filter/page substitutions, resource-name and
parameter bounds, strict JSON, mismatched context digests/status/headers, unknown
profiles and versions, unverified archives, second-input lineage cycles, unsafe
TLS/redirect/preload paths, compression and stream failures, credential
contamination, private exclusive writes, interruption, and capture/offline CLIs.
Existing Audit Log, Azure context/capture, and provenance regressions run as
compatibility gates. No live provider access is used.

The full source and extracted-package gates require the self-test and all 228
regressions. Package manifest and conditional independent verification require
the new files and shared capture/native-parser dependencies, while preserving
historical release verification. See the
[analyst guide](docs/reference/GCP_LOGGING_CAPTURE_V1.7.md) for field limits and
the difference between capture completion, replay success, and complete collection.

## 33. Unreleased pinned raw-evidence reassessment

```bash
python v17_evidence_validation_selftest.py
python -m pytest tests/test_v17_evidence_validation.py -q
```

The 190 focused regressions bring the v1.7 total to 3,082. Synthetic acceptance
reassesses JSON object/array/JSONL, text, and binary bytes under retained pinned
rules, verifies signed offline replay, reproduces failed validation correctly,
and rejects a re-signed false promotion of the assessment result.

Tests cover explicit pins and case identity, complete rule schemas, exact numeric
kinds, duplicate/hostile JSON, byte/depth/node/record/line/field budgets, every-row
field checks, schema fingerprints, empty signed evidence, digest/size/literal
failures, second-input lineage cycles, unknown versions, independent trust gates,
no network/process/extraction, and CLI preservation and exit distinctions.
The existing recorded-gate, provenance, query-context, Google capture, and lossless
numeric suites remain compatibility checks; no live provider acceptance is used.

Source and extracted release gates require the self-test and all 190 regressions.
The package and conditional independent verifier require the new files, matching
assurance, and tokenizer/provenance dependencies while preserving older releases.
See [Raw-evidence reassessment](docs/reference/RAW_EVIDENCE_REASSESSMENT_V1.7.md).

## 34. Unreleased witnessed private transparency proofs

```bash
python v17_private_transparency_selftest.py
python -m pytest tests/test_v17_private_transparency.py -q
```

The 160 focused regressions bring the v1.7 total to 3,242. Acceptance covers
independent iterative history-tree roots, all leaves and prior prefixes around
power-of-two boundaries through 129 leaves, malformed/altered/unused proof nodes,
signed conflicting histories, independent subject/pin expectations, signature
roles, witness thresholds, complete-state witness checks, and 4,096-entry bounds.
CLI tests cover zero/one/two-witness operation, encrypted/protected keys, strict
bounded JSON and special-file rejection, exclusive outputs, failed snapshot
publication, interruption, and empty subjects. A legacy receipt's recorded
inclusion flag never passes cryptographic verification, including with CLI output.

Source and extracted gates require the self-test and all 160 regressions. Package
verification requires the complete feature files and assurance fields when this
profile is present, while retaining historical release compatibility. These tests
use ephemeral synthetic keys and block network connections. They do not establish
independent operator custody, trusted time, global fork freedom, evidence truth,
or an operated log service. See [Private transparency](docs/reference/PRIVATE_TRANSPARENCY_V1.7.md).

## 35. Unreleased deterministic hostile-input parser corpus

```bash
python v17_parser_corpus_selftest.py
python -m pytest tests/test_v17_parser_corpus.py -q
```

The 76 harness regressions bring the v1.7 regression total to 3,318. Separately,
the default synthetic mutation campaign also contains 3,318 logical cases across
twelve native response/context profiles, each evaluated twice. It pins corpus and
outcome digests, counts duplicate inputs explicitly, preserves numeric spelling,
and tests malformed encoding/structure/embedded JSON plus deterministic replay.

Fault injection requires detection of parser exceptions, nondeterminism, source
substitution, unsupported authority/scope/execution/coverage claims, oversized
output, false seed rejection, malformed-input acceptance, and incorrect matching
or altered-output replay. Tests also cover profile/seed/mutation bounds, independent
streams, blocked Python network/process calls, restored guards after interruption,
bounded redacted failure details, and exclusive CLI report output.

Source and extracted-package gates require both the default 3,318-case campaign
and all 76 harness regressions. The conditional independent verifier checks the
complete feature/dependency files and assurance fields while preserving historical
releases. No production parser, new dependency, live acquisition, arbitrary module
loading, or automatic gate promotion is introduced. This finite campaign is not
coverage-guided fuzzing, OS isolation, or exhaustive security validation. See
[Hostile parser corpus](docs/reference/PARSER_HOSTILE_CORPUS_V1.7.md).

## 36. Unreleased pinned nested schema comparison

```bash
python v17_schema_drift_selftest.py
python -m pytest tests/test_v17_schema_drift.py -q
```

The 182 focused regressions bring the v1.7 total to 3,500. Synthetic acceptance
compares complete nested object/array/JSONL populations, binds a retained baseline
by exact independent digest, and reproduces changed/unchanged observations within
signed case verification. Empty JSONL baseline/current artifacts also replay.

Tests cover all JSON-kind transitions; typed member/items path identity; Unicode
and separator distinctions; array occurrence versus record-presence counts; changes
after record 200; exact numeric spelling; empty arrays/record sets; byte, key, path,
record, line, depth, node, and output limits; malformed late records; incorrect pins;
re-signed input/report/authority substitution; baseline lineage cycles; unknown
versions; opt-in replay; and required independent verification gates. CLI tests
verify change-versus-replay exit codes, protected exclusive output, regular-file
bounds, interruption, and redacted failures.

Source and extracted-package gates require the self-test and all 182 regressions.
Independent package verification requires the full feature/dependency set and
matching assurance when present, preserving historical releases. No live provider
comparison, new dependency, automatic gate promotion, or provider schema-change
authority is claimed. See [Nested schema comparison](docs/reference/NESTED_SCHEMA_DRIFT_V1.7.md).

## 37. Unreleased CASE/UCO inventory exchange

```bash
python v17_case_exchange_selftest.py
python -m pytest tests/test_v17_case_exchange.py -q
python -m pip install -r requirements-case-validation.txt
python scripts/case_exchange_conformance_v17.py
```

The 101 focused regressions bring the v1.7 total to 3,601. Acceptance verifies
immutable signed-case snapshots, hashes/sizes, deterministic instance IDs, primary
and secondary input references, omissions, literal labels, unknown versions,
external identity/key/policy gates, tampered members, resource limits, complete
graph comparison, integer types, fixed contexts, and CLI failure/output behavior.

The separate pinned CASE/UCO 1.5.0 conformance command validates a synthetic graph,
preserves all 89 RDF statements through an N-Triples round trip, and rejects four
invalid graphs. It uses the official CASE validator with a pinned local ontology;
network access and ontology imports are disabled. CI and full source/extracted
gates require this check. Runtime export/comparison do not require RDF libraries.
The independent package verifier checks feature completeness and assurance while
preserving historical release support. See [CASE/UCO exchange](docs/reference/CASE_EXCHANGE_V1.7.md).

## 38. Unreleased bounded archive intake and hostile corpus

```bash
python v17_archive_intake_selftest.py
python -m pytest tests/test_v17_archive_intake.py -q
```

The 190 focused regressions bring the v1.7 total to 3,791. Acceptance covers
bounded ZIP32/TAR/gzip/bzip2/xz metadata, early directory/header counts, expansion
and LZMA memory limits, local/central conflicts, overlap, ZIP64/sparse rejection,
PAX/GNU extensions, complete termination, portable paths/aliases, links, encrypted
or special members, unopened corrupt ZIP bodies, snapshots, and legacy gate/CLI
behavior. Parse failures remain review findings, with redacted error details.

A separate pinned 680-case campaign exercises all five profiles twice, reports
32 accepted metadata observations and 648 rejections, blocks member-content/
extraction/network/process APIs, and checks deterministic output and qualification
flags. Source and extracted gates require both checks. Independent package
verification requires feature completeness and assurance while preserving older
releases. This is finite synthetic mutation testing; coverage-guided fuzzing and
independent document rendering remain separate. See [Bounded archive intake](docs/reference/ARCHIVE_INTAKE_V1.7.md).

## 39. Unreleased coverage-guided parser and archive fuzzing

```bash
python v17_fuzz_targets_selftest.py
python -m pytest tests/test_v17_fuzz_targets.py -q
# Optional engine: Linux x86_64 / CPython 3.12
python -m pip install --only-binary=:all: -r requirements-fuzz.txt
python scripts/run_coverage_fuzz_v17.py --runs 5000 --out-dir /tmp/ai-dfir-fuzz-new
```

The 115 focused regressions bring the v1.7 total to 3,906. They exercise every
fixed selector, accepted/rejected seeds, source and claim fault injection,
nondeterminism, unknown selectors, bounds, restored API tripwires, disabled
assertions, partial/failed engine completion, timeouts, failure retention,
exclusive output, private permissions, and redacted CLI failures.

Source and extracted full gates require those tests and a pinned 34-case,
17-profile preflight. They explicitly do not count the preflight as a coverage-
guided campaign. The optional Atheris runner requires actual native completion
and nonzero instrumentation counters. PR/main CI requires 5,000 inputs, and
the existing scheduled/manual workflow requires 20,000 with a rotating seed.
An initial local 20,000-input campaign passed; counters are build/run observations
and are not a coverage percentage or proof of safety. See
[Coverage-guided fuzzing](docs/reference/COVERAGE_FUZZING_V1.7.md).
