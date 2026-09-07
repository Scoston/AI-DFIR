# CASE/UCO inventory exchange — v1.7 development

Status: implemented in development, unreleased. This optional one-way view uses
CASE 1.5.0 and UCO 1.5.0 to exchange selected verified artifact inventory and
recorded lineage. It complements the existing neutral/STIX/ECS exports.

The output is **unsigned**. Retain the original signed case ZIP and independently
selected export verification key. A graph detached from those inputs cannot
authenticate itself. No evidence-quality, conclusion, or closure gate changes.

## Create and compare

```bash
python case_exchange_v17.py \
  --zip retained-case.zip --export-public-key approved-export.pub.pem \
  --tenant TENANT-001 --case CASE-001 --out inventory.jsonld

python case_exchange_v17.py \
  --zip retained-case.zip --export-public-key approved-export.pub.pem \
  --tenant TENANT-001 --case CASE-001 --compare inventory.jsonld
```

Tenant and case identity are mandatory. The original package must pass manifest,
artifact, ledger, checkpoint, signer, and provenance checks. External key-policy,
authenticated-store/root, retained trust-history, and RFC 3161 timestamp options
are the same as the offline case verifier; required but unavailable or rejected
controls block export. For example, an independently retained policy may be pinned:

```bash
python case_exchange_v17.py \
  --zip retained-case.zip --export-public-key approved-export.pub.pem \
  --tenant TENANT-001 --case CASE-001 --out inventory.jsonld \
  --checkpoint-key-policy approved-policy.json \
  --expected-key-policy-sha256 APPROVED_CANONICAL_POLICY_SHA256 \
  --policy-evaluation-time 2026-09-07T12:00:00Z \
  --require-checkpoint-key-policy
```

Use the same explicit evaluation time, policy, and other trust inputs when
reproducing a graph. The complete verifier report is digest-bound; a changing
policy evaluation time or trust result can change that digest even when evidence
bytes are unchanged. A successful comparison proves reproduction under the
provided verification inputs, not that a previously reported trust policy was
independently approved or remains current.

`--out` and `--compare` are exclusive. New outputs use mode `0600`, exclusive
creation, and `fsync`; existing files and symlink targets are never overwritten.
Exit `0` means export or comparison succeeded, `1` means failure, and `130` means
interrupted. Argument errors use argparse's exit `2`. The console prints bounded
status/digest information without evidence content or input/output paths. A failed
write can leave an incomplete newly created file; only a successful exit and
matching output digest report completion.

## Mapping and meaning

The graph has an inline `@context` dictionary and a sorted `@graph` array.
Prefixes are fixed by the profile; there is no remote context, `@import`, selected
ontology URL, or runtime RDF loading. Input-derived names and labels are literals,
never keys, predicates, type names, or executable/remote references.

| Verified input or observation | Export representation |
| --- | --- |
| Case identity | `case-investigation:Investigation`, case/tenant literals |
| Original immutable ZIP | `uco-observable:ObservableObject`, content size and SHA-256 |
| Bound artifact | `uco-observable:ObservableObject`, artifact ID and literal package path |
| Exact retained bytes | `uco-observable:ContentDataFacet`, integer size and linked `uco-types:Hash` |
| SHA-256 digest | `uco-types:hashMethod` = `SHA256`, `hashValue` typed `xsd:hexBinary` |
| Recorded primary lineage | `uco-core:Relationship`, source = child, target = parent, directional |
| Relationship type/transform/version | Explicit recorded AI-DFIR literals; metadata bound by digest |
| Validated secondary inputs | AI-DFIR context/rules/baseline artifact references for the four fixed v1.7 profiles |
| Ledger binding | Record hash, ledger sequence, and ledger-entry hash |
| Recorded classification/media labels | Explicit recorded AI-DFIR literals; content type and handling authority are not inferred |
| Verification | Source archive, checkpoint/report digests, trust-source and gate-status literals |
| Omitted data | Counts for other provenance records, unbound ledger events, and unmapped package files |

The project extension namespace is
`https://github.com/Scoston/AI-DFIR/ns/case-exchange/1.7/`. It is an identifier
namespace, not a schema-loading endpoint. CASE/UCO validation checks the standard
terms and their constraints; the project's regression tests check its extension
meaning and complete projection. General CASE validators do not authenticate or
fully constrain these project-specific claims.

The primary relationship is explicitly named `AI-DFIR recorded lineage`; the
original relationship string is retained separately. Known v1.7 context/rules/
baseline references are emitted only when their exact transformation version
received the provenance validator's additional-input checks. Unsupported versions
retain their recorded strings and metadata digest without interpreting metadata
as additional validated edges. No transformation, model, or tool is executed.

All instances have deterministic UUIDv5 URNs. The UUID name is the canonical JSON
array `[profile, exact_zip_sha256, node_kind, identity]` under UUID's URL namespace.
This avoids delimiter ambiguities and deliberately scopes instances to one exact
export archive. Recompressing or otherwise changing archive bytes creates new
IDs. Equal artifact content does not collapse distinct artifact identities.
UUIDs are identifiers; SHA-256 commitments and the source signatures provide
integrity. Any duplicate generated identifier fails closed.

The graph does not export prompts, structured model output, arguments, analyst
rationales, arbitrary metadata values, or inferred actors/actions/custody. Their
records remain in the original case and contribute to the bound verification
report. Package names, case identifiers, classification labels, and hashes can
still be sensitive; this profile does not certify a graph for public release.

## Bounded snapshot and comparison

The file reader opens a regular input once, bounds compressed bytes, and captures
an immutable value. Regular input symlinks are permitted. The verifier accepts
this byte value, hashes it, and checks a `BytesIO` archive. Projection reopens
only that same immutable value after all required checks pass; it never extracts
members or reopens the original path for evidence metadata. Existing path-based
verification remains available. Callers of the verifier's new byte-input form
outside this exchange profile must bound their own compressed input.

| Limit | Maximum |
| --- | ---: |
| Compressed source archive | 64 MiB, nonempty |
| Archive members | 4,096 |
| Total uncompressed bytes | 128 MiB |
| Individual uncompressed member | 16 MiB |
| Compression ratio | 1,000 |
| Provenance records | 10,000, under existing provenance limits |
| Output JSON bytes | 16 MiB |
| Generated graph nodes | 32,000 |
| Comparison/global output JSON depth | 32 |
| Comparison/global output JSON nodes | 200,000, including dictionary keys |

The effective ceiling is the first applicable bound, not a promise every maximum
can be reached simultaneously. Empty valid provenance produces an explicit empty
artifact inventory and unmapped-file counts, not a claim of complete collection.

Comparison parses bounded strict JSON only. Duplicate keys, malformed Unicode,
nonfinite numbers, and excessive structures fail. It recomputes the complete graph
from a newly verified source snapshot and compares RFC 8785 canonical JSON while
requiring integer numeric types. A floating-point spelling such as `2.0` cannot
replace an emitted integer: RDF consumers can assign different literal datatypes.
Object-key order and whitespace may vary. Array order, contexts, identifiers,
hashes, counts, bindings, and qualification flags must match. This is deliberately
not RDF-equivalence or general JSON-LD import: a semantically equivalent graph
rewritten by another tool may fail this profile's comparison.

## Acceptance and standards references

```bash
python v17_case_exchange_selftest.py
python -m pytest tests/test_v17_case_exchange.py -q
python -m pip install -r requirements-case-validation.txt
python scripts/case_exchange_conformance_v17.py
```

The 101 regressions cover exact source/hash/size binding, deterministic IDs,
primary and secondary references, omissions, recorded labels, unknown versions,
immutable source use, signed-member tampering, wrong identity/keys, policy pins
and revocation, mandatory independent gates, resource bounds, integer types,
malformed comparison JSON, context/claim replacement, exclusive output, and
redacted failure/interruption handling.

The conformance command generates only its own synthetic graph. It checks
`case-utils==0.18.0`, `rdflib==7.6.0`, `pyshacl==0.40.1`, and the bundled CASE/UCO
1.5.0 ontology byte digest
`d246cfba2dbb8a521a97015c41c973a861a4906f6017d0e5f6c0b17487b63a7f`.
Network calls/imports are disabled. The official validator accepts the graph;
all 89 RDF triples survive an N-Triples round trip without blank nodes. Four
negative graphs cover hash datatype, missing relationship target, size datatype,
and unknown ontology concepts. Warnings are not accepted as conformance.

CI and full source/extracted release gates require this acceptance; the independent
package verifier requires the complete feature and matching assurance when present.
RDF tooling is optional for development/release validation and is not imported by
the runtime exporter or comparator. No runtime SHACL validation is claimed in
individual output graphs. Acceptance is not a certification of an external case
management deployment, interoperability with every consumer, or complete CASE
investigation modeling. Bidirectional import and richer investigation mapping
remain separate work.

Primary references: [CASE 1.5.0 release](https://caseontology.org/releases/1.5.0/),
[CASE graph and validator guide](https://caseontology.org/ontology/get-started.html),
[CASE instance identifiers](https://caseontology.org/resources/instance_data.html),
[CASE ontology documentation](https://ontology.caseontology.org/documentation/index.html),
and [UCO ontology documentation](https://ontology.unifiedcyberontology.org/documentation/index.html).
