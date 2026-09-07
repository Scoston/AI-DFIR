# Deterministic hostile-input corpus for offline parsers

Status: implemented in development, unreleased. This bounded synthetic campaign
adds repeatable structural and byte mutations across twelve fixed provider
response and retained-context profiles. It is a developer test utility, not a
parser sandbox, continuous coverage-guided fuzzer, or production certification.
It does not change evidence interpretation, case gates, or the replay registry.

## Fixed profiles and inputs

| Profile names | Parser surface |
| --- | --- |
| `cloudtrail-records`, `cloudtrail-lookup` | Native CloudTrail Records and LookupEvents, including embedded event JSON |
| `gcp-audit-entries`, `gcp-audit-array` | Google Cloud Audit response and array |
| `azure-activity`, `azure-array` | Azure Activity response and EventData array |
| `log-analytics-tables`, `log-analytics-resource` | Original typed table and resource-table results |
| `lossless-tables`, `lossless-resource` | Exact numeric-token table and resource-table results |
| `log-analytics-context` | Retained workspace POST context paired with fixed response bytes |
| `gcp-logging-context` | Retained entries.list context paired with fixed Audit Log response bytes |

Seeds are fixed synthetic factories from the existing acceptance cases. No
user-supplied corpus, parser module, command, URL, provider credential, acquisition,
or filesystem discovery is loaded. A profile's input hash and fixed name identify
the seed. Mutations of context operate on the retained context only; the paired
response bytes remain fixed, so changed response-binding claims must fail.

Each profile first tests its valid seed and whitespace variation, then guaranteed
rejection cases: invalid UTF-8/BOM/NUL/comment/trailing content, truncated JSON,
excessive nesting, duplicate keys, unpaired Unicode, non-JSON numeric constants,
and excessive number tokens. LookupEvents also tests six malformed embedded JSON
strings. A stable random stream then selects structural replacements and member
deletions. The mutator preserves unmodified numeric spelling, including wide
integers, precise decimals, negative zero, and numeric strings.

Default seed 17017 and 256 structural mutations per profile produce 3,318 logical
cases. Inputs may repeat; reports separately count unique inputs within each
profile and their sum across profiles. Each logical case runs twice. The corpus
digest binds profile, ordinal, category, input digest, and expected result; a
separate outcome digest additionally binds status, output digest, and error type.
The self-test pins both digests for this corpus version. Profile selection order
does not change a profile's stream or reorder the fixed campaign output.

## Oracles and failures

Expected parse rejection is `ValueError`, including the parsers' typed
`ProvenanceError` and standard date/JSON/Unicode errors. Other ordinary exceptions
are failures. Repeated invocations must agree on acceptance/rejection and the
complete canonical output digest. An accepted projection must satisfy all of:

- a bounded canonical object with the exact source digest and, where applicable, context digest;
- source authenticity and network requirement explicitly false, with collection completeness false or unknown;
- any recorded scope/execution/permission/pagination verification flags remaining false;
- matching retained-output replay passing, and an altered source-digest projection failing comparison.

The valid seeds must be accepted and guaranteed-malformed cases must be rejected.
Structural mutations may legitimately be accepted or rejected: optional metadata
and opaque payloads can change without making an export invalid. Acceptance alone
is never treated as evidence truth or verified provider origin.

Reports count all failures but retain details for at most twenty. A reproducer is
identified by corpus version, seed, mutation count, profile, ordinal, category,
and input SHA-256. Reports omit raw evidence, parser output payloads, exception
messages, and tracebacks. `KeyboardInterrupt` remains an interruption rather than
a swallowed parser failure. Fault-injection regressions confirm detection of
unexpected exceptions, nondeterminism, digest/authority promotion, incorrect
replay acceptance, output overflow, and false acceptance/rejection.

## Commands and limits

Run in a dedicated process. During parser evaluation the harness temporarily
blocks selected Python socket/DNS and process-creation operations. These guards
are process-wide and restored afterward; they are not OS isolation and do not
make arbitrary parser code safe. Production parsers are fixed trusted code.

```bash
python parser_corpus_v17.py --out parser-corpus-report.json

python parser_corpus_v17.py --seed 42 --mutations 512 \
  --profile cloudtrail-lookup --profile lossless-resource \
  --out selected-parser-report.json

python v17_parser_corpus_selftest.py
python -m pytest tests/test_v17_parser_corpus.py -q
```

The seed is an unsigned 32-bit integer. Structural mutations are limited to
1–2,048 per selected profile; every synthetic input is at most 64 KiB. Output
projections retain each parser's own bound. Source/extracted release checks run
the default pinned campaign with their external self-test timeout. This utility
does not enforce a separate per-case wall-clock or memory sandbox.

The optional report uses exclusive mode-0600 creation and never overwrites an
existing file or symlink. A failed/interrupted write returns an unsuccessful
status; retain it as incomplete and retry into a new path. Standard output also
contains the report. Exit 0 means this selected finite campaign passed, 1 means
it found a failure or could not complete/output the campaign, and 130 indicates
interruption. An unknown profile is an argument error; repeated profiles fail.

The source and extracted package gates require the pinned 3,318-case self-test
and all 76 harness regressions. Independent package verification requires the
complete harness, profile dependencies, guide, and matching assurance fields
when this feature is present, while retaining older release compatibility.

Continuous coverage-guided fuzzing, larger hostile archive/document corpora,
independent renderers, target-platform resource isolation, and external security
evaluation remain separate roadmap work. A passing campaign does not establish
exhaustive parser correctness, operating-system isolation, or live collection.
