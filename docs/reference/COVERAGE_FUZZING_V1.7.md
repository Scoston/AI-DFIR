# Coverage-guided parser fuzzing (development)

The optional Atheris 3.1.0 job uses Python bytecode coverage to choose mutations
of committed synthetic provider responses, request contexts, and archive inputs.
It complements the pinned finite parser and archive campaigns. It does not
acquire evidence, run queries, load user-selected parsers, or change quality gates.

## Run the qualified profile

Use Linux x86_64, CPython 3.12, and the regular runtime dependencies:

```bash
python -m pip install --only-binary=:all: -r requirements-fuzz.txt
python scripts/run_coverage_fuzz_v17.py --runs 5000 --seed 17019 --out-dir /tmp/ai-dfir-fuzz-new
```

The output directory must be new and its parent must exist. It is created with
mode 0700; logs, reports, corpus seeds, and native failure artifacts use 0600.
The CLI exits 0 only after successful engine completion; failures exit 1 and
argument syntax errors exit 2. An interrupted or failed run never reports PASS.
Preflight/setup failures may happen before a report can be created. Ordinary
console failures contain an exception type without evidence or local path text.

`report.json` records engine/Python versions, the run seed, selected source-file
hashes, the pinned preflight manifest, limits, and actual engine execution and
coverage counters. The counters include instrumented helpers. They are not a
percentage of project coverage and are not comparable across arbitrary builds.
The report is unsigned. A successful synthetic campaign does not authenticate a
source, prove complete collection, or certify parser safety.

## Targets and oracles

Each input starts with one byte selecting the following fixed profile, followed
by raw input bytes. Selector order is part of the v1.7 harness profile.

| Selector | Profile |
|---|---|
| 0 | CloudTrail Records |
| 1 | CloudTrail LookupEvents |
| 2 | Google Cloud Audit entries |
| 3 | Google Cloud Audit array |
| 4 | Azure Activity Log response |
| 5 | Azure Activity Log array |
| 6 | Log Analytics workspace tables |
| 7 | Log Analytics resource tables |
| 8 | Lossless workspace numeric tables |
| 9 | Lossless resource numeric tables |
| 10 | Log Analytics workspace POST request context |
| 11 | Google Cloud Logging entries.list request context |
| 12 | ZIP32 metadata |
| 13 | TAR metadata |
| 14 | gzip-wrapped TAR metadata |
| 15 | bzip2-wrapped TAR metadata |
| 16 | xz-wrapped TAR metadata |

Empty inputs and selectors above 16 are ignored; selected empty payloads must
reject. Before starting the engine, all 17 valid synthetic seeds must accept and
all 17 selected empty payloads must reject. The source/output manifest is pinned
by the engine-independent self-test. No real provider exports enter this corpus.
Context mutations retain a separate fixed synthetic response.

Every selected engine input is evaluated twice. Accepted provider projections
must retain source/context digest bindings, bounded output, unknown/false
authority and completeness claims, successful matching replay, and rejection of
altered replay. Archive observations must retain source/count bindings and
metadata-only claims. Unexpected exceptions, invariant failures, and differing
repeated outcomes fail the engine. Expected parser rejection is a normal result.
Coverage does not imply that every format's deep paths were exercised equally.

## Limits and isolation

- 100–20,000 requested executions; default 5,000. A nonzero 32-bit seed is required.
- At most 16,385 bytes per input, including the selector. Production parser bounds
  can be larger; this campaign does not exercise every production-size boundary.
- Native limits: five seconds per input, 512 MiB RSS threshold, and 540 seconds
  campaign time. Parent wall timeout and child CPU limit are 600 seconds.
- Child core dumps are disabled and each child-written file is limited to 8 MiB.
  The engine log is also read under that bound. Normal retained corpus data is
  bounded by run count and maximum input length (under 314 MiB at maximum runs).
- A timeout kills the child process group. The temporary evolving corpus is
  removed on normal completion or handled failure; forced parent termination
  can leave temporary files for the runner host to clean up.
- Python socket connection/send, DNS, subprocess, shell, ZIP member-content,
  and TAR extraction APIs are blocked while parsing. These are tripwires, not an
  OS sandbox. Native codecs and libraries are not rebuilt with sanitizers.

The runner launches a fixed script with an argument list and no shell. It has no
arbitrary command, module, URL, corpus, or additional engine-flag option. The
private output parent and checked-out source must be trusted local paths.
Atheris/native RSS and timeout checks are detection thresholds, not strict
process-memory reservations or instruction-by-instruction resource isolation.

## CI, packaging, and retained failures

The existing CI workflow requires a 5,000-input run on PRs and main pushes.
The existing scheduled/manual Full Regression workflow adds 20,000 inputs and a
seed derived from its run number. Both retain the report, engine log, and any
failure inputs for 14 days, including when the campaign step fails. They do not
upload the evolving corpus. Dependency/install failures fail the job; they do
not silently skip coverage testing.

Source and extracted full release gates require 115 engine-independent harness
regressions (including both workflow YAML files) and a 34-case, 17-profile pinned preflight. These gates do **not**
claim to have run Atheris. The release manifest explicitly records the preflight
as `coverage_guided: false`; the optional engine has its own CI/run report.
The independent package verifier checks the complete harness and those claims.
No Atheris dependency is added to ordinary runtime or cross-platform development
requirements.

`engine.log` retains native failure diagnostics and Atheris writes a selector-
prefixed reproducer in `failures/` when possible. Preserve it with the report and
the exact source revision. For developer diagnosis in a disposable test host,
the internal child can replay one retained synthetic failure under host limits:

```bash
timeout 15s python scripts/fuzz_parsers_v17.py -runs=1 -timeout=5 -rss_limit_mb=512 /absolute/path/to/failures/crash-HASH
```

This direct child command is a developer interface; the bounded public runner is
the qualified campaign path. Fix confirmed bugs with focused regressions before
changing seed pins. Follow SECURITY.md for vulnerability reporting and do not
publish customer evidence in CI artifacts.

Broader document formats, structure-aware archive mutation, persistent corpus
curation, native sanitizer builds, and independent rendering remain future work.

## Dependency and references

[Atheris](https://github.com/google/atheris) is an Apache-2.0 licensed optional
development tool built on libFuzzer. The pinned
[3.1.0 package](https://pypi.org/project/atheris/3.1.0/) provides the qualified
CPython 3.12 Linux wheel. Bytecode instrumentation covers the fixed module list
reported by this harness; this wheel is not a native sanitizer qualification.

PyYAML (MIT license) is an explicit development dependency for the workflow syntax
regressions; it is not added to the ordinary runtime requirements.
