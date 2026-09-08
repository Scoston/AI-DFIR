# Structured fuzz targets and curated synthetic corpus (development)

The coverage harness now rebuilds bounded ZIP32 containers around mutated DOCX
XML, font relationships, and literal member names. Recomputed headers, sizes,
offsets, and CRCs let mutations reach selected-part parsing instead of usually
failing at the archive checksum. The original twenty selector meanings and
source/output digests remain pinned and unchanged.

## Fixed profiles

| Selector | Mutated payload | Generated input |
|---|---|---|
| 20 | Main document XML | One stored `word/document.xml` part |
| 21 | Font relationship XML | Fixed document/font table, mutated relationships, opaque synthetic font |
| 22 | UTF-8 member name | One stored member with fixed synthetic content |

Inputs remain at most 16,385 bytes including the selector. Payloads are nonempty
and at most 16 KiB. Generated archives contain one to four regular stored members,
with names at most 4,096 UTF-8 bytes and at most 32 KiB total archive bytes. The
builder uses in-memory header assembly and never opens or extracts a member.
Invalid UTF-8, unsupported profiles, and excessive structures reject normally.

The two DOCX profiles use the existing pure selected-part loader and its source,
selected-byte, CRC, and unverified-claim oracles. Font bytes stay opaque; no font
worker runs. The name profile uses metadata inspection, including unsafe-name
findings. An accepted observation does not authorize extraction or establish
that a name, reference, document, or payload is safe. Each accepted structured
outcome binds the profile, mutation bytes, generated archive, and parser report
by digest. Every mutation is evaluated twice to detect inconsistent outcomes.

## Persistent reviewed corpus

`tests/fixtures/fuzz/v17/structured_cases.json` contains eight synthetic records.
Each has a unique stable ID, fixed profile name, canonical base64 payload, and
expected `ACCEPT` or `REJECT` outcome. Its exact bytes are SHA-256 pinned in
`v17_structured_fuzz.py`; the preflight separately pins input/output digests.
The fixed corpus is opened without following a final symlink, must be a regular
file of at most 64 KiB, and is checked before JSON parsing. The checkout and its
parent directories remain trusted. There is no arbitrary corpus-path option.

| Case | Expected observation |
|---|---|
| `docx-valid-text` | Valid selected XML accepts |
| `docx-entity-forbidden` | DTD/entity input rejects after ZIP reconstruction |
| `docx-depth-excess` | Excessive XML nesting rejects |
| `font-external-reference` | Bounded relationship metadata accepts without loading an external font |
| `font-duplicate-id` | Duplicate relationship identity rejects |
| `zip-parent-name` | Metadata accepts and records a path-escape finding |
| `zip-control-name` | Literal NUL-containing name is retained with an ambiguity finding |
| `zip-invalid-utf8` | Name decoding rejects |

Before every public campaign, 23 valid seeds accept, 23 selected empty payloads
reject, and all eight curated outcomes match: 54 preflight cases. All 54 inputs
are then supplied to Atheris, including the rejection seeds. The campaign report
records the corpus-file hash, curated input/output rows, source hashes, and the
generated-archive bound. The corpus file is committed and packaged; the evolving
native corpus remains temporary and is removed on handled completion/failure.
Retained crash inputs remain in the campaign's private `failures/` directory.

To curate a confirmed regression:

1. Reproduce it against the exact recorded source and profile in a disposable
   test host. Preserve the report and original failure for diagnosis.
2. Create a minimal synthetic reproducer and a focused parser/oracle test. Never
   commit customer evidence, credentials, or blindly import native corpus files.
3. Add or replace a reviewed case with a stable ID and an explicitly justified
   outcome. Regenerate canonical base64 and the exact corpus digest. If the case
   count changes, deliberately update the loader, self-tests, package gates, and
   documentation together. A changed hash alone is not a bug fix.
4. Confirm the old selector/outcome contract, updated preflight pin, focused tests,
   actual bounded Atheris campaign, source/extracted gates, and independent
   package verification before merging.

## Acceptance and limits

```bash
python v17_structured_fuzz_selftest.py
python v17_fuzz_targets_selftest.py
python -m pytest tests/test_v17_structured_fuzz.py tests/test_v17_fuzz_targets.py -q
python scripts/run_coverage_fuzz_v17.py --runs 20000 --seed 17019 --out-dir /tmp/ai-dfir-structured-fuzz-new
```

The engine-independent gates require 96 structured/corpus regressions, 147
general harness regressions, the pinned 54-case preflight, and the preserved
twenty-profile manifest. Tests include independently readable ZIP CRCs, deep XML
rejection, literal hostile names, forged source/claim results, nondeterministic
generation, corrupt or ambiguous corpus records, symlinks/FIFOs, and actual seed
handoff to the runner. Full source/extracted gates require all five new package
files; independent verification retains the earlier 17/18/20-profile contracts.

The optional campaign still requires Linux x86_64, CPython 3.12, and pinned
Atheris 3.1.0. Existing process limits, Python API tripwires, required PR/main and
scheduled jobs, and failure retention apply; see
[Coverage-guided fuzzing](COVERAGE_FUZZING_V1.7.md). There are no new dependencies.
This implements a small, manually curated corpus and three structure-preserving
targets. It does not claim full grammar generation, all document formats, native
sanitizers, OS isolation, independent rendering, complete collection, or source
authenticity. Broader format/corpus qualification remains open.
