# Bounded archive intake — v1.7 development

Status: implemented in development, unreleased. The existing archive-intake CLI
and content-intake gate now use a bounded immutable-snapshot metadata parser.
The former ZIP/TAR scanner accumulated all member metadata without explicit
resource limits; TAR detection could also expand compressed input without a
profile limit. The new parser checks resource and structural constraints before
returning a complete metadata report.

This is static intake triage. It never extracts members, runs archive content,
recurses into nested files, or verifies ZIP member payload CRCs. A successfully
inspected archive is not certified safe to extract or execute.

## Usage and existing integration

```bash
python archive_intake_forensics.py retained.zip --out new-intake-report.json
python archive_intake_forensics.py retained.tar.gz
python content_intake_gate.py retained.tar.xz
```

The existing `analyze`, `analyze_zip`, `analyze_tar`, and `suspicious_name` entry
points remain available. The legacy report retains its v1.2 schema and adds
`analysis_profile: ai-dfir/bounded-archive-intake/v1.7`, source digest/size, resource
observations, and explicit qualification flags. Its link Boolean retains the old
symlink-or-hardlink meaning; `is_hardlink` distinguishes hardlinks. The pure new
profile keeps separate `is_symlink` and `is_hardlink` flags.

```python
from v17_archive_intake import inspect_archive, read_archive

raw = read_archive("retained.tar.gz")
report = inspect_archive(raw, input_format="tar-gzip")
```

The pure API requires an explicit format. The legacy CLI selects from bounded
snapshot magic bytes and checks the selected parser; it does not reopen the input
to probe competing decoders. Input symlinks may refer to regular files. The
reported legacy path is the absolute requested path, not a claim that a symlink
target or filesystem identity remained unchanged. The SHA-256 identifies the
bytes actually inspected.

New CLI report files use exclusive creation, mode `0600`, and `fsync`. Existing
files or symlink targets are not overwritten. The formatted report also has an
output-size check. A failed write may leave an incomplete newly created file;
exit `0` is required for completed publication. Without `--out`, the CLI prints
the metadata report as escaped JSON. Errors use a generic redacted `FAIL` report
and exit `1`; interruption returns `130`. Findings do not change the archive CLI's
successful-analysis exit `0` into an authorization or safety decision.

The content-intake gate retains existing severity handling: critical findings
produce `QUARANTINE`, high findings produce `REVIEW`, and parsing/limit failures
produce a redacted high `archive_parse_failure` finding. Additional `.bz2`, `.xz`,
`.tbz`, `.tbz2`, and `.txz` suffixes are inspected alongside the existing archive
suffixes. A format failure cannot silently become a clean archive result. The
existing `generic.agent_workspace_archive_intake` Evidence Pack remains in use;
this change does not approve evidence quality or investigative conclusions.

## Supported bounded profiles

| Profile | Interpretation |
| --- | --- |
| `zip` | Single-disk ZIP metadata with 32-bit directory/member fields; local/central metadata consistency and nonoverlapping declared ranges |
| `tar` | Complete USTAR, supported GNU long-name/link, and bounded PAX metadata |
| `tar-gzip` | One complete gzip stream containing the supported TAR profile |
| `tar-bzip2` | One complete bzip2 stream containing the supported TAR profile |
| `tar-xz` | One complete XZ stream containing the supported TAR profile, with an LZMA dictionary-memory cap |

ZIP directories are walked and actually counted before `ZipFile` constructs its
member list. End-record counts alone are not trusted as a resource bound. Split
archives, ZIP64 extras, prefixes, trailing data, malformed extra fields, conflicting
local/central names/flags/methods or non-descriptor size/CRC fields, and overlapping
declared member ranges are rejected. An unsupported standard-library ZIP version
is a controlled rejection. ZIP member contents are never opened or decompressed;
compression method and encryption are metadata observations only.

TAR compression is expanded only into bounded memory, never into filesystem
members. This necessarily decompresses the container stream, including bytes
around member bodies. The parser then checks complete 512-byte blocks, header
checksums, member extents, physical-header counts, and a two-zero-block terminator
with zero-only padding. It checks PAX framing/UTF-8/duplicate keys and GNU extension
lengths before standard-library semantic interpretation. Physical versus logical
member counts must agree. GNU sparse files, PAX size/sparse/binary-name overrides,
non-file member payloads, orphan extensions, excessive extension chains, and
trailing/concatenated containers are outside the profile and fail closed.

The profile intentionally accepts less than every valid ZIP/TAR variant. It does
not silently fall back to the former unbounded parser for unsupported structures.
The stricter limits and format rules also apply to existing archive entry points.

| Resource | Maximum |
| --- | ---: |
| Retained compressed/input bytes | 16 MiB, nonempty |
| Decompressed TAR stream | 32 MiB |
| Effective members | 4,096 |
| Physical TAR headers, including extensions | 8,192 |
| Declared individual member size | 32 MiB |
| Total declared member size | 128 MiB |
| Member or link name, UTF-8 bytes | 4,096 |
| Aggregate member/link-name bytes | 1 MiB |
| PAX body | 64 KiB |
| PAX records per body | 256 |
| Consecutive TAR extension headers | 8 |
| Compressed TAR expansion ratio | 1,000 |
| LZMA decoder dictionary-memory limit | 64 MiB |
| Encoded report | 8 MiB |

The first applicable bound controls acceptance. Uncompressed TAR also remains
subject to the 16 MiB input cap. These are format/data limits, not an OS sandbox
or a hard process-wide memory/CPU deadline. No partial member-list success is
returned when a limit is exceeded; the old 5,000-row output slice is removed.

## Findings and qualifications

Member names remain literal data. Findings cover absolute/drive-relative/UNC
paths, raw `..` segments, control characters, ambiguous separators or trailing
dot/space names, Windows reserved names, portable path aliases, link targets,
symlinks/hardlinks, special members, encryption, extreme declared ZIP ratios,
known archive suffixes, and agent/workspace auto-load controls.

Portable alias detection combines slash normalization, NFC, case folding,
trailing-dot/space removal, and path normalization. This is conservative triage
for cross-platform handling, not a statement that all filesystems treat two
names identically. Both original names remain in the report. A duplicate or
portable alias produces a finding instead of silently discarding one entry.

TAR link targets are retained as literals and assessed separately. ZIP symlink
targets generally live in member content; that content is not read and no target
is inferred. Likewise, a corrupt ZIP body may still have consistent metadata:
`member_payload_integrity_verified` remains false even if inspection succeeds.

Every pure report binds exact input bytes and format and explicitly reports:
`metadata_only: true`, `members_extracted: false`,
`member_payload_integrity_verified: false`, `source_authenticity_verified: false`,
`archive_safety_verified: false`, `extraction_authorized: false`,
`collection_complete: null`, and `network_required: false`.

These safeguards cover archive intake. They do not establish independent visible
rendering, qualify unrelated document/font parsers, detect all nested containers
from filenames, or authorize execution after a clean triage result.

## Acceptance

```bash
python v17_archive_intake_selftest.py
python -m pytest tests/test_v17_archive_intake.py -q
```

All 190 regressions cover the five profiles, supported TAR dialects, Unicode and
portable aliases, links/special files, encryption, unopened corrupt ZIP payloads,
early directory/header bounds, local metadata conflicts, overlapping members,
small local ZIP64 extras, unsupported ZIP versions, compressed-stream expansion,
LZMA memory, PAX overrides/framing, extension chains, sparse/non-file bodies,
terminators, empty archives, all resource budgets, immutable input use, legacy
compatibility, intake severity, and CLI output/failure behavior.

The separate deterministic campaign contains 680 logical cases: five seeds, seven
guaranteed rejection variants per profile, and 128 seeded mutations per profile.
It evaluates each case twice, binds all input/outcome digests, and checks source
binding and qualification flags. Public compressed seeds are committed as exact
bytes. Seed `17018` produces 32 accepted metadata observations and 648 controlled
rejections in the supported acceptance environment. Member-content/extraction,
network, and process APIs are blocked during the campaign and restored afterward.
Fault injection tests require false safety claims to fail acceptance.

- Corpus SHA-256: `a22b595655eb1b8b536cee3c4efa8544d0c4c0dafba1427a069349cb545e00e9`
- Outcomes SHA-256: `ea08648021310f6781a975e4529f64a3083e177c4e5fd0daef2210d0d60b07e1`

Source and extracted-package gates require the campaign and all 190 regressions.
Independent package verification requires the full feature and matching assurance
when present, while preserving historical release support. This finite synthetic
campaign is not coverage-guided fuzzing, exhaustive parser testing, native-code
sanitizer qualification, or independent penetration testing.

Primary library references: [Python 3.12 ZIP documentation](https://docs.python.org/3.12/library/zipfile.html)
and [Python 3.12 TAR documentation](https://docs.python.org/3.12/library/tarfile.html).
