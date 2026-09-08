# Bounded DOCX intake (development)

The existing DOCX font analyzer now reads one bounded immutable ZIP snapshot,
validates its metadata, and decompresses only the main document XML, optional
font table/relationships, and referenced regular embedded fonts. Its unsigned
intake receipt binds those selected bytes to the source SHA-256. CRC and size
agreement establish consistency with ZIP metadata, not authorship or truth.

```bash
python evil_font_forensics.py synthetic.docx --out /tmp/docx-report-new.json
python content_intake_gate.py synthetic.docx
python v17_docx_intake_selftest.py
python -m pytest tests/test_v17_docx_intake.py -q
```

The DOCX analyzer's output file must be new. It uses exclusive creation and mode
0600, refuses existing files and symlinks, and never overwrites source evidence.
Invalid input or unavailable output exits 1 with a redacted error; interruption
exits 130. The Python API raises on invalid intake. The content gate turns that
failure into a high-severity `docx_parse_failure` requiring REVIEW. Existing
critical font-deception findings still produce QUARANTINE. PASS means no modeled
high/critical finding; it is not proof that the document is safe.

## Selected-part profile

| Boundary | Limit or behavior |
|---|---|
| Source | Nonempty regular file, at most 16 MiB; one descriptor read and immutable bytes |
| Container | Existing ZIP32 metadata checks; at most 512 members |
| Members | Stored or deflated; no encryption, links, special files, path aliases, or conflicting entry types |
| Selected XML | At most 2 MiB per part; transitional WordprocessingML namespace |
| XML tree | 50,000 elements, depth 64, 1,048,576 text characters per part |
| XML attributes | At most 128 per element; tag/key/value length at most 4,096 characters |
| Fonts | At most 32 font-table entries; 4 MiB per selected regular font |
| Selected bytes | At most 16 MiB total; declared expansion ratio at most 1,000 |
| Output | At most 2 MiB canonical report; CLI formatted output separately capped at 2 MiB |

DTD declarations, entities, and external XML references are forbidden through
`defusedxml`. Malformed optional font XML is rejected, rather than treated as an
absent table. Namespace declarations are not ElementTree attributes; their bytes
remain subject to the XML part limit. This profile does not implement complete
OOXML or OPC schema validation.

Member names remain package data. Absolute, traversal, backslash, control,
portable alias/case/Unicode collision, and other ambiguous names are rejected.
Local/central ZIP metadata and payload ranges must agree before selected
decompression. Selected deflate streams must end exactly, without trailing or
concatenated data, and their actual length and CRC must match declared values.
No ZIP member-read or filesystem-extraction API is used.

Font relationship IDs must be unique. Only internal relationships of the font
type with a restricted literal relative target can select a part. URLs, drive
paths, percent escapes, query/fragment text, backslashes, and dot segments stay
unresolved. External, missing, or unsupported regular-font references cause a
high finding; no URL or filesystem lookup is attempted. ActiveX, embedded object,
and VBA-named parts cause a high finding without inspecting their payloads.

## Embedded-font boundary

Selected regular fonts are deobfuscated when a supported key is present, then
checked in a fixed child using the existing fontTools glyph-geometry analyzer.
Invalid keys never fall back to interpreting the obfuscated bytes as clear data.
Repeated decoded bytes share a cached result. The original selected-font hash
and decoded-font hash remain distinct.

The qualified child path is Linux, with 3 seconds CPU, 256 MiB address space,
zero file/core output limits, and a parent timeout of 5 seconds. The document
stops starting new font children after a 20-second elapsed budget; an already
running child may consume its remaining timeout. Input is piped bytes only, with
no evidence path, arbitrary command, shell, or font-supplied argument. Python
network/process APIs are blocked during geometry analysis. The trusted worker
caps its JSON response at 256 KiB before writing it; the parent validates its
size, decoded-byte hash, successful status, and findings structure.

These are resource controls and Python tripwires, not an OS sandbox, native
sanitizer build, or independent renderer. Only TrueType/OpenType SFNT signatures
are accepted by this worker; WOFF, WOFF2, collections, unsupported platforms,
missing dependencies, timeout, crash, or invalid responses remain unavailable
and produce a high `docx_font_analysis_incomplete` finding. Geometry examines
the existing printable ASCII mapping model, not every glyph or writing system.

## Evidence and qualification limits

`selected_part_size_crc_checked` is true only after all selected parts pass.
`uninspected_member_count` explicitly counts the rest. Corruption in an unselected
payload need not cause rejection; `all_member_payloads_verified` remains false.
Source authenticity and complete visible rendering remain false, and collection
completeness remains unknown. Headers, footers, other font variants, alternate
content, document layout, and independent rendering are outside this profile.
Font-name visible-text reconstruction remains a tool-specific signal.

The 133 regressions cover hostile XML encodings/entities, archive inconsistencies,
expansion and tree budgets, unresolved references, source replacement, actual
worker limits and geometry, fault-injected child failures, old findings, and
exclusive output. Source and extracted release gates require these tests and an
eight-input synthetic acceptance/rejection self-test. Independent package
verification requires the complete feature and explicit no-rendering assurance.
Historical releases without the feature retain their previous assurance contract.

The coverage-guided campaign adds selector 17 for this pure selected-part loader,
with repeated source/selected-byte/claim checks. It does not launch font children
or qualify native font parsing. A fixed 18-profile, 36-case preflight and 125
harness regressions remain separate from actual Atheris execution. See
[Coverage-guided fuzzing](COVERAGE_FUZZING_V1.7.md).

Security review focused on decompression before limits, XML entity/resource
expansion, package-to-filesystem confusion, malformed font worker responses,
source replacement, and false completeness claims. Negative regressions exercise
those boundaries. Independent human review is not implied by these checks.
Broader HTML/CSS, PDF, standalone-font intake and independent rendering remain
separate roadmap work.

## Dependency

The runtime adds `defusedxml>=0.7.1,<0.8`, under the Python Software Foundation
License. Python's [XML security guidance](https://docs.python.org/3.12/library/xml.html#xml-vulnerabilities)
recommends defusedxml for untrusted XML; see the
[upstream implementation](https://github.com/tiran/defusedxml). Keep the Python
runtime and Expat patched as well. Existing fontTools remains the geometry
dependency; optional PDF dependencies are unchanged.
