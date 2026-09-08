# Bounded content workers and file entry points (development)

The content gate, document/font CLI, and specialist Unicode, terminal, and markup
CLIs now use bounded file, worker, and report boundaries. Unavailable processing
produces a high finding requiring REVIEW. Existing critical findings still
produce QUARANTINE, including PDF structural leads when optional extraction fails.

```bash
python content_intake_gate.py synthetic.txt --out /tmp/intake-new.json
python unicode_forensics.py synthetic.txt --out /tmp/unicode-new.json
python terminal_render_forensics.py synthetic.txt --out /tmp/terminal-new.json
python markup_representation_forensics.py synthetic.md --out /tmp/markup-new.json
python evil_font_forensics.py synthetic.pdf --out /tmp/pdf-new.json
python evil_font_forensics.py synthetic.ttf --out /tmp/font-new.json
python v17_content_intake_selftest.py
python -m pytest tests/test_v17_content_intake.py -q
```

Output paths must be new: files are created exclusively with mode 0600, flushed,
and synced. Existing files, symlinks, and source overwrite are refused. Input or
output failures exit 1 with a redacted message; interruption exits 130. The gate
retains its verdict exit codes (PASS 0, REVIEW 1, QUARANTINE 2). Successful specialist
text analysis exits 0 independently of finding severity; unavailable processing
exits 1. The document/font CLI reports findings rather than using verdict exits.

## Fixed processing boundaries

| Mode | Input | CPU | Address space | Parent timeout | Worker output |
|---|---|---|---|---|---|
| Plain text | 256 KiB UTF-8 | 3 s | 256 MiB | 5 s | 2 MiB |
| Markup text | 256 KiB UTF-8 | 3 s | 256 MiB | 5 s | 2 MiB |
| Optional PDF | 8 MiB PDF bytes | 8 s | 512 MiB | 12 s | 2 MiB |
| Standalone SFNT font | 4 MiB | 3 s | 256 MiB | 5 s | 256 KiB |

The qualified process profile is Linux. Core dumps and child filesystem output
are disabled. A fixed argument list selects only `plain`, `markup`, or `pdf`;
input travels through stdin, without evidence paths or arbitrary commands. The
parent kills the process group on timeout. These limits cover processing after
the source snapshot; they are not acquisition deadlines or an OS sandbox.

Workers build bounded JSON before writing stdout. The parent checks exit status,
response size, schema/mode, exact source hash/size, successful availability,
domain findings, and explicit unknown/unverified claims. Duplicate JSON keys,
non-finite numbers, wrong domains, partial/forged metadata, malformed responses,
exceptions, crashes, and timeouts cannot become successful analysis. Python
socket/DNS/process/shell APIs are blocked while analyzing, without claiming
native-code isolation or a sanitizer build.

File reads reuse the [directory-handle boundary](HTML_INTAKE_V1.7.md): selected
sources must be regular files, and source symlinks and named pipes are refused.
The HTML gate continues to reuse its one captured HTML snapshot. General text
analyses now run in the child rather than the gate process. The low-level Python
`analyze(text)` and `analyze_font_bytes(data)` functions remain available to callers
that provide their own trusted or bounded execution context.

## PDF scope

The parent preserves bounded raw marker observations and sends the exact same
bytes to the optional worker. The worker uses an in-memory PDF stream and refuses
password-required or repaired documents. It caps pages at 64, extracted text at
256 Ki characters, font references at 4,096, and unique font references at 32.
Candidate font extraction occurs inside the PDF process envelope; selected
TrueType/OpenType font bytes are then limited to 4 MiB each and 8 MiB total for
geometry analysis. These post-extraction limits do not bound a native allocation
before it happens; the process address-space limit supplies that outer boundary.

Missing, unsupported, malformed, or unavailable embedded font data causes a high
`pdf_font_analysis_incomplete` finding. Built-in unembedded fonts can therefore
require review even when text extraction succeeds. The text/metadata extraction
result is separate from font-analysis completeness. A missing backend or failed
PDF process causes `pdf_analysis_incomplete`; a failed source read/profile causes
`pdf_parse_failure`. Neither discards an already detected raw critical marker.

Raw `3 Tr` and image-marker matches are static leads and may occur in inactive or
unrelated bytes. Their absence is not proof that a PDF lacks hidden content.
This profile does not enumerate attachments/actions, render pages, recover every
font variant, establish visible text, or certify the native parser. PDF metadata,
source authenticity, collection completeness, and rendering remain distinct.

The existing optional PyMuPDF dependency remains outside default requirements.
Its memory-stream API is documented [upstream](https://pymupdf.readthedocs.io/en/latest/document.html).
Read [the licensing guide](../../LICENSE_GUIDE.md) before opting into the PDF
extra. Local synthetic acceptance was exercised with PyMuPDF 1.28.2; ordinary CI
also exercises explicit missing-backend behavior and does not require this extra.

## Font, gate, and report semantics

Standalone fonts use the existing fixed DOCX geometry worker. Malformed fonts,
unsupported WOFF/WOFF2/collections, missing dependencies, or resource failures
produce high `font_analysis_incomplete` findings instead of an empty success.
The font CLI retains its existing `font` result shape and adds a separate intake
receipt; unavailable analysis includes the new high finding.

Unknown file extensions now require REVIEW. Canonical gate reports are capped
at 8 MiB. If aggregation exceeds the cap, a compact `intake_output_limit` report
retains an existing QUARANTINE verdict and otherwise requires REVIEW. CLI formatted
bytes are separately capped before output creation. Specialist/document reports
use a 2 MiB cap. Output failure never modifies an existing file; a failed write to
a newly created file may leave an incomplete new artifact.

All receipts are unsigned observations of exact selected bytes. They do not
authenticate evidence, prove custody or complete collection, or establish
independent rendering. A successful worker is processing availability, not proof
that every document feature was inspected or that the artifact is safe.

## Validation and security review

The 100 regressions cover protocol and claim forgery, missing fields, malformed
JSON, input/size bounds, actual child resource limits, excessive report rejection,
real text findings, actual standalone font geometry, optional real PDF extraction,
mocked PDF native-boundary failures, missing PDF dependencies, unknown formats,
source symlinks, output limits, and exclusive output across all changed CLIs.
The real self-test accepts both text modes, rejects two invalid text inputs, and
preserves a PDF structural finding through failed extraction.

Source and extracted release gates require these checks. Independent package
verification requires the complete feature when present and preserves historical
package contracts. The 20-profile coverage campaign remains unchanged; it does
not claim to fuzz these worker processes or native PDF/font libraries.

Security review focused on unchecked processing time/memory/output, source
reopening, child-result promotion, optional-parser failures, and output/source
collisions. Resource limits and negative tests address those boundaries without
claiming an independent human review, OS sandbox, broad native sanitizer campaign,
or independent renderer. Operated deployment qualification remains separate.
