# Contained static HTML/CSS intake (development)

The HTML font analyzer now reads bounded source bytes and confines optional local
stylesheet/font reads to the caller-selected evidence folder. It records the
exact source and selected-resource hashes, preserves existing font-name deception
findings, and reports unsupported or unavailable resources for review.

```bash
python evil_font_forensics.py synthetic.html --out /tmp/html-report-new.json
python content_intake_gate.py synthetic.html
python v17_html_intake_selftest.py
python -m pytest tests/test_v17_html_intake.py -q
```

HTML CLI output is exclusive, private (0600), and bounded; existing files,
symlinks, and source overwrite are refused. Invalid intake or unavailable output
exits 1 with a redacted error. Gate parse failures and unresolved resources are
high findings requiring REVIEW; existing critical deception findings remain
QUARANTINE. PASS is not proof of safety or correct rendering.

## Filesystem boundary

The parent folder supplied by the caller is the trusted root. It is opened once
as a directory handle. Every resource component is opened relative to an already
opened directory, with no-follow flags; final files must be regular and are read
nonblocking under a byte limit. Resource symlinks, named pipes, directories used
as files, absolute paths, schemes, drives, backslashes, percent-encoded paths,
query/fragment suffixes, controls, and ambiguous trailing dots/spaces are refused.

Literal `.` and `..` segments are normalized before opening. Parent traversal is
allowed only when it stays inside the root. A stylesheet's font references use
that stylesheet's directory, so `styles/site.css` can refer to
`../fonts/demo.ttf`. CSS escapes are decoded by the parser before containment
checks. No URL, data URI, installed system font, CSS import, or JavaScript is
loaded. A base element prevents all relative resource loading and causes review.

The root's caller-supplied ancestor path is trusted; the no-symlink claim applies
to resource traversal below that opened root. Ordinary hard links are regular
files and do not establish exclusive ownership. Mount topology and concurrent
filesystem administration are outside this profile. Each selected path is cached
as one byte snapshot, but separate resources are not acquired atomically. The
receipt explicitly leaves `atomic_resource_snapshot_verified` false.

## Static parsing profile

| Boundary | Limit or behavior |
|---|---|
| HTML / general gate text | At most 256 KiB, strict UTF-8; empty text is supported |
| HTML structure | 8,192 start tags, depth 64, explicitly balanced non-void elements |
| Attributes | At most 64 per element; 4,096 characters per tag/key/value; no duplicate names |
| Span text | At most 256 Ki characters across retained spans, including descendant text |
| Stylesheets | Up to 32 inline and 32 linked sheets; 64 KiB per sheet |
| CSS | At most 32,768 observed tokens, nested token depth 64 |
| Fonts | At most 32 selected top-level font faces; 4 MiB per font |
| Local reads | At most 64 resource attempts plus the HTML source; 8 MiB selected bytes |
| Report | At most 2 MiB canonical output; CLI formatted output separately capped |

HTMLParser observes static spans and style/link elements. Optional closing tags
and malformed nesting accepted by some browsers can fail this deliberately
restricted profile. Span descendant text may appear in more than one retained
span; these are static observations, not a rendered text stream. Inline literal
font families preserve the existing encoded-family detection model.

tinycss2 parses CSS syntax, including escaped names and URLs. This analyzer
selects only top-level `@font-face` rules with a literal family and a single URL,
optionally followed by `format(...)`. Duplicate declarations, malformed syntax,
unsupported font sources/fallbacks, imports, and nested at-rules remain unparsed
or uninspected with high findings. Ordinary selector rules are outside the font
selection model. There is no cascade, selector matching, media evaluation, or
claim to enumerate every font/resource that a browser would use.

Selected font bytes use the existing fixed Linux geometry worker and per-document
20-second start budget. A running worker retains its five-second parent timeout.
Unsupported fonts/platforms, missing dependencies, crashes, or timeouts produce
`html_font_analysis_incomplete`. See the [font worker limits](DOCX_INTAKE_V1.7.md).
These controls are not an OS sandbox or native parser qualification.

The gate reuses the same HTML snapshot for font, Unicode, terminal, and markup
analyses. Other supported text inputs now also receive bounded snapshot reads;
invalid encoding/size becomes a high `text_parse_failure`. General text/PDF
processing, standalone-font boundaries, and exclusive gate/specialist CLI output
now use the separate [bounded content worker profile](CONTENT_WORKERS_V1.7.md).

## Evidence and validation

The unsigned receipt includes source SHA-256/size, selected resource paths,
roles, hashes and byte counts. It leaves external loading, resource symlink
following, source authenticity, complete visible rendering, and atomic resource
acquisition unverified; collection completeness remains unknown. Resources not
selected by this static model are not exhaustively enumerated. Source truth,
custody, execution, and independent visible text are not established.

The 88 regressions cover path and symlink escapes, escaped CSS references,
safe parent normalization, resource limits, parser rejection, missing resources,
base/import behavior, anchored-root replacement, cached snapshots, real font
geometry, unknown font results, existing critical findings, and exclusive output.
The synthetic self-test covers two accepted/six rejected HTML inputs, two
accepted/four rejected CSS inputs, and a contained three-file fixture.

Pure HTML/CSS observations are fuzz selectors 18 and 19. They never call the
filesystem loader or font worker. Empty selected payloads are deliberately
rejected by the harness although empty HTML/CSS can be valid intake. The current
campaign has 20 profiles, a pinned 40-case preflight, and 141 harness regressions.
Actual Atheris execution remains separate from engine-independent release gates.
Source/extracted and independent package checks require the complete feature;
older packages retain their previous assurance contracts.

Security review addressed package-to-filesystem confusion, symlink races,
reference decoding, unbounded resource reads, source replacement, parser limits,
and silent incomplete analysis. Negative regressions exercise those boundaries.
Independent human review and browser equivalence are not implied.

## Dependency

The runtime adds `tinycss2>=1.5.1,<2`, a low-level CSS syntax parser, under the
[BSD-3-Clause license](https://github.com/Kozea/tinycss2/blob/main/LICENSE).
It does not implement CSS property semantics or fetch resources; see its
[upstream documentation](https://github.com/Kozea/tinycss2). HTML parsing uses
Python's standard library. Existing fontTools and optional PDF licensing remain
unchanged.
