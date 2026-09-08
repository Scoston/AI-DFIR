# Bounded representation comparison (development)

The standalone text-differential CLI and the case representation pipeline now
compare two bounded source snapshots in a fixed worker. This closes unbounded
file reads and potentially expensive `SequenceMatcher` execution at those entry
points. The existing NFKC/whitespace normalization, token/character scores, and
divergence thresholds are preserved. Supplied visible text remains an observation
whose rendering origin has not been verified.

```bash
python representation_differential.py --machine machine.txt --visible visible.txt --out /tmp/comparison-new.json
python representation_integrity_analyze.py --case /tmp/case-new --machine-text machine.txt --visible-text visible.txt
python v17_representation_compare_selftest.py
python -m pytest tests/test_v17_representation_compare.py -q
```

## Boundaries and outputs

Each source must be a regular file of at most 16 KiB, decoded as strict UTF-8.
Empty sources are valid observations. Existing descriptor-relative reads reject
final symlinks, named pipes, and excessive files; source parent directories remain
trusted. Each source is captured once and the exact retained bytes supply both
the worker and its digest receipt. The pair is not an atomic acquisition snapshot.

The worker receives a fixed, strictly validated JSON/base64 protocol of at most
48 KiB through stdin. It receives no source paths or arbitrary command/mode. Linux
limits are three CPU seconds, 256 MiB address space, no file/core output, and a
five-second parent deadline. The process group is killed on timeout/interruption.
Python network, DNS, shell, and subprocess tripwires apply while comparing. These
are resource controls and selected API guards; they do not establish OS isolation.

Worker replies are capped at 64 KiB. The parent rejects duplicate/non-finite JSON,
wrong schemas or keys, changed source hashes/sizes/character counts, invalid score
or finding shapes, and missing or promoted rendering/authenticity/completeness
claims. Worker crashes, deadlines, malformed replies, invalid text, unsupported
platforms, and resource failures produce a high
`representation_comparison_incomplete` finding with no similarity scores. Bounded
byte inputs retain both source digests even when strict UTF-8 decoding fails.

Successful reports retain the v1.2 differential fields and add a separate intake
receipt. File-source labels are bounded metadata added after worker validation;
they are not proof of renderer identity. `independent_rendering_verified` and
`source_authenticity_verified` stay false, and `collection_complete` stays null.
High similarity, including identical empty text, does not authenticate either
input or prove that all visible content was collected.

Standalone output uses exclusive 0600 creation, canonical/formatted 64 KiB caps,
flush, and fsync. Existing output files, symlinks, and evidence overwrite are
refused. A failed write to a newly created file may leave a partial new artifact.
Input/output failures exit 1; interruption exits 130. Successful comparison exits
0 even when it finds critical divergence; unavailable comparison exits 1.

The case pipeline requires both text arguments together and uses the same bounded
comparison. Its comparison artifact is privately and exclusively created. An
unavailable comparison records `representation_comparison_available: false` and
`review_required: true` in the run result, then exits 1. Other case analyses and
the intentional incident-profile attachment workflow retain their existing
behavior; this change does not qualify all case-pipeline input/output paths.

## Acceptance and scope

The 112 regressions cover real unchanged scores/findings, empty and boundary-size
sources, Unicode preservation, actual child resource limits and API tripwires,
both-source forgery, strict protocols, failed/killed children, timeout and
interruption cleanup, bounded snapshots, symlinks/FIFOs, output/source collisions,
formatted-output caps, and case-pipeline review behavior. The self-test compares
matching/divergent synthetic pairs and rejects invalid/oversized inputs.

Source and extracted release gates require that self-test and all 112 regressions.
Independent verification requires complete support when present and preserves
older package contracts. No new dependency is introduced. The pure Python
`representation_differential.analyze()` API remains available to trusted or
caller-contained code; it does not supply this process boundary by itself.

The 23-profile fuzz campaign does not claim worker-process or comparison-engine
coverage. Independent rendering and broad native qualification are still separate
roadmap items; see [Qualification requirements](ROADMAP_QUALIFICATION_V1.7.md).
