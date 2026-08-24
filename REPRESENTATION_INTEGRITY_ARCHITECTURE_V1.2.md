# AI-DFIR v1.2 — Representation Integrity Architecture

## New trust boundary

v1.2 adds a representation layer before content reaches model, agent, or human
decision paths.

```text
             UNTRUSTED CONTENT
                    |
                    v
          DETERMINISTIC INTAKE
                    |
       +------------+-------------+
       |                          |
       v                          v
 MACHINE REPRESENTATION     HUMAN-VISIBLE REPRESENTATION
 parser / extracted text    renderer / independent vision
       |                          |
       +------------+-------------+
                    |
                    v
          REPRESENTATION DIFF
                    |
        +-----------+-----------+
        |                       |
        v                       v
     parity                 divergence
        |                       |
        v                       v
 normal evidence          quarantine / review
                                |
              +-----------------+-----------------+
              |                 |                 |
              v                 v                 v
          font/glyph          Unicode          markup
          remapping           smuggling        hidden source
              |                 |                 |
              +-----------------+-----------------+
                                |
              +-----------------+-----------------+
              |                 |                 |
              v                 v                 v
          terminal           approval          session
          controls           TOCTOU            tamper
              |                 |                 |
              +-----------------+-----------------+
                                |
                                v
                         AI EXECUTION STACK
                                |
               Harness / RAG / Memory / Cache
                                |
                                v
                          Model / Agent
                                |
                                v
                        MCP / A2A / Browser
                                |
                                v
                           Consequence
```

## Evidence trust path

```text
COLLECTOR KEY
     |
     v
SIGNED ACQUISITION MANIFEST
     |
     v
SIGNATURE + ARTIFACT HASH VERIFICATION
     |
     v
ACQUISITION_TRUST.json
     |
     v
Evidence Quality Engine
```

An `authoritative: true` source flag is not enough by itself.

## Content-intake rule

The default content intake path is deterministic and non-agentic.

It must not:

- execute macros,
- execute scripts,
- load remote fonts,
- follow remote links,
- render terminal control sequences,
- call tools described in the document,
- send raw quarantined content to the privileged investigation agent.

Optional semantic analysis occurs in a separate trust domain and returns a
hash-bound verdict only.

## Representation evidence

For high-risk content, preserve:

```text
source bytes
source hash
parser/version
machine-readable representation + hash
renderer/vision version
human-visible representation + hash
representation differential
```

This supports the forensic proposition:

> The AI and human participants did or did not perceive materially equivalent
> information.

## Evil Font / glyph deception

The generic detector does not depend on tool names.

It measures:

```text
Unicode cmap
glyph-outline signatures
blank-glyph ratio
identical-outline clusters
layout-table state
embedded fonts
per-character font assignment
visible-machine divergence
```

Tool-specific family-name patterns remain supporting evidence only.

## Coding-agent representation boundary

v1.2 treats these as potentially instruction-bearing content:

```text
file contents
directory/file names
Markdown source
HTML comments
Unicode metadata
MCP tool descriptions
LSP/IDE settings
prompt templates
skills/tools
hooks
session histories
terminal output
archive member names
```

Anything a model/harness consumes can become an instruction channel even if a
human does not normally perceive it as one.
