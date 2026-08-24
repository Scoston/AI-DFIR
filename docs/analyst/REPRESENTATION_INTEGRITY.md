# Representation Integrity

For documents/web content preserve separately:

```text
source bytes
machine-readable representation
human-visible representation
```

Then preserve the parser/renderer/version/hash for each transformation.

Use this guide for EvilFont-style glyph remapping, hidden PDF layers, Unicode
smuggling, hidden Markdown/HTML source, terminal control sequences, and renderer
network effects.

A representation divergence establishes that participants may have perceived
different information. It does not by itself establish malicious intent or
incident impact; link it to ingestion and downstream actions.
