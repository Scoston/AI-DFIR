# Common Benign Explanations / False-Positive Checks

- scanned PDFs often contain invisible OCR text layers;
- accessibility HTML can contain hidden text/ARIA metadata legitimately;
- Unicode bidi/variation selectors can be valid in multilingual content;
- model routing/failover may be approved operational behavior;
- key rotation is expected when change control and overlap are present;
- high-entropy DNS labels may be legitimate CDN/tracking identifiers;
- multiple MCP tools with similar names may be intentional if effective identity
  remains distinct;
- memory version changes may reflect normal maintenance;
- large numbers of custom fonts can be legitimate in designed documents.

A benign explanation should be supported by evidence, not used to dismiss a
finding without validation.
