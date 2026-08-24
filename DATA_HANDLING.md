# Data Handling and Evidence Classification

AI-DFIR may process prompts, documents, identities, logs, model artifacts, and
regulated data. Treat incident evidence according to organizational policy.

Recommended minimum controls:

- collect only evidence authorized for the incident;
- default prompt/content logging to hashes where full content is unnecessary;
- classify evidence at ingest;
- encrypt evidence before durable object storage;
- use legal hold for preserved cases where required;
- redact exports using deterministic manifests;
- keep analyst annotations separate from original evidence;
- never use production incident data in public GitHub issues or test fixtures.

The synthetic test corpus supplied with AI-DFIR contains fabricated data only.
