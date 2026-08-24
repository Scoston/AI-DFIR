# Standalone Lab Deployment

Use this mode for research, training, synthetic validation, and single-analyst
case review. It is **not** the enterprise production topology.

## Prerequisites

- Python 3.11+
- Node.js only if the bundled A2A RFC 8785 fallback is needed
- 8 GB RAM minimum for evidence-only workflows; model/activation analysis may
  require substantially more RAM/GPU capacity
- local disk with enough room for copied evidence

## Install

```bash
./install.sh default
source .venv/bin/activate
python tests/generate_test_corpus.py
python scripts/release_check.py --quick
```

For model/activation analysis:

```bash
./install.sh model
```

## Create a case

```bash
python case_init.py --case-id LAB-001 --root ./cases
```

## Launch read-only Workbench

```bash
python analyst_dashboard.py   --case-root ./cases   --host 127.0.0.1   --port 8877
```

Keep the Workbench bound to loopback. For remote access use an authenticated
reverse proxy/VPN/SSH tunnel rather than exposing the reference server directly.

## Validate a synthetic case

```bash
python evidence_pack_engine.py catalog
python tests/test_evidence_pack_matrix.py
```
