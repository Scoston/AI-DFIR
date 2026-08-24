# Installation — AI-DFIR v1.6.0

## Supported baseline

- Python 3.11+
- Linux/macOS/Windows for reference workflows
- Node.js is optional and used only as a standards-conformant fallback for A2A
  RFC 8785 JCS when the Python `rfc8785` package is unavailable.

## Default install

```bash
./install.sh default
source .venv/bin/activate
```

## Full model-integrity features

```bash
./install.sh model
```

Model analysis can require substantial memory/GPU capacity depending on the
checkpoint under investigation.

## Enterprise integrations

```bash
./install.sh enterprise
```

This adds PostgreSQL and cloud provider/KMS SDK dependencies. Credentials are
not created by the installer.

## Developer install

```bash
./install.sh dev
python tests/generate_test_corpus.py
python scripts/release_check.py --quick
```

## Optional PDF parser

PyMuPDF is intentionally separated from the default install because it is
licensed under AGPL or commercial terms. Read `LICENSE_GUIDE.md` before:

```bash
./install.sh pdf-agpl
```

AI-DFIR's raw PDF structural checks still run without PyMuPDF; independent
render/vision output can also be supplied to the representation-differential
workflow.

## Verify the checkout before installation

Before installing a downloaded release, verify the published SHA-256 from `SHA256SUMS` or the GitHub release assets. For source checkouts, review the release tag and provenance according to `docs/reference/GITHUB_RELEASE_GUIDE.md`.

## Post-install validation

```bash
python tests/generate_test_corpus.py
python tests/test_evidence_pack_matrix.py
python tests/run_synthetic_scenarios.py
python scripts/release_check.py --quick
```

For enterprise dependencies, repeat the quick gate after installing the `enterprise` profile. Do not add production credentials to the synthetic fixtures or repository.
