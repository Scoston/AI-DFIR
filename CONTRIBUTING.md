# Contributing to AI-DFIR

AI-DFIR accepts defensive security, forensic, testing, documentation, and
interoperability contributions.

## Before you start

- Read `SECURITY.md`, `THREAT_MODEL.md`, and `docs/analyst/HUMAN_IN_THE_LOOP.md`.
- Do not contribute operational exploit automation, safeguard-removal code, or
  code that turns the platform into an arbitrary remote-execution framework.
- Do not commit real customer evidence, credentials, API keys, bearer tokens,
  private keys, proprietary prompts, or provider exports.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
python tests/generate_test_corpus.py
python scripts/release_check.py --quick
```

On Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
python tests\generate_test_corpus.py
python scriptselease_check.py --quick
```

## Pull requests

A pull request should include:

1. the forensic proposition being added or changed;
2. evidence required to support it;
3. failure/unknown behavior when evidence is unavailable;
4. tests, including at least one negative path;
5. analyst-facing documentation when interpretation changes;
6. licensing notes for every new dependency.

Changes to evidence integrity, identity, authorization, containment, or closure
logic should receive two-person review when possible.

## Commit hygiene

Use focused commits. Do not commit generated secrets or production telemetry.
Run `python scripts/secret_scan.py .` before submitting.
