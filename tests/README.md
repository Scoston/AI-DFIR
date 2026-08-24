# AI-DFIR Synthetic Test Corpus

All data under `tests/fixtures/` is fabricated for testing and training.

## Generate

```bash
python tests/generate_test_corpus.py
```

## Test every Evidence Pack

```bash
python tests/test_evidence_pack_matrix.py
```

The generator creates one case directory for every Evidence Pack and includes an
`ACQUISITION_MANIFEST.json` with correct SHA-256 values. This verifies evidence
matching and quality gates. Placeholder binary files in this matrix are not
intended to exercise file-format parsers.

## Run higher-fidelity scenarios

```bash
python tests/run_synthetic_scenarios.py
```

These scenarios exercise real parser/detector logic without provider network
access or real secrets.

## Existing version suites

`v15_selftest.py`, `v14_selftest.py`, `v13_selftest.py`, and earlier suites
provide deeper version-specific regression coverage including crypto and custody
workflows.
