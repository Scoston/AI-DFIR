#!/usr/bin/env python3
"""Pinned, engine-independent fuzz-oracle preflight; not a coverage campaign."""
import json

from v17_fuzz_targets import preflight

SEED_MANIFEST_SHA256 = "b16370fd14330fe5f87d5a8fb301bb09e6cf778133f460daaa07b0df0eda25b8"


def check():
    report = preflight()
    if (report["profiles"] != 23 or report["cases"] != 54 or report["curated_cases"] != 8
            or report["seed_manifest_sha256"] != SEED_MANIFEST_SHA256):
        raise AssertionError("fixed fuzz seed manifest mismatch")
    return report


if __name__ == "__main__":
    print(json.dumps(check(), indent=2))
