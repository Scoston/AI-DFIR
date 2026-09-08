#!/usr/bin/env python3
"""Pinned, engine-independent fuzz-oracle preflight; not a coverage campaign."""
import json

from v17_fuzz_targets import preflight

SEED_MANIFEST_SHA256 = "546cfb663a44ba5cc295578f9dd35fda3abe3bdb42a986ed115528c60b0d4c77"


def check():
    report = preflight()
    if (report["profiles"] != 18 or report["cases"] != 36
            or report["seed_manifest_sha256"] != SEED_MANIFEST_SHA256):
        raise AssertionError("fixed fuzz seed manifest mismatch")
    return report


if __name__ == "__main__":
    print(json.dumps(check(), indent=2))
