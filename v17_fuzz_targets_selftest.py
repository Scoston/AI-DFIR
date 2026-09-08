#!/usr/bin/env python3
"""Pinned, engine-independent fuzz-oracle preflight; not a coverage campaign."""
import json

from v17_fuzz_targets import preflight

SEED_MANIFEST_SHA256 = "83b28fa6b51b74ac50c459b566739ee6feffe52508aec896f8f6ac5ea9a40456"


def check():
    report = preflight()
    if (report["profiles"] != 20 or report["cases"] != 40
            or report["seed_manifest_sha256"] != SEED_MANIFEST_SHA256):
        raise AssertionError("fixed fuzz seed manifest mismatch")
    return report


if __name__ == "__main__":
    print(json.dumps(check(), indent=2))
