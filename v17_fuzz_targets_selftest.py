#!/usr/bin/env python3
"""Pinned, engine-independent fuzz-oracle preflight; not a coverage campaign."""
import json

from v17_fuzz_targets import preflight

SEED_MANIFEST_SHA256 = "87e2b0c2ecec6e8ca5a56ca0b93dc49e51b6132a62d4de2fe512b4df8333932f"


def check():
    report = preflight()
    if (report["profiles"] != 17 or report["cases"] != 34
            or report["seed_manifest_sha256"] != SEED_MANIFEST_SHA256):
        raise AssertionError("fixed fuzz seed manifest mismatch")
    return report


if __name__ == "__main__":
    print(json.dumps(check(), indent=2))
