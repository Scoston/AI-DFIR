#!/usr/bin/env python3
"""Pinned structured synthetic corpus acceptance; not a native fuzz campaign."""
import hashlib
import json

from v17_fuzz_targets_selftest import check as preflight
from v17_integrity import canonical_json_bytes
from v17_structured_fuzz import CORPUS_SHA256

LEGACY_MANIFEST_SHA256 = "83b28fa6b51b74ac50c459b566739ee6feffe52508aec896f8f6ac5ea9a40456"


def check():
    report = preflight()
    if hashlib.sha256(canonical_json_bytes(report["rows"][:20])).hexdigest() != LEGACY_MANIFEST_SHA256:
        raise AssertionError("legacy fuzz selectors or outcomes changed")
    if report["curated_corpus_sha256"] != CORPUS_SHA256:
        raise AssertionError("curated corpus binding changed")
    return {"status": "PASS", "structured_profiles": 3, "curated_cases": report["curated_cases"],
            "legacy_profiles_unchanged": 20, "corpus_sha256": CORPUS_SHA256,
            "coverage_guided": False, "native_sanitizers": False, "network_required": False,
            "source_authenticity_verified": False, "collection_complete": None}


if __name__ == "__main__":
    print(json.dumps(check(), indent=2))
