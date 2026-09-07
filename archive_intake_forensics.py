#!/usr/bin/env python3
"""Bounded static archive intake; member content is never extracted or executed."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from v17_archive_intake import MAX_OUTPUT_BYTES, detect_format, inspect_archive, name_risks, read_archive
from v17_integrity import canonical_json_bytes
from v17_provenance import ProvenanceError


def suspicious_name(name):
    return name_risks(name)[:4]


def _read(path, expected=None):
    raw = read_archive(path)
    selected = expected or detect_format(raw)
    if selected == "any-tar":
        selected = detect_format(raw)
        if selected == "zip": raise ProvenanceError("expected a TAR container")
    return inspect_archive(raw, input_format=selected)


def _legacy_members(report):
    # Preserve the existing symlink-or-hardlink flag, with an explicit hardlink
    # field so clients can distinguish the two. Findings share these rows.
    for row in report["members"]:
        row["is_symlink"] = row["is_symlink"] or row["is_hardlink"]
    return report["members"], report["findings"]


def analyze_zip(path):
    return _legacy_members(_read(path, "zip"))


def analyze_tar(path):
    return _legacy_members(_read(path, "any-tar"))


def analyze(path):
    report = _read(path)
    _legacy_members(report)
    result = {**report, "schema": "ai-dfir/archive-intake-analysis/v1.2", "analysis_profile": report["schema"],
            "path": str(Path(path).absolute()),
            "rule": "Bounded static metadata only; no extraction, execution, member-payload verification, or proof of archive safety."}
    if len(canonical_json_bytes(result)) > MAX_OUTPUT_BYTES:
        raise ProvenanceError("archive report exceeds output limit")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path"); parser.add_argument("--out")
    args = parser.parse_args()
    try:
        report = analyze(args.path)
        encoded = json.dumps(report, indent=2, sort_keys=True).encode("utf-8")
        if len(encoded) > MAX_OUTPUT_BYTES:
            raise ProvenanceError("formatted archive report exceeds output limit")
        if args.out:
            fd = os.open(Path(args.out), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(encoded); stream.flush(); os.fsync(stream.fileno())
        else:
            print(encoded.decode("utf-8"))
        return 0
    except KeyboardInterrupt:
        print(json.dumps({"status": "INTERRUPTED", "network_required": False})); return 130
    except (ValueError, TypeError, OSError, OverflowError, RecursionError):
        print(json.dumps({"status": "FAIL", "error": "invalid, unsupported, excessive, unavailable, or conflicting archive input/output", "network_required": False})); return 1


if __name__ == "__main__":
    raise SystemExit(main())
