#!/usr/bin/env python3
"""Run the bounded synthetic hostile-input corpus against fixed offline parsers."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from v17_integrity import canonical_json_bytes
from v17_parser_corpus import DEFAULT_MUTATIONS, DEFAULT_SEED, profiles, run_campaign


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--mutations", type=int, default=DEFAULT_MUTATIONS, help="1–2048 structural mutations per profile")
    parser.add_argument("--profile", action="append", choices=[item.name for item in profiles()])
    parser.add_argument("--out", help="Optional new private report file; existing files are preserved")
    args = parser.parse_args()
    try:
        report = run_campaign(seed=args.seed, mutations=args.mutations, selected=args.profile)
        if args.out is not None:
            raw = canonical_json_bytes(report)
            descriptor = os.open(Path(args.out), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        print(json.dumps(report, sort_keys=True))
        return 0 if report["status"] == "PASS" else 1
    except KeyboardInterrupt:
        print(json.dumps({"status": "INTERRUPTED", "network_performed": False})); return 130
    except (ValueError, TypeError, OSError, RecursionError):
        print(json.dumps({"status": "FAIL", "error": "invalid corpus options or unavailable report output", "network_performed": False})); return 1


if __name__ == "__main__":
    raise SystemExit(main())
