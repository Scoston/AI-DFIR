#!/usr/bin/env python3
"""Offline reconstruction of a signed case; never re-invoke recorded agents."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from case_export_v17 import verify_case
from verify_case_v17 import _runtime_report, exit_code_for_report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zip", required=True)
    parser.add_argument("--export-public-key", required=True)
    parser.add_argument("--tenant")
    parser.add_argument("--case")
    parser.add_argument("--out")
    parser.add_argument("--replay-transforms", action="store_true", help="Replay supported pure transforms from preserved bytes")
    args = parser.parse_args()
    try:
        report = verify_case(
            args.zip, args.export_public_key, expected_tenant=args.tenant,
            expected_case=args.case, require_provenance=True,
            include_reconstruction=True, replay_transforms=args.replay_transforms,
        )
    except (OSError, ValueError, TypeError, KeyError) as exc:
        report = _runtime_report(exc)
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    code = exit_code_for_report(report)
    replay = report.get("reconstruction", {}).get("deterministic_replay", {}).get("status")
    # Integrity PASS is separate from reproducing a derived result. Do not let
    # a mismatched or unsupported requested replay return a successful exit.
    return code or (1 if replay in {"FAIL", "INCOMPLETE"} else 0)


if __name__ == "__main__":
    raise SystemExit(main())
