#!/usr/bin/env python3
"""Independent assurance CLI for AI-DFIR v1.7 offline case verification."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from case_export_v17 import (
    DEFAULT_MAX_COMPRESSION_RATIO,
    DEFAULT_MAX_MEMBERS,
    DEFAULT_MAX_MEMBER_UNCOMPRESSED,
    DEFAULT_MAX_TOTAL_UNCOMPRESSED,
    OFFLINE_VERIFICATION_SCHEMA,
    verify_case,
)


EXIT_VERIFIED = 0
EXIT_VERIFICATION_FAILED = 1
EXIT_MALFORMED_OR_UNSUPPORTED = 2
EXIT_RUNTIME_ERROR = 3


def _pass_fail(value: Any) -> str:
    return "PASS" if value is True else "FAIL"


def _display(value: Any, default: str = "N/A") -> str:
    if value is None or value == "":
        return default
    return str(value)


def render_verification_report(report: dict[str, Any]) -> str:
    """Render a stable human-readable report without changing verification semantics."""
    findings = report.get("findings") or []
    lines = [
        "AI-DFIR v1.7 Offline Case Verification Report",
        "",
        f"Status: {_display(report.get('status'), 'UNKNOWN')}",
        f"Valid: {'YES' if report.get('valid') is True else 'NO'}",
        f"Failure class: {_display(report.get('failure_class'), 'NONE')}",
        f"Package SHA-256: {_display(report.get('zip_sha256'))}",
        f"Tenant ID: {_display(report.get('tenant_id'))}",
        f"Case ID: {_display(report.get('case_id'))}",
        f"Package safety: {_display(report.get('package_safety'), 'NOT_RUN')}",
        f"Export manifest integrity: {_display(report.get('export_manifest_integrity'), 'NOT_RUN')}",
        f"Artifact integrity: {_display(report.get('artifact_integrity'), 'NOT_RUN')}",
        f"Ledger integrity: {_display(report.get('ledger_integrity'), 'NOT_RUN')}",
        f"Checkpoint integrity: {_display(report.get('checkpoint_integrity'), 'NOT_RUN')}",
        f"Checkpoint signature: {_pass_fail(report.get('signature_valid'))}",
        f"Checkpoint signer trust: {_pass_fail(report.get('signer_trusted'))}",
        f"Signer key ID: {_display(report.get('signer_key_id'))}",
        f"Checkpoint hash: {_display(report.get('checkpoint_hash'))}",
        f"Combined checkpoint verification: {_pass_fail(report.get('combined_checkpoint_verification'))}",
        f"Network required: {'YES' if report.get('network_required') is True else 'NO'}",
        f"Findings: {len(findings)}",
    ]

    if findings:
        lines.extend(["", "Findings"])
        for index, finding in enumerate(findings, start=1):
            if not isinstance(finding, dict):
                lines.append(f"{index}. {finding}")
                continue
            kind = _display(finding.get("type"), "unknown")
            severity = _display(finding.get("severity"), "unknown")
            details = []
            for key in ("path", "error", "expected", "actual", "members", "files"):
                if key in finding:
                    details.append(f"{key}={finding[key]}")
            suffix = f" ({'; '.join(details)})" if details else ""
            lines.append(f"{index}. [{severity}] {kind}{suffix}")

    errors = report.get("verification_errors") or []
    if errors:
        lines.extend(["", "Verification errors"])
        lines.extend(f"- {error}" for error in errors)

    lines.extend(
        [
            "",
            "Trust interpretation:",
            "- A valid checkpoint signature proves cryptographic validity only.",
            "- Signer trust is evaluated separately and must also pass.",
            "- The package is anchored by the independently supplied export public key.",
        ]
    )
    return "\n".join(lines) + "\n"


def exit_code_for_report(report: dict[str, Any]) -> int:
    if report.get("valid") is True:
        return EXIT_VERIFIED
    failure_class = report.get("failure_class")
    if failure_class in {"malformed-package", "unsupported-package"}:
        return EXIT_MALFORMED_OR_UNSUPPORTED
    if failure_class == "runtime-error" or report.get("status") == "ERROR":
        return EXIT_RUNTIME_ERROR
    return EXIT_VERIFICATION_FAILED


def _runtime_report(exc: Exception) -> dict[str, Any]:
    return {
        "schema": OFFLINE_VERIFICATION_SCHEMA,
        "status": "ERROR",
        "valid": False,
        "offline": True,
        "network_required": False,
        "failure_class": "runtime-error",
        "error": f"{type(exc).__name__}: {exc}",
        "findings": [],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Independently verify an AI-DFIR v1.7 case export using an externally "
            "obtained export public key. No network access is required."
        )
    )
    parser.add_argument("--zip", required=True)
    parser.add_argument("--export-public-key", required=True)
    parser.add_argument("--tenant")
    parser.add_argument("--case")
    parser.add_argument("--format", choices=("json", "text"), default="text")
    parser.add_argument("--out")
    parser.add_argument("--max-members", type=int, default=DEFAULT_MAX_MEMBERS)
    parser.add_argument(
        "--max-total-uncompressed-gib",
        type=float,
        default=DEFAULT_MAX_TOTAL_UNCOMPRESSED / 1024**3,
    )
    parser.add_argument(
        "--max-member-uncompressed-gib",
        type=float,
        default=DEFAULT_MAX_MEMBER_UNCOMPRESSED / 1024**3,
    )
    parser.add_argument(
        "--max-compression-ratio",
        type=float,
        default=DEFAULT_MAX_COMPRESSION_RATIO,
    )
    args = parser.parse_args()

    try:
        report = verify_case(
            args.zip,
            args.export_public_key,
            expected_tenant=args.tenant,
            expected_case=args.case,
            max_members=args.max_members,
            max_total_uncompressed=int(args.max_total_uncompressed_gib * 1024**3),
            max_member_uncompressed=int(args.max_member_uncompressed_gib * 1024**3),
            max_compression_ratio=args.max_compression_ratio,
        )
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        report = _runtime_report(exc)

    if args.format == "json":
        rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    else:
        rendered = render_verification_report(report)

    if args.out:
        Path(args.out).write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")

    return exit_code_for_report(report)


if __name__ == "__main__":
    raise SystemExit(main())
