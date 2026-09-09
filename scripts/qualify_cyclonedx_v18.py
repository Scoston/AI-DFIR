#!/usr/bin/env python3
"""Qualify AI-DFIR v1.8 CycloneDX 1.7 projection with a pinned external validator.

The harness runs a positive projection and a deliberately invalid negative control,
retains validator output, and emits a hash-bound qualification receipt. It does
not mark arbitrary future BOMs as conformant and does not imply production BOM
completeness or authenticity.
"""
from __future__ import annotations

import argparse
import json
import subprocess
from copy import deepcopy
from pathlib import Path
from typing import Any

import v18_ai_ml_bom as aibom
from v18_agent_execution_record import canonical_bytes, sha256_bytes

SCHEMA = "ai-dfir/cyclonedx-qualification/v1.8"
PINNED_VALIDATOR = "CycloneDX/sbom-utility"
PINNED_VALIDATOR_VERSION = "0.19.2"
PINNED_ARCHIVE_SHA256 = "e0cd37e6e67b1d0e44dbb7b38e055a4e2ee66db590bb8e7f89e2d9b650f4490b"
TARGET_FORMAT = "CycloneDX"
TARGET_VERSION = "1.7"


def _write_json(path: Path, value: Any) -> bytes:
    data = json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"
    path.write_bytes(data)
    return data


def _run(argv: list[str]) -> dict[str, Any]:
    cp = subprocess.run(argv, text=True, capture_output=True, check=False)
    return {"argv": argv, "exit_code": cp.returncode, "stdout": cp.stdout, "stderr": cp.stderr}


def _record_run(out_dir: Path, stem: str, result: dict[str, Any]) -> dict[str, Any]:
    stdout = result["stdout"].encode("utf-8")
    stderr = result["stderr"].encode("utf-8")
    (out_dir / f"{stem}.stdout.txt").write_bytes(stdout)
    (out_dir / f"{stem}.stderr.txt").write_bytes(stderr)
    return {
        "exit_code": result["exit_code"],
        "stdout_sha256": sha256_bytes(stdout),
        "stderr_sha256": sha256_bytes(stderr),
    }


def _synthetic_projection() -> tuple[dict[str, Any], dict[str, Any]]:
    model = aibom.component(
        "model:primary", "model", "synthetic-agent-model", version="1.8-test",
        sha256="1" * 64, source="synthetic-qualification",
        properties={"purpose": "agentic-runtime-qualification"},
    )
    embedding = aibom.component(
        "model:embedding", "embedding-model", "synthetic-embedding-model", version="1.0",
        sha256="2" * 64, source="synthetic-qualification",
    )
    mcp_server = aibom.component(
        "mcp:identity", "mcp-server", "synthetic-identity-server", version="2026-07-28",
        sha256="3" * 64, source="synthetic-qualification",
    )
    policy = aibom.component(
        "policy:tool", "policy", "synthetic-tool-policy", version="7",
        sha256="4" * 64, source="synthetic-qualification",
    )
    internal = aibom.build(
        "synthetic-v18-cyclonedx-qualification",
        observed_at="2026-09-09T18:55:00Z",
        components=[model, embedding, mcp_server, policy],
        dependencies=[
            ("model:primary", "model:embedding"),
            ("model:primary", "mcp:identity"),
            ("model:primary", "policy:tool"),
        ],
        source_versions={"ai-dfir": "1.8-development", "cyclonedx-target": TARGET_VERSION},
    )
    projection = aibom.to_cyclonedx_1_7(internal)
    return internal, projection


def qualify(*, validator: str, out_dir: Path, validator_version: str,
            validator_archive_sha256: str, network_isolated: bool = False) -> dict[str, Any]:
    if validator_version != PINNED_VALIDATOR_VERSION:
        raise ValueError("validator version does not match the pinned qualification profile")
    if validator_archive_sha256 != PINNED_ARCHIVE_SHA256:
        raise ValueError("validator archive SHA-256 does not match the pinned qualification profile")
    if not isinstance(network_isolated, bool):
        raise TypeError("network_isolated must be bool")

    out_dir.mkdir(parents=True, exist_ok=True)
    validator_path = str(Path(validator).resolve())

    schema_result = _run([validator_path, "schema", "list", "-q"])
    schema_observation = _record_run(out_dir, "schema-list", schema_result)
    if schema_result["exit_code"] != 0:
        raise RuntimeError("validator schema inventory failed")
    schema_text = schema_result["stdout"] + schema_result["stderr"]
    if TARGET_FORMAT not in schema_text or TARGET_VERSION not in schema_text:
        raise RuntimeError("validator did not expose built-in CycloneDX 1.7 support")

    internal, projection = _synthetic_projection()
    internal_bytes = _write_json(out_dir / "source-ai-ml-bom.json", internal)
    valid_bytes = _write_json(out_dir / "valid-cyclonedx-1.7.json", projection)

    invalid = deepcopy(projection)
    invalid["version"] = 0  # CycloneDX schema requires root version >= 1.
    invalid_bytes = _write_json(out_dir / "negative-control-invalid.json", invalid)

    valid_result = _run([
        validator_path, "validate", "-i", str(out_dir / "valid-cyclonedx-1.7.json"),
        "--format", "json", "-q",
    ])
    valid_observation = _record_run(out_dir, "valid", valid_result)
    if valid_result["exit_code"] != 0:
        raise RuntimeError("AI-DFIR CycloneDX 1.7 projection failed external schema validation")

    invalid_result = _run([
        validator_path, "validate", "-i", str(out_dir / "negative-control-invalid.json"),
        "--format", "json", "-q",
    ])
    invalid_observation = _record_run(out_dir, "negative-control", invalid_result)
    if invalid_result["exit_code"] != 2:
        raise RuntimeError("negative control was not rejected with the expected validation-error exit code")

    receipt = {
        "schema": SCHEMA,
        "validator": {
            "name": PINNED_VALIDATOR,
            "version": validator_version,
            "archive_sha256": validator_archive_sha256,
        },
        "target": {
            "format": TARGET_FORMAT,
            "version": TARGET_VERSION,
            "built_in_schema_observed": True,
        },
        "source_internal_bom": {
            "record_sha256": internal["record_sha256"],
            "file_sha256": sha256_bytes(internal_bytes),
        },
        "positive_control": {
            "file": "valid-cyclonedx-1.7.json",
            "sha256": sha256_bytes(valid_bytes),
            **valid_observation,
        },
        "negative_control": {
            "file": "negative-control-invalid.json",
            "mutation": "root.version=0",
            "sha256": sha256_bytes(invalid_bytes),
            **invalid_observation,
        },
        "schema_inventory": schema_observation,
        "claims": {
            "tested_projection_schema_conformant": True,
            "negative_control_rejected": True,
            "qualification_network_namespace_isolated": network_isolated,
            "production_bom_conformance_implied": False,
            "all_future_projections_conform": False,
            "inventory_complete": False,
            "component_authenticity_verified": False,
        },
    }
    receipt["receipt_sha256"] = sha256_bytes(canonical_bytes(receipt))
    _write_json(out_dir / "qualification-receipt.json", receipt)
    return receipt


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--validator", required=True)
    ap.add_argument("--validator-version", required=True)
    ap.add_argument("--validator-archive-sha256", required=True)
    ap.add_argument("--network-isolated", action="store_true")
    ap.add_argument("--out-dir", required=True, type=Path)
    args = ap.parse_args()
    receipt = qualify(
        validator=args.validator,
        out_dir=args.out_dir,
        validator_version=args.validator_version,
        validator_archive_sha256=args.validator_archive_sha256,
        network_isolated=args.network_isolated,
    )
    print(json.dumps({
        "status": "PASS",
        "target": f"{TARGET_FORMAT} {TARGET_VERSION}",
        "validator": f"{PINNED_VALIDATOR} v{PINNED_VALIDATOR_VERSION}",
        "negative_control_rejected": receipt["claims"]["negative_control_rejected"],
        "receipt_sha256": receipt["receipt_sha256"],
    }, sort_keys=True))


if __name__ == "__main__":
    main()
