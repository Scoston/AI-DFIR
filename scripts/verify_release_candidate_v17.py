#!/usr/bin/env python3
"""Verify packaged AI-DFIR v1.7 release-candidate assets without network access."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

V17_SERIES = "1.7"
ASSURANCE_SCHEMA = "ai-dfir/release-candidate-assurance/v1.7"
MANIFEST_SCHEMA = "ai-dfir/package-manifest/v1.7"
VALIDATION_SCHEMA = "ai-dfir/release-validation/v1.7"
VERSION_RE = re.compile(r"^1\.7\.[0-9]+(?:-rc[1-9][0-9]*)?$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

SLSA_PROVENANCE_ASSET = "multiple.intoto.jsonl"
ALLOWED_EXTERNAL_RELEASE_ASSETS = {SLSA_PROVENANCE_ASSET}

REQUIRED_PACKAGE_PATHS = {
    "CHANGELOG_V1.7.md",
    "RELEASE_NOTES_V1.7.md",
    "case_export_v17.py",
    "verify_case_v17.py",
    "v17_integrity.py",
    "v17_signing.py",
    "v17_offline_selftest.py",
    "v17_verification_assurance_selftest.py",
    "v17_release_candidate_selftest.py",
    "tests/test_v17_offline_case_verification.py",
    "tests/test_v17_verification_assurance.py",
    "tests/test_v17_release_candidate.py",
    "docs/reference/OFFLINE_VERIFICATION_V1.7.md",
    "docs/reference/RELEASE_ASSURANCE_V1.7.md",
    "scripts/verify_release_candidate_v17.py",
}

PROVENANCE_PACKAGE_PATHS = {
    "v17_provenance.py", "v17_reconstruction.py", "replay_case_v17.py",
    "v17_provenance_selftest.py", "tests/test_v17_provenance_replay.py",
    "docs/reference/INVESTIGATION_REPLAY_V1.7.md",
}

PACK_REPLAY_PACKAGE_PATHS = {
    "v17_pack_replay.py", "pack_replay_v17.py", "v17_pack_replay_selftest.py",
    "tests/test_v17_pack_replay.py", "docs/reference/EVIDENCE_PACK_REPLAY_V1.7.md",
}

CLOUDTRAIL_PACKAGE_PATHS = {
    "v17_cloudtrail.py", "cloudtrail_v17.py", "v17_cloudtrail_selftest.py",
    "tests/test_v17_cloudtrail.py", "docs/reference/CLOUDTRAIL_REPLAY_V1.7.md",
}

GCP_AUDIT_PACKAGE_PATHS = {
    "v17_gcp_audit.py", "gcp_audit_v17.py", "v17_gcp_audit_selftest.py",
    "tests/test_v17_gcp_audit.py", "docs/reference/GCP_AUDIT_REPLAY_V1.7.md",
}

AZURE_ACTIVITY_PACKAGE_PATHS = {
    "v17_azure_activity.py", "azure_activity_v17.py", "v17_azure_activity_selftest.py",
    "tests/test_v17_azure_activity.py", "docs/reference/AZURE_ACTIVITY_REPLAY_V1.7.md",
}

LOG_ANALYTICS_PACKAGE_PATHS = {
    "v17_log_analytics.py", "log_analytics_v17.py", "v17_log_analytics_selftest.py",
    "tests/test_v17_log_analytics.py", "docs/reference/LOG_ANALYTICS_REPLAY_V1.7.md",
}

LOG_ANALYTICS_CONTEXT_PACKAGE_PATHS = {
    "v17_log_analytics_context.py", "log_analytics_context_v17.py", "v17_log_analytics_context_selftest.py",
    "tests/test_v17_log_analytics_context.py", "docs/reference/LOG_ANALYTICS_CONTEXT_V1.7.md",
}

LOG_ANALYTICS_CAPTURE_PACKAGE_PATHS = {
    "v17_log_analytics_capture.py", "v17_log_analytics_capture_selftest.py",
    "tests/test_v17_log_analytics_capture.py", "docs/reference/LOG_ANALYTICS_CAPTURE_V1.7.md",
}

LOG_ANALYTICS_GET_PACKAGE_PATHS = {
    "v17_log_analytics_get_selftest.py", "tests/test_v17_log_analytics_get.py",
    "docs/reference/LOG_ANALYTICS_GET_CONTEXT_V1.7.md",
}

LOG_ANALYTICS_GET_CAPTURE_PACKAGE_PATHS = {
    "v17_log_analytics_get_capture_selftest.py", "tests/test_v17_log_analytics_get_capture.py",
    "docs/reference/LOG_ANALYTICS_GET_CAPTURE_V1.7.md",
}

LOG_ANALYTICS_RESOURCE_PACKAGE_PATHS = {
    "v17_log_analytics_resource_selftest.py", "tests/test_v17_log_analytics_resource.py",
    "docs/reference/LOG_ANALYTICS_RESOURCE_V1.7.md",
}

LOG_ANALYTICS_FORM_PACKAGE_PATHS = {
    "v17_log_analytics_form_selftest.py", "tests/test_v17_log_analytics_form.py",
    "docs/reference/LOG_ANALYTICS_GET_FORM_V1.7.md",
}

LOG_ANALYTICS_LOSSLESS_PACKAGE_PATHS = {
    "v17_numeric_json.py", "v17_log_analytics_lossless.py", "log_analytics_lossless_v17.py",
    "v17_log_analytics_lossless_selftest.py", "tests/test_v17_log_analytics_lossless.py",
    "docs/reference/LOG_ANALYTICS_LOSSLESS_V1.7.md",
}

GCP_LOGGING_CAPTURE_PACKAGE_PATHS = {
    "v17_gcp_logging_context.py", "v17_gcp_logging_capture.py", "gcp_logging_context_v17.py",
    "v17_gcp_logging_capture_selftest.py", "tests/test_v17_gcp_logging_capture.py",
    "docs/reference/GCP_LOGGING_CAPTURE_V1.7.md",
}

EVIDENCE_VALIDATION_PACKAGE_PATHS = {
    "v17_evidence_validation.py", "evidence_validation_v17.py", "v17_evidence_validation_selftest.py",
    "tests/test_v17_evidence_validation.py", "docs/reference/RAW_EVIDENCE_REASSESSMENT_V1.7.md",
}

PRIVATE_TRANSPARENCY_PACKAGE_PATHS = {
    "v17_merkle.py", "v17_private_transparency.py", "private_transparency_v17.py",
    "v17_private_transparency_selftest.py", "tests/test_v17_private_transparency.py",
    "docs/reference/PRIVATE_TRANSPARENCY_V1.7.md",
}

PARSER_CORPUS_PACKAGE_PATHS = {
    "v17_parser_corpus.py", "parser_corpus_v17.py", "v17_parser_corpus_selftest.py",
    "tests/test_v17_parser_corpus.py", "docs/reference/PARSER_HOSTILE_CORPUS_V1.7.md",
}

SCHEMA_DRIFT_PACKAGE_PATHS = {
    "v17_schema_drift.py", "schema_drift_v17.py", "v17_schema_drift_selftest.py",
    "tests/test_v17_schema_drift.py", "docs/reference/NESTED_SCHEMA_DRIFT_V1.7.md",
}

CASE_EXCHANGE_PACKAGE_PATHS = {
    "v17_case_exchange.py", "case_exchange_v17.py", "v17_case_exchange_selftest.py",
    "tests/test_v17_case_exchange.py", "scripts/case_exchange_conformance_v17.py",
    "requirements-case-validation.txt", "docs/reference/CASE_EXCHANGE_V1.7.md",
}

ARCHIVE_INTAKE_PACKAGE_PATHS = {
    "v17_archive_intake.py", "v17_archive_intake_selftest.py",
    "tests/test_v17_archive_intake.py", "docs/reference/ARCHIVE_INTAKE_V1.7.md",
}

FUZZ_TARGET_PACKAGE_PATHS = {
    "v17_fuzz_targets.py", "v17_fuzz_targets_selftest.py", "tests/test_v17_fuzz_targets.py",
    "scripts/fuzz_parsers_v17.py", "scripts/run_coverage_fuzz_v17.py",
    "requirements-fuzz.txt", "docs/reference/COVERAGE_FUZZING_V1.7.md",
}

DOCX_INTAKE_PACKAGE_PATHS = {
    "v17_docx_intake.py", "v17_docx_font.py", "v17_docx_intake_selftest.py",
    "scripts/docx_font_worker_v17.py", "tests/test_v17_docx_intake.py", "docs/reference/DOCX_INTAKE_V1.7.md",
}

HTML_INTAKE_PACKAGE_PATHS = {
    "v17_html_intake.py", "v17_html_intake_selftest.py", "tests/test_v17_html_intake.py",
    "docs/reference/HTML_INTAKE_V1.7.md",
}

CONTENT_INTAKE_PACKAGE_PATHS = {
    "v17_content_intake.py", "v17_content_intake_selftest.py", "scripts/content_worker_v17.py",
    "tests/test_v17_content_intake.py", "docs/reference/CONTENT_WORKERS_V1.7.md",
}

KEY_POLICY_PACKAGE_PATHS = {
    "v17_key_policy.py", "v17_key_policy_selftest.py", "tests/test_v17_key_policy.py",
    "docs/reference/CHECKPOINT_KEY_POLICY_V1.7.md",
}

TIMESTAMP_PACKAGE_PATHS = {
    "v17_timestamp.py", "checkpoint_timestamp_v17.py", "v17_timestamp_selftest.py",
    "tests/test_v17_timestamps.py", "docs/reference/CHECKPOINT_TIMESTAMPS_V1.7.md",
}

POLICY_DISTRIBUTION_PACKAGE_PATHS = {
    "v17_policy_distribution.py", "checkpoint_policy_v17.py",
    "v17_policy_distribution_selftest.py", "tests/test_v17_policy_distribution.py",
    "docs/reference/CHECKPOINT_POLICY_UPDATES_V1.7.md",
}

POLICY_QUORUM_PACKAGE_PATHS = {
    "v17_policy_quorum.py", "v17_policy_quorum_selftest.py",
    "tests/test_v17_policy_quorum.py", "docs/reference/CHECKPOINT_POLICY_QUORUM_V1.7.md",
}

POLICY_GOVERNANCE_PACKAGE_PATHS = {
    "v17_policy_governance.py", "checkpoint_governance_v17.py", "v17_policy_governance_selftest.py",
    "tests/test_v17_policy_governance.py", "docs/reference/CHECKPOINT_POLICY_GOVERNANCE_V1.7.md",
}

POLICY_DELIVERY_PACKAGE_PATHS = {
    "v17_policy_delivery.py", "checkpoint_delivery_v17.py", "v17_policy_delivery_selftest.py",
    "tests/test_v17_policy_delivery.py", "docs/reference/CHECKPOINT_POLICY_DELIVERY_V1.7.md",
}

KEY_TRUST_HISTORY_PACKAGE_PATHS = {
    "v17_key_trust_history.py", "checkpoint_history_v17.py", "v17_key_trust_history_selftest.py",
    "tests/test_v17_key_trust_history.py", "docs/reference/CHECKPOINT_KEY_TRUST_HISTORY_V1.7.md",
}

DELIVERY_IDENTITY_PACKAGE_PATHS = {
    "v17_delivery_identity.py", "v17_delivery_identity_selftest.py",
    "tests/test_v17_delivery_identity.py", "docs/reference/POLICY_DELIVERY_MTLS_V1.7.md",
}

POLICY_SYNC_PACKAGE_PATHS = {
    "v17_policy_sync.py", "checkpoint_sync_v17.py", "v17_policy_sync_selftest.py",
    "tests/test_v17_policy_sync.py", "docs/reference/POLICY_SYNC_SCHEDULING_V1.7.md",
}


class ReleaseCandidateError(ValueError):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_rel(path: str) -> bool:
    if not path or "\\" in path or "\x00" in path:
        return False
    pure = PurePosixPath(path)
    return not pure.is_absolute() and all(part not in {"", ".", ".."} for part in pure.parts)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseCandidateError(f"invalid JSON file: {path.name}") from exc
    if not isinstance(value, dict):
        raise ReleaseCandidateError(f"JSON file must contain an object: {path.name}")
    return value


def _validate_external_release_asset(path: Path) -> None:
    """Validate structure only; this does not cryptographically verify SLSA provenance."""
    if path.name not in ALLOWED_EXTERNAL_RELEASE_ASSETS:
        raise ReleaseCandidateError(f"unexpected external release asset: {path.name}")

    try:
        lines = [
            line
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, UnicodeDecodeError) as exc:
        raise ReleaseCandidateError(
            f"external release asset is unreadable: {path.name}"
        ) from exc

    if not lines:
        raise ReleaseCandidateError(f"external release asset is empty: {path.name}")

    for number, line in enumerate(lines, start=1):
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ReleaseCandidateError(
                f"external provenance is not valid JSONL: {path.name}:{number}"
            ) from exc

        if not isinstance(value, dict):
            raise ReleaseCandidateError(
                f"external provenance row must be an object: {path.name}:{number}"
            )


def verify_sha256sums(release_dir: Path) -> dict[str, str]:
    sums_path = release_dir / "SHA256SUMS"
    if not sums_path.is_file():
        raise ReleaseCandidateError("SHA256SUMS is missing")

    expected: dict[str, str] = {}
    for number, raw in enumerate(
        sums_path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if not raw.strip():
            continue

        match = re.fullmatch(r"([0-9a-f]{64})  ([^/\\]+)", raw)
        if match is None:
            raise ReleaseCandidateError(f"invalid SHA256SUMS row {number}")

        digest, name = match.groups()
        if name in expected:
            raise ReleaseCandidateError(
                f"duplicate SHA256SUMS entry: {name}"
            )

        asset_path = release_dir / name
        if not asset_path.is_file():
            raise ReleaseCandidateError(
                f"SHA256SUMS references missing file: {name}"
            )

        actual = sha256_file(asset_path)
        if actual != digest:
            raise ReleaseCandidateError(f"SHA256 mismatch: {name}")

        expected[name] = digest

    actual_files = {
        asset_path.name
        for asset_path in release_dir.iterdir()
        if asset_path.is_file()
        and asset_path.name != "SHA256SUMS"
    }

    checksummed_files = set(expected)
    missing = checksummed_files - actual_files
    unlisted = actual_files - checksummed_files
    unexpected = unlisted - ALLOWED_EXTERNAL_RELEASE_ASSETS

    if unexpected or missing:
        raise ReleaseCandidateError(
            "SHA256SUMS coverage mismatch; "
            f"unlisted={sorted(unexpected)}, missing={sorted(missing)}"
        )

    for name in sorted(unlisted):
        _validate_external_release_asset(release_dir / name)

    return expected


def verify_package_zip(zip_path: Path, version: str) -> dict[str, Any]:
    package_name = f"AI-DFIR-v{version}"
    manifest_member = f"{package_name}/PACKAGE_MANIFEST_V1.7.json"
    try:
        archive = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile as exc:
        raise ReleaseCandidateError("release ZIP is malformed") from exc
    with archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            raise ReleaseCandidateError("release ZIP contains duplicate members")
        if any(not _safe_rel(name) for name in names):
            raise ReleaseCandidateError("release ZIP contains an unsafe member path")
        if any(not name.startswith(package_name + "/") for name in names):
            raise ReleaseCandidateError("release ZIP contains a member outside the versioned root")
        try:
            manifest = json.loads(archive.read(manifest_member).decode("utf-8"))
        except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReleaseCandidateError("release ZIP has no valid v1.7 package manifest") from exc
        if not isinstance(manifest, dict):
            raise ReleaseCandidateError("package manifest must be an object")
        if manifest.get("schema") != MANIFEST_SCHEMA:
            raise ReleaseCandidateError("package manifest schema mismatch")
        if manifest.get("version") != version:
            raise ReleaseCandidateError("package manifest version mismatch")
        if manifest.get("release_series") != V17_SERIES:
            raise ReleaseCandidateError("package manifest release series mismatch")
        source_commit = manifest.get("source_commit")
        if not isinstance(source_commit, str) or not re.fullmatch(r"[0-9a-f]{40}", source_commit):
            raise ReleaseCandidateError("package manifest source commit is invalid")
        rows = manifest.get("files")
        if not isinstance(rows, list):
            raise ReleaseCandidateError("package manifest files must be a list")
        expected: dict[str, dict[str, Any]] = {}
        for row in rows:
            if not isinstance(row, dict):
                raise ReleaseCandidateError("package manifest file row must be an object")
            path = row.get("path")
            digest = row.get("sha256")
            size = row.get("size")
            if not isinstance(path, str) or not _safe_rel(path):
                raise ReleaseCandidateError("package manifest contains an unsafe path")
            if path in expected:
                raise ReleaseCandidateError(f"package manifest duplicates path: {path}")
            if not isinstance(digest, str) or HEX64_RE.fullmatch(digest) is None:
                raise ReleaseCandidateError(f"package manifest has invalid SHA-256: {path}")
            if not isinstance(size, int) or isinstance(size, bool) or size < 0:
                raise ReleaseCandidateError(f"package manifest has invalid size: {path}")
            expected[path] = row
        if not REQUIRED_PACKAGE_PATHS.issubset(expected):
            missing = sorted(REQUIRED_PACKAGE_PATHS - set(expected))
            raise ReleaseCandidateError("required v1.7 package paths missing: " + ", ".join(missing))
        has_provenance = bool(PROVENANCE_PACKAGE_PATHS & set(expected))
        if has_provenance and not PROVENANCE_PACKAGE_PATHS.issubset(expected):
            raise ReleaseCandidateError("incomplete provenance/replay package support")
        has_pack_replay = bool(PACK_REPLAY_PACKAGE_PATHS & set(expected))
        if has_pack_replay and not (PACK_REPLAY_PACKAGE_PATHS | PROVENANCE_PACKAGE_PATHS | {"evidence_quality.py", "evidence_pack_engine.py"}).issubset(expected):
            raise ReleaseCandidateError("incomplete Evidence Pack gate-replay package support")
        has_cloudtrail = bool(CLOUDTRAIL_PACKAGE_PATHS & set(expected))
        if has_cloudtrail and not (CLOUDTRAIL_PACKAGE_PATHS | PROVENANCE_PACKAGE_PATHS).issubset(expected):
            raise ReleaseCandidateError("incomplete native CloudTrail replay package support")
        has_gcp_audit = bool(GCP_AUDIT_PACKAGE_PATHS & set(expected))
        if has_gcp_audit and not (GCP_AUDIT_PACKAGE_PATHS | PROVENANCE_PACKAGE_PATHS).issubset(expected):
            raise ReleaseCandidateError("incomplete Google Cloud Audit replay package support")
        has_azure_activity = bool(AZURE_ACTIVITY_PACKAGE_PATHS & set(expected))
        if has_azure_activity and not (AZURE_ACTIVITY_PACKAGE_PATHS | PROVENANCE_PACKAGE_PATHS).issubset(expected):
            raise ReleaseCandidateError("incomplete Azure Activity Log replay package support")
        has_log_analytics = bool(LOG_ANALYTICS_PACKAGE_PATHS & set(expected))
        if has_log_analytics and not (LOG_ANALYTICS_PACKAGE_PATHS | PROVENANCE_PACKAGE_PATHS | {"provider_collectors_v15.py"}).issubset(expected):
            raise ReleaseCandidateError("incomplete Log Analytics replay package support")
        has_log_analytics_context = bool(LOG_ANALYTICS_CONTEXT_PACKAGE_PATHS & set(expected))
        if has_log_analytics_context and not (LOG_ANALYTICS_CONTEXT_PACKAGE_PATHS | LOG_ANALYTICS_PACKAGE_PATHS | PROVENANCE_PACKAGE_PATHS | {"provider_collectors_v15.py"}).issubset(expected):
            raise ReleaseCandidateError("incomplete Log Analytics context replay package support")
        has_log_analytics_capture = bool(LOG_ANALYTICS_CAPTURE_PACKAGE_PATHS & set(expected))
        if has_log_analytics_capture and not (LOG_ANALYTICS_CAPTURE_PACKAGE_PATHS | LOG_ANALYTICS_CONTEXT_PACKAGE_PATHS | LOG_ANALYTICS_PACKAGE_PATHS | PROVENANCE_PACKAGE_PATHS | {"provider_collectors_v15.py"}).issubset(expected):
            raise ReleaseCandidateError("incomplete Log Analytics capture package support")
        has_log_analytics_get = bool(LOG_ANALYTICS_GET_PACKAGE_PATHS & set(expected))
        if has_log_analytics_get and not (LOG_ANALYTICS_GET_PACKAGE_PATHS | LOG_ANALYTICS_CONTEXT_PACKAGE_PATHS | LOG_ANALYTICS_PACKAGE_PATHS | PROVENANCE_PACKAGE_PATHS).issubset(expected):
            raise ReleaseCandidateError("incomplete Log Analytics GET context package support")
        has_log_analytics_get_capture = bool(LOG_ANALYTICS_GET_CAPTURE_PACKAGE_PATHS & set(expected))
        if has_log_analytics_get_capture and not (LOG_ANALYTICS_GET_CAPTURE_PACKAGE_PATHS | LOG_ANALYTICS_CAPTURE_PACKAGE_PATHS | LOG_ANALYTICS_GET_PACKAGE_PATHS | LOG_ANALYTICS_CONTEXT_PACKAGE_PATHS | LOG_ANALYTICS_PACKAGE_PATHS | PROVENANCE_PACKAGE_PATHS | {"provider_collectors_v15.py"}).issubset(expected):
            raise ReleaseCandidateError("incomplete Log Analytics GET capture package support")
        has_log_analytics_resource = bool(LOG_ANALYTICS_RESOURCE_PACKAGE_PATHS & set(expected))
        if has_log_analytics_resource and not (LOG_ANALYTICS_RESOURCE_PACKAGE_PATHS | LOG_ANALYTICS_CAPTURE_PACKAGE_PATHS | LOG_ANALYTICS_GET_PACKAGE_PATHS | LOG_ANALYTICS_CONTEXT_PACKAGE_PATHS | LOG_ANALYTICS_PACKAGE_PATHS | PROVENANCE_PACKAGE_PATHS | {"provider_collectors_v15.py"}).issubset(expected):
            raise ReleaseCandidateError("incomplete Log Analytics resource package support")
        has_log_analytics_form = bool(LOG_ANALYTICS_FORM_PACKAGE_PATHS & set(expected))
        if has_log_analytics_form and not (LOG_ANALYTICS_FORM_PACKAGE_PATHS | LOG_ANALYTICS_RESOURCE_PACKAGE_PATHS | LOG_ANALYTICS_GET_CAPTURE_PACKAGE_PATHS | LOG_ANALYTICS_CAPTURE_PACKAGE_PATHS | LOG_ANALYTICS_GET_PACKAGE_PATHS | LOG_ANALYTICS_CONTEXT_PACKAGE_PATHS | LOG_ANALYTICS_PACKAGE_PATHS | PROVENANCE_PACKAGE_PATHS | {"provider_collectors_v15.py"}).issubset(expected):
            raise ReleaseCandidateError("incomplete Log Analytics form GET package support")
        has_log_analytics_lossless = bool(LOG_ANALYTICS_LOSSLESS_PACKAGE_PATHS & set(expected))
        if has_log_analytics_lossless and not (LOG_ANALYTICS_LOSSLESS_PACKAGE_PATHS | LOG_ANALYTICS_PACKAGE_PATHS | PROVENANCE_PACKAGE_PATHS).issubset(expected):
            raise ReleaseCandidateError("incomplete lossless Log Analytics package support")
        has_gcp_logging_capture = bool(GCP_LOGGING_CAPTURE_PACKAGE_PATHS & set(expected))
        if has_gcp_logging_capture and not (GCP_LOGGING_CAPTURE_PACKAGE_PATHS | GCP_AUDIT_PACKAGE_PATHS | LOG_ANALYTICS_CAPTURE_PACKAGE_PATHS | LOG_ANALYTICS_CONTEXT_PACKAGE_PATHS | LOG_ANALYTICS_PACKAGE_PATHS | PROVENANCE_PACKAGE_PATHS | {"provider_collectors_v15.py"}).issubset(expected):
            raise ReleaseCandidateError("incomplete Google Cloud Logging capture package support")
        has_evidence_validation = bool(EVIDENCE_VALIDATION_PACKAGE_PATHS & set(expected))
        if has_evidence_validation and not (EVIDENCE_VALIDATION_PACKAGE_PATHS | LOG_ANALYTICS_LOSSLESS_PACKAGE_PATHS | LOG_ANALYTICS_CONTEXT_PACKAGE_PATHS | LOG_ANALYTICS_PACKAGE_PATHS | PROVENANCE_PACKAGE_PATHS).issubset(expected):
            raise ReleaseCandidateError("incomplete raw-evidence reassessment package support")
        has_private_transparency = bool(PRIVATE_TRANSPARENCY_PACKAGE_PATHS & set(expected))
        if has_private_transparency and not (PRIVATE_TRANSPARENCY_PACKAGE_PATHS | EVIDENCE_VALIDATION_PACKAGE_PATHS | LOG_ANALYTICS_CAPTURE_PACKAGE_PATHS | DELIVERY_IDENTITY_PACKAGE_PATHS | PROVENANCE_PACKAGE_PATHS | {"transparency_anchor_v14.py", "v14_selftest.py"}).issubset(expected):
            raise ReleaseCandidateError("incomplete private transparency package support")
        has_parser_corpus = bool(PARSER_CORPUS_PACKAGE_PATHS & set(expected))
        if has_parser_corpus and not (PARSER_CORPUS_PACKAGE_PATHS | CLOUDTRAIL_PACKAGE_PATHS | GCP_AUDIT_PACKAGE_PATHS | AZURE_ACTIVITY_PACKAGE_PATHS | LOG_ANALYTICS_PACKAGE_PATHS | LOG_ANALYTICS_LOSSLESS_PACKAGE_PATHS | LOG_ANALYTICS_CONTEXT_PACKAGE_PATHS | GCP_LOGGING_CAPTURE_PACKAGE_PATHS).issubset(expected):
            raise ReleaseCandidateError("incomplete hostile parser corpus package support")
        has_schema_drift = bool(SCHEMA_DRIFT_PACKAGE_PATHS & set(expected))
        if has_schema_drift and not (SCHEMA_DRIFT_PACKAGE_PATHS | EVIDENCE_VALIDATION_PACKAGE_PATHS | LOG_ANALYTICS_CONTEXT_PACKAGE_PATHS | PROVENANCE_PACKAGE_PATHS).issubset(expected):
            raise ReleaseCandidateError("incomplete nested schema comparison package support")
        has_case_exchange = bool(CASE_EXCHANGE_PACKAGE_PATHS & set(expected))
        if has_case_exchange and not (CASE_EXCHANGE_PACKAGE_PATHS | PROVENANCE_PACKAGE_PATHS | LOG_ANALYTICS_PACKAGE_PATHS | KEY_POLICY_PACKAGE_PATHS | {"case_export_v17.py", "requirements-dev.txt"}).issubset(expected):
            raise ReleaseCandidateError("incomplete CASE exchange package support")
        has_archive_intake = bool(ARCHIVE_INTAKE_PACKAGE_PATHS & set(expected))
        if has_archive_intake and not (ARCHIVE_INTAKE_PACKAGE_PATHS | {"archive_intake_forensics.py", "content_intake_gate.py", "v17_integrity.py", "v17_provenance.py"}).issubset(expected):
            raise ReleaseCandidateError("incomplete bounded archive intake package support")
        has_fuzz_targets = bool(FUZZ_TARGET_PACKAGE_PATHS & set(expected))
        if has_fuzz_targets and not (FUZZ_TARGET_PACKAGE_PATHS | PARSER_CORPUS_PACKAGE_PATHS | ARCHIVE_INTAKE_PACKAGE_PATHS).issubset(expected):
            raise ReleaseCandidateError("incomplete coverage fuzz target package support")
        has_docx_intake = bool(DOCX_INTAKE_PACKAGE_PATHS & set(expected))
        if has_docx_intake and not (DOCX_INTAKE_PACKAGE_PATHS | ARCHIVE_INTAKE_PACKAGE_PATHS | {
                "evil_font_forensics.py", "content_intake_gate.py", "requirements.txt", "v17_integrity.py", "v17_provenance.py"}).issubset(expected):
            raise ReleaseCandidateError("incomplete bounded DOCX intake package support")
        has_html_intake = bool(HTML_INTAKE_PACKAGE_PATHS & set(expected))
        if has_html_intake and not (HTML_INTAKE_PACKAGE_PATHS | DOCX_INTAKE_PACKAGE_PATHS | FUZZ_TARGET_PACKAGE_PATHS | {
                "evil_font_forensics.py", "content_intake_gate.py", "requirements.txt", "v17_integrity.py", "v17_provenance.py"}).issubset(expected):
            raise ReleaseCandidateError("incomplete contained HTML/CSS intake package support")
        has_content_intake = bool(CONTENT_INTAKE_PACKAGE_PATHS & set(expected))
        if has_content_intake and not (CONTENT_INTAKE_PACKAGE_PATHS | HTML_INTAKE_PACKAGE_PATHS | DOCX_INTAKE_PACKAGE_PATHS | {
                "evil_font_forensics.py", "content_intake_gate.py", "unicode_forensics.py", "terminal_render_forensics.py",
                "markup_representation_forensics.py", "requirements-pdf-agpl.txt"}).issubset(expected):
            raise ReleaseCandidateError("incomplete bounded content worker package support")
        has_key_policy = bool(KEY_POLICY_PACKAGE_PATHS & set(expected))
        if has_key_policy and not KEY_POLICY_PACKAGE_PATHS.issubset(expected):
            raise ReleaseCandidateError("incomplete checkpoint key-policy package support")
        has_timestamps = bool(TIMESTAMP_PACKAGE_PATHS & set(expected))
        if has_timestamps and not TIMESTAMP_PACKAGE_PATHS.issubset(expected):
            raise ReleaseCandidateError("incomplete checkpoint timestamp package support")
        has_policy_distribution = bool(POLICY_DISTRIBUTION_PACKAGE_PATHS & set(expected))
        if has_policy_distribution and not POLICY_DISTRIBUTION_PACKAGE_PATHS.issubset(expected):
            raise ReleaseCandidateError("incomplete authenticated policy update package support")
        has_policy_quorum = bool(POLICY_QUORUM_PACKAGE_PATHS & set(expected))
        if has_policy_quorum and not (POLICY_QUORUM_PACKAGE_PATHS | POLICY_DISTRIBUTION_PACKAGE_PATHS | KEY_POLICY_PACKAGE_PATHS).issubset(expected):
            raise ReleaseCandidateError("incomplete policy issuer quorum package support")
        has_policy_governance = bool(POLICY_GOVERNANCE_PACKAGE_PATHS & set(expected))
        if has_policy_governance and not (POLICY_GOVERNANCE_PACKAGE_PATHS | POLICY_QUORUM_PACKAGE_PATHS | POLICY_DISTRIBUTION_PACKAGE_PATHS | KEY_POLICY_PACKAGE_PATHS).issubset(expected):
            raise ReleaseCandidateError("incomplete signed issuer governance package support")
        has_policy_delivery = bool(POLICY_DELIVERY_PACKAGE_PATHS & set(expected))
        if has_policy_delivery and not (POLICY_DELIVERY_PACKAGE_PATHS | POLICY_GOVERNANCE_PACKAGE_PATHS | POLICY_QUORUM_PACKAGE_PATHS | POLICY_DISTRIBUTION_PACKAGE_PATHS | KEY_POLICY_PACKAGE_PATHS).issubset(expected):
            raise ReleaseCandidateError("incomplete online policy delivery package support")
        has_key_trust_history = bool(KEY_TRUST_HISTORY_PACKAGE_PATHS & set(expected))
        if has_key_trust_history and not (KEY_TRUST_HISTORY_PACKAGE_PATHS | POLICY_GOVERNANCE_PACKAGE_PATHS | POLICY_QUORUM_PACKAGE_PATHS | POLICY_DISTRIBUTION_PACKAGE_PATHS | KEY_POLICY_PACKAGE_PATHS | TIMESTAMP_PACKAGE_PATHS).issubset(expected):
            raise ReleaseCandidateError("incomplete timestamped historical key-trust package support")
        has_delivery_identity = bool(DELIVERY_IDENTITY_PACKAGE_PATHS & set(expected))
        if has_delivery_identity and not (DELIVERY_IDENTITY_PACKAGE_PATHS | POLICY_DELIVERY_PACKAGE_PATHS | POLICY_GOVERNANCE_PACKAGE_PATHS | POLICY_QUORUM_PACKAGE_PATHS | POLICY_DISTRIBUTION_PACKAGE_PATHS | KEY_POLICY_PACKAGE_PATHS).issubset(expected):
            raise ReleaseCandidateError("incomplete policy delivery client-identity package support")
        has_policy_sync = bool(POLICY_SYNC_PACKAGE_PATHS & set(expected))
        if has_policy_sync and not (POLICY_SYNC_PACKAGE_PATHS | DELIVERY_IDENTITY_PACKAGE_PATHS | POLICY_DELIVERY_PACKAGE_PATHS | POLICY_GOVERNANCE_PACKAGE_PATHS | POLICY_QUORUM_PACKAGE_PATHS | POLICY_DISTRIBUTION_PACKAGE_PATHS | KEY_POLICY_PACKAGE_PATHS).issubset(expected):
            raise ReleaseCandidateError("incomplete policy synchronization scheduling package support")
        archive_rel = {
            name[len(package_name) + 1 :]
            for name in names
            if name != manifest_member
        }
        if archive_rel != set(expected):
            raise ReleaseCandidateError("package manifest does not exactly cover ZIP members")
        for rel, row in expected.items():
            member = f"{package_name}/{rel}"
            info = archive.getinfo(member)
            digest = hashlib.sha256()
            size = 0
            with archive.open(info, "r") as stream:
                for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):
                    digest.update(block)
                    size += len(block)
            if digest.hexdigest() != row["sha256"] or size != row["size"]:
                raise ReleaseCandidateError(f"package manifest verification failed: {rel}")
        sbom_member = f"{package_name}/SBOM_CYCLONEDX_1.7.json"
        try:
            sbom = json.loads(archive.read(sbom_member).decode("utf-8"))
        except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReleaseCandidateError("package SBOM is missing or malformed") from exc
        component = ((sbom.get("metadata") or {}).get("component") or {}) if isinstance(sbom, dict) else {}
        if component.get("name") != "AI-DFIR" or component.get("version") != version:
            raise ReleaseCandidateError("SBOM application version does not match release version")
        return {
            "source_commit": source_commit,
            "has_provenance": has_provenance,
            "has_pack_replay": has_pack_replay,
            "has_cloudtrail": has_cloudtrail,
            "has_gcp_audit": has_gcp_audit,
            "has_azure_activity": has_azure_activity,
            "has_log_analytics": has_log_analytics,
            "has_log_analytics_context": has_log_analytics_context,
            "has_log_analytics_capture": has_log_analytics_capture,
            "has_log_analytics_get": has_log_analytics_get,
            "has_log_analytics_get_capture": has_log_analytics_get_capture,
            "has_log_analytics_resource": has_log_analytics_resource,
            "has_log_analytics_form": has_log_analytics_form,
            "has_log_analytics_lossless": has_log_analytics_lossless,
            "has_gcp_logging_capture": has_gcp_logging_capture,
            "has_evidence_validation": has_evidence_validation,
            "has_private_transparency": has_private_transparency,
            "has_parser_corpus": has_parser_corpus,
            "has_schema_drift": has_schema_drift,
            "has_case_exchange": has_case_exchange,
            "has_archive_intake": has_archive_intake,
            "has_fuzz_targets": has_fuzz_targets,
            "has_docx_intake": has_docx_intake,
            "has_html_intake": has_html_intake,
            "has_content_intake": has_content_intake,
            "has_key_policy": has_key_policy,
            "has_timestamps": has_timestamps,
            "has_policy_distribution": has_policy_distribution,
            "has_policy_quorum": has_policy_quorum,
            "has_policy_governance": has_policy_governance,
            "has_policy_delivery": has_policy_delivery,
            "has_key_trust_history": has_key_trust_history,
            "has_delivery_identity": has_delivery_identity,
            "has_policy_sync": has_policy_sync,
            "manifest_files": len(expected),
            "evidence_packs": manifest.get("evidence_pack_count"),
        }


def verify_release_dir(release_dir: Path, version: str) -> dict[str, Any]:
    if VERSION_RE.fullmatch(version) is None:
        raise ReleaseCandidateError("v1.7 verifier received an invalid release version")
    if not release_dir.is_dir():
        raise ReleaseCandidateError("release directory does not exist")
    package_name = f"AI-DFIR-v{version}"
    zip_path = release_dir / f"{package_name}.zip"
    tar_path = release_dir / f"{package_name}.tar.gz"
    validation_path = release_dir / "RELEASE_VALIDATION_V1.7.json"
    assurance_path = release_dir / "RELEASE_CANDIDATE_ASSURANCE_V1.7.json"
    manifest_asset = release_dir / "PACKAGE_MANIFEST_V1.7.json"
    for path in (zip_path, tar_path, validation_path, assurance_path, manifest_asset):
        if not path.is_file():
            raise ReleaseCandidateError(f"required release asset missing: {path.name}")
    sums = verify_sha256sums(release_dir)
    external_assets = sorted(
        path.name
        for path in release_dir.iterdir()
        if path.is_file()
        and path.name in ALLOWED_EXTERNAL_RELEASE_ASSETS
        and path.name not in sums
    )
    zip_result = verify_package_zip(zip_path, version)
    validation = load_json(validation_path)
    assurance = load_json(assurance_path)
    manifest_asset_obj = load_json(manifest_asset)
    if validation.get("schema") != VALIDATION_SCHEMA or validation.get("status") != "PASS":
        raise ReleaseCandidateError("release validation report did not pass")
    if validation.get("version") != version or validation.get("release_series") != V17_SERIES:
        raise ReleaseCandidateError("release validation version mismatch")
    if validation.get("source_commit") != zip_result["source_commit"]:
        raise ReleaseCandidateError("release validation source commit mismatch")
    if validation.get("zip_sha256") != sha256_file(zip_path):
        raise ReleaseCandidateError("release validation ZIP hash mismatch")
    if validation.get("tar_gz_sha256") != sha256_file(tar_path):
        raise ReleaseCandidateError("release validation TAR hash mismatch")
    if validation.get("package_manifest_sha256") != sha256_file(manifest_asset):
        raise ReleaseCandidateError("release validation manifest hash mismatch")
    if manifest_asset_obj.get("source_commit") != zip_result["source_commit"]:
        raise ReleaseCandidateError("detached package manifest source commit mismatch")
    if assurance.get("schema") != ASSURANCE_SCHEMA or assurance.get("status") != "PASS":
        raise ReleaseCandidateError("v1.7 release-candidate assurance report did not pass")
    required_assurance = {
        "version": version,
        "source_commit": zip_result["source_commit"],
        "network_required": False,
        "committed_head_only": True,
        "extracted_full_gate": "PASS",
        "v17_regression_tests": 56,
        "v17_known_answer_selftest": "PASS",
        "v17_offline_verification_selftest": "PASS",
        "v17_verification_assurance_selftest": "PASS",
    }
    # Published v1.7.0 archives predate this optional profile. Preserve their
    # verification contract, while requiring the new gates when it is shipped.
    if zip_result.get("has_provenance"):
        required_assurance.update(v17_provenance_selftest="PASS", v17_provenance_regression_tests=30)
    if zip_result.get("has_pack_replay"):
        required_assurance.update(v17_pack_replay_selftest="PASS", v17_pack_replay_regression_tests=96)
    if zip_result.get("has_cloudtrail"):
        required_assurance.update(v17_cloudtrail_selftest="PASS", v17_cloudtrail_regression_tests=130)
    if zip_result.get("has_gcp_audit"):
        required_assurance.update(v17_gcp_audit_selftest="PASS", v17_gcp_audit_regression_tests=163)
    if zip_result.get("has_azure_activity"):
        required_assurance.update(v17_azure_activity_selftest="PASS", v17_azure_activity_regression_tests=207)
    if zip_result.get("has_log_analytics"):
        required_assurance.update(v17_log_analytics_selftest="PASS", v17_log_analytics_regression_tests=224)
    if zip_result.get("has_log_analytics_context"):
        required_assurance.update(v17_log_analytics_context_selftest="PASS", v17_log_analytics_context_regression_tests=171)
    if zip_result.get("has_log_analytics_capture"):
        required_assurance.update(v17_log_analytics_capture_selftest="PASS", v17_log_analytics_capture_regression_tests=114)
    if zip_result.get("has_log_analytics_get"):
        required_assurance.update(v17_log_analytics_get_selftest="PASS", v17_log_analytics_get_regression_tests=160)
    if zip_result.get("has_log_analytics_get_capture"):
        required_assurance.update(v17_log_analytics_get_capture_selftest="PASS", v17_log_analytics_get_capture_regression_tests=143)
    if zip_result.get("has_log_analytics_resource"):
        required_assurance.update(v17_log_analytics_resource_selftest="PASS", v17_log_analytics_resource_regression_tests=142)
    if zip_result.get("has_log_analytics_form"):
        required_assurance.update(v17_log_analytics_form_selftest="PASS", v17_log_analytics_form_regression_tests=123)
    if zip_result.get("has_log_analytics_lossless"):
        required_assurance.update(v17_log_analytics_lossless_selftest="PASS", v17_log_analytics_lossless_regression_tests=171)
    if zip_result.get("has_gcp_logging_capture"):
        required_assurance.update(v17_gcp_logging_capture_selftest="PASS", v17_gcp_logging_capture_regression_tests=228)
    if zip_result.get("has_evidence_validation"):
        required_assurance.update(v17_evidence_validation_selftest="PASS", v17_evidence_validation_regression_tests=190)
    if zip_result.get("has_private_transparency"):
        required_assurance.update(v17_private_transparency_selftest="PASS", v17_private_transparency_regression_tests=160)
    if zip_result.get("has_parser_corpus"):
        required_assurance.update(v17_parser_corpus_selftest="PASS", v17_parser_corpus_regression_tests=76, v17_parser_corpus_cases=3318)
    if zip_result.get("has_schema_drift"):
        required_assurance.update(v17_schema_drift_selftest="PASS", v17_schema_drift_regression_tests=182)
    if zip_result.get("has_case_exchange"):
        required_assurance.update(v17_case_exchange_selftest="PASS", v17_case_exchange_regression_tests=101,
                                  v17_case_exchange_conformance="PASS", v17_case_exchange_ontology="1.5.0")
    if zip_result.get("has_archive_intake"):
        required_assurance.update(v17_archive_intake_selftest="PASS", v17_archive_intake_regression_tests=190,
                                  v17_archive_intake_cases=680)
    if zip_result.get("has_fuzz_targets"):
        # Preserve earlier seventeen/eighteen-profile package assurance contracts.
        required_assurance.update(v17_fuzz_targets_selftest="PASS",
                                  v17_fuzz_targets_regression_tests=141 if zip_result.get("has_html_intake") else (125 if zip_result.get("has_docx_intake") else 115),
                                  v17_fuzz_target_profiles=20 if zip_result.get("has_html_intake") else (18 if zip_result.get("has_docx_intake") else 17),
                                  v17_fuzz_preflight_coverage_guided=False)
    if zip_result.get("has_docx_intake"):
        required_assurance.update(v17_docx_intake_selftest="PASS", v17_docx_intake_regression_tests=133,
                                  v17_docx_independent_rendering_verified=False)
    if zip_result.get("has_html_intake"):
        required_assurance.update(v17_html_intake_selftest="PASS", v17_html_intake_regression_tests=88,
                                  v17_html_independent_rendering_verified=False)
    if zip_result.get("has_content_intake"):
        required_assurance.update(v17_content_intake_selftest="PASS", v17_content_intake_regression_tests=100,
                                  v17_content_independent_rendering_verified=False)
    if zip_result.get("has_key_policy"):
        required_assurance.update(v17_key_policy_selftest="PASS", v17_key_policy_regression_tests=57)
    if zip_result.get("has_timestamps"):
        required_assurance.update(v17_timestamp_selftest="PASS", v17_timestamp_regression_tests=68)
    if zip_result.get("has_policy_distribution"):
        required_assurance.update(v17_policy_distribution_selftest="PASS", v17_policy_distribution_regression_tests=66)
    if zip_result.get("has_policy_quorum"):
        required_assurance.update(v17_policy_quorum_selftest="PASS", v17_policy_quorum_regression_tests=67)
    if zip_result.get("has_policy_governance"):
        required_assurance.update(v17_policy_governance_selftest="PASS", v17_policy_governance_regression_tests=87)
    if zip_result.get("has_policy_delivery"):
        required_assurance.update(v17_policy_delivery_selftest="PASS", v17_policy_delivery_regression_tests=139)
    if zip_result.get("has_key_trust_history"):
        required_assurance.update(v17_key_trust_history_selftest="PASS", v17_key_trust_history_regression_tests=85)
    if zip_result.get("has_delivery_identity"):
        required_assurance.update(v17_delivery_identity_selftest="PASS", v17_delivery_identity_regression_tests=80)
    if zip_result.get("has_policy_sync"):
        required_assurance.update(v17_policy_sync_selftest="PASS", v17_policy_sync_regression_tests=85)
    for key, expected in required_assurance.items():
        if assurance.get(key) != expected:
            raise ReleaseCandidateError(f"release assurance mismatch: {key}")
    if assurance.get("zip_sha256") != validation.get("zip_sha256"):
        raise ReleaseCandidateError("release assurance ZIP hash mismatch")
    if assurance.get("tar_gz_sha256") != validation.get("tar_gz_sha256"):
        raise ReleaseCandidateError("release assurance TAR hash mismatch")
    if assurance.get("package_manifest_sha256") != validation.get("package_manifest_sha256"):
        raise ReleaseCandidateError("release assurance manifest hash mismatch")
    return {
        "schema": "ai-dfir/release-candidate-verification/v1.7",
        "status": "PASS",
        "version": version,
        "source_commit": zip_result["source_commit"],
        "network_required": False,
        "sha256sum_assets": len(sums),
        "external_release_assets": external_assets,
        "slsa_provenance_present": SLSA_PROVENANCE_ASSET in external_assets,
        "slsa_provenance_cryptographically_verified": False,
        "manifest_files": zip_result["manifest_files"],
        "evidence_packs": zip_result["evidence_packs"],
        "zip_sha256": validation["zip_sha256"],
        "tar_gz_sha256": validation["tar_gz_sha256"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-dir", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--out")
    args = parser.parse_args()
    try:
        result = verify_release_dir(Path(args.release_dir).resolve(), args.version)
    except (OSError, ReleaseCandidateError) as exc:
        print(json.dumps({"schema": "ai-dfir/release-candidate-verification/v1.7", "status": "FAIL", "error": str(exc)}, indent=2, sort_keys=True))
        return 1
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
