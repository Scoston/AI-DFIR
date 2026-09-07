#!/usr/bin/env python3
"""Build an AI-DFIR release after full offline verification.

Release archives are staged from Git-tracked files plus explicitly generated
release metadata. Untracked working-tree files are never packaged.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_VERSION = "1.6.0"
TAG_RE = re.compile(r"^v(?P<version>[0-9]+\.[0-9]+\.[0-9]+(?:-rc[1-9][0-9]*)?)$")
VERSION_RE = re.compile(r"^(?P<major>[0-9]+)\.(?P<minor>[0-9]+)\.(?P<patch>[0-9]+)(?:-rc(?P<rc>[1-9][0-9]*))?$")
GENERATED_MANIFEST_RE = re.compile(r"^PACKAGE_MANIFEST_V[0-9]+\.[0-9]+\.json$")


def resolve_version(tag: str | None = None) -> str:
    value = (tag if tag is not None else os.environ.get("AI_DFIR_RELEASE_TAG", "")).strip()
    if not value:
        return DEFAULT_VERSION
    match = TAG_RE.fullmatch(value)
    if match is None:
        raise ValueError(f"Invalid AI_DFIR_RELEASE_TAG: {value!r}")
    return match.group("version")


def version_series(version: str) -> str:
    match = VERSION_RE.fullmatch(version)
    if match is None:
        raise ValueError(f"Invalid release version: {version!r}")
    return f"{match.group('major')}.{match.group('minor')}"


def is_release_candidate(version: str) -> bool:
    match = VERSION_RE.fullmatch(version)
    if match is None:
        raise ValueError(f"Invalid release version: {version!r}")
    return match.group("rc") is not None


def release_names(version: str) -> dict[str, str]:
    series = version_series(version)
    return {
        "name": f"AI-DFIR-v{version}",
        "manifest": f"PACKAGE_MANIFEST_V{series}.json",
        "validation": f"RELEASE_VALIDATION_V{series}.json",
        "assurance": f"RELEASE_CANDIDATE_ASSURANCE_V{series}.json",
        "release_notes_series": f"RELEASE_NOTES_V{series}.md",
    }


def utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def git_head(root: Path) -> str:
    cp = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        text=True,
        capture_output=True,
        check=False,
    )
    if cp.returncode:
        raise RuntimeError(f"unable to resolve source commit: {cp.stderr.strip()}")
    commit = cp.stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise RuntimeError(f"unexpected source commit: {commit!r}")
    return commit


def stage_tracked_tree(source: Path, staged: Path) -> None:
    """Stage the committed HEAD tree, never mutable working-tree file bytes."""
    cp = subprocess.run(
        ["git", "archive", "--format=tar", "HEAD"],
        cwd=source,
        capture_output=True,
        check=False,
    )
    if cp.returncode:
        raise RuntimeError("git archive HEAD failed; release packaging requires a Git checkout")
    staged.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(cp.stdout), mode="r:") as archive:
        for member in archive.getmembers():
            if member.isdir():
                continue
            if not member.isfile():
                raise RuntimeError(f"unsupported non-file Git archive member: {member.name}")
            rel = PurePosixPath(member.name)
            if rel.is_absolute() or any(part in {"", ".", ".."} for part in rel.parts):
                raise RuntimeError(f"unsafe Git archive path: {member.name}")
            if GENERATED_MANIFEST_RE.fullmatch(rel.name):
                continue
            source_stream = archive.extractfile(member)
            if source_stream is None:
                raise RuntimeError(f"unable to read Git archive member: {member.name}")
            target = staged.joinpath(*rel.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("wb") as output:
                shutil.copyfileobj(source_stream, output)
            os.chmod(target, member.mode & 0o777)
            os.utime(target, (member.mtime, member.mtime))


def release_notes_path(root: Path, version: str) -> Path:
    series = version_series(version)
    exact = root / f"RELEASE_NOTES_V{version}.md"
    series_path = root / f"RELEASE_NOTES_V{series}.md"
    if exact.is_file():
        return exact
    if series_path.is_file():
        return series_path
    raise FileNotFoundError(
        f"No release notes found for {version}; expected {exact.name} or {series_path.name}"
    )


def required_v17_paths() -> set[str]:
    return {
        "CHANGELOG_V1.7.md",
        "RELEASE_NOTES_V1.7.md",
        "case_export_v17.py",
        "verify_case_v17.py",
        "v17_integrity.py",
        "v17_signing.py",
        "v17_key_policy.py",
        "v17_key_policy_selftest.py",
        "tests/test_v17_key_policy.py",
        "docs/reference/CHECKPOINT_KEY_POLICY_V1.7.md",
        "v17_timestamp.py",
        "checkpoint_timestamp_v17.py",
        "v17_timestamp_selftest.py",
        "tests/test_v17_timestamps.py",
        "docs/reference/CHECKPOINT_TIMESTAMPS_V1.7.md",
        "v17_policy_distribution.py",
        "checkpoint_policy_v17.py",
        "v17_policy_distribution_selftest.py",
        "tests/test_v17_policy_distribution.py",
        "docs/reference/CHECKPOINT_POLICY_UPDATES_V1.7.md",
        "v17_policy_quorum.py",
        "v17_policy_quorum_selftest.py",
        "tests/test_v17_policy_quorum.py",
        "docs/reference/CHECKPOINT_POLICY_QUORUM_V1.7.md",
        "v17_policy_governance.py",
        "checkpoint_governance_v17.py",
        "v17_policy_governance_selftest.py",
        "tests/test_v17_policy_governance.py",
        "docs/reference/CHECKPOINT_POLICY_GOVERNANCE_V1.7.md",
        "v17_policy_delivery.py",
        "checkpoint_delivery_v17.py",
        "v17_policy_delivery_selftest.py",
        "tests/test_v17_policy_delivery.py",
        "docs/reference/CHECKPOINT_POLICY_DELIVERY_V1.7.md",
        "v17_key_trust_history.py",
        "checkpoint_history_v17.py",
        "v17_key_trust_history_selftest.py",
        "tests/test_v17_key_trust_history.py",
        "docs/reference/CHECKPOINT_KEY_TRUST_HISTORY_V1.7.md",
        "v17_delivery_identity.py",
        "v17_delivery_identity_selftest.py",
        "tests/test_v17_delivery_identity.py",
        "docs/reference/POLICY_DELIVERY_MTLS_V1.7.md",
        "v17_policy_sync.py",
        "checkpoint_sync_v17.py",
        "v17_policy_sync_selftest.py",
        "tests/test_v17_policy_sync.py",
        "docs/reference/POLICY_SYNC_SCHEDULING_V1.7.md",
        "v17_provenance.py",
        "v17_reconstruction.py",
        "replay_case_v17.py",
        "v17_provenance_selftest.py",
        "tests/test_v17_provenance_replay.py",
        "docs/reference/INVESTIGATION_REPLAY_V1.7.md",
        "v17_pack_replay.py",
        "pack_replay_v17.py",
        "v17_pack_replay_selftest.py",
        "tests/test_v17_pack_replay.py",
        "docs/reference/EVIDENCE_PACK_REPLAY_V1.7.md",
        "v17_cloudtrail.py",
        "cloudtrail_v17.py",
        "v17_cloudtrail_selftest.py",
        "tests/test_v17_cloudtrail.py",
        "docs/reference/CLOUDTRAIL_REPLAY_V1.7.md",
        "v17_gcp_audit.py",
        "gcp_audit_v17.py",
        "v17_gcp_audit_selftest.py",
        "tests/test_v17_gcp_audit.py",
        "docs/reference/GCP_AUDIT_REPLAY_V1.7.md",
        "v17_azure_activity.py",
        "azure_activity_v17.py",
        "v17_azure_activity_selftest.py",
        "tests/test_v17_azure_activity.py",
        "docs/reference/AZURE_ACTIVITY_REPLAY_V1.7.md",
        "v17_log_analytics.py",
        "log_analytics_v17.py",
        "v17_log_analytics_selftest.py",
        "tests/test_v17_log_analytics.py",
        "docs/reference/LOG_ANALYTICS_REPLAY_V1.7.md",
        "v17_log_analytics_context.py",
        "log_analytics_context_v17.py",
        "v17_log_analytics_context_selftest.py",
        "tests/test_v17_log_analytics_context.py",
        "docs/reference/LOG_ANALYTICS_CONTEXT_V1.7.md",
        "v17_log_analytics_capture.py",
        "v17_log_analytics_capture_selftest.py",
        "tests/test_v17_log_analytics_capture.py",
        "docs/reference/LOG_ANALYTICS_CAPTURE_V1.7.md",
        "v17_log_analytics_get_selftest.py",
        "tests/test_v17_log_analytics_get.py",
        "docs/reference/LOG_ANALYTICS_GET_CONTEXT_V1.7.md",
        "v17_log_analytics_get_capture_selftest.py",
        "tests/test_v17_log_analytics_get_capture.py",
        "docs/reference/LOG_ANALYTICS_GET_CAPTURE_V1.7.md",
        "v17_log_analytics_resource_selftest.py",
        "tests/test_v17_log_analytics_resource.py",
        "docs/reference/LOG_ANALYTICS_RESOURCE_V1.7.md",
        "v17_log_analytics_form_selftest.py",
        "tests/test_v17_log_analytics_form.py",
        "docs/reference/LOG_ANALYTICS_GET_FORM_V1.7.md",
        "v17_numeric_json.py",
        "v17_log_analytics_lossless.py",
        "log_analytics_lossless_v17.py",
        "v17_log_analytics_lossless_selftest.py",
        "tests/test_v17_log_analytics_lossless.py",
        "docs/reference/LOG_ANALYTICS_LOSSLESS_V1.7.md",
        "v17_gcp_logging_context.py",
        "v17_gcp_logging_capture.py",
        "gcp_logging_context_v17.py",
        "v17_gcp_logging_capture_selftest.py",
        "tests/test_v17_gcp_logging_capture.py",
        "docs/reference/GCP_LOGGING_CAPTURE_V1.7.md",
        "v17_evidence_validation.py",
        "evidence_validation_v17.py",
        "v17_evidence_validation_selftest.py",
        "tests/test_v17_evidence_validation.py",
        "docs/reference/RAW_EVIDENCE_REASSESSMENT_V1.7.md",
        "v17_merkle.py",
        "v17_private_transparency.py",
        "private_transparency_v17.py",
        "v17_private_transparency_selftest.py",
        "tests/test_v17_private_transparency.py",
        "docs/reference/PRIVATE_TRANSPARENCY_V1.7.md",
        "v17_parser_corpus.py",
        "parser_corpus_v17.py",
        "v17_parser_corpus_selftest.py",
        "tests/test_v17_parser_corpus.py",
        "docs/reference/PARSER_HOSTILE_CORPUS_V1.7.md",
        "transparency_anchor_v14.py",
        "v14_selftest.py",
        "evidence_quality.py",
        "evidence_pack_engine.py",
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


def validate_release_inputs(root: Path, version: str) -> None:
    release_notes_path(root, version)
    series = version_series(version)
    if series == "1.7":
        missing = sorted(path for path in required_v17_paths() if not (root / path).is_file())
        if missing:
            raise FileNotFoundError("v1.7 release inputs missing: " + ", ".join(missing))
        if not is_release_candidate(version):
            citation = (root / "CITATION.cff").read_text(encoding="utf-8", errors="strict")
            if not re.search(rf"^version:\s*['\"]?{re.escape(version)}['\"]?\s*$", citation, re.M):
                raise RuntimeError(
                    "stable v1.7 packaging requires CITATION.cff to match the release version; "
                    "use an -rcN version while the stable production designation remains v1.6.0"
                )


def run_check(root: Path, full: bool = True, json_out: Path | None = None) -> str:
    cmd = [
        sys.executable,
        str(root / "scripts/release_check.py"),
        "--full" if full else "--quick",
    ]
    if json_out:
        cmd += ["--json-out", str(json_out)]
    cp = subprocess.run(cmd, cwd=root, text=True, capture_output=True, timeout=900)
    if cp.returncode:
        raise RuntimeError(f"release check failed\n{cp.stdout}\n{cp.stderr}")
    return cp.stdout


def package_manifest(root: Path, version: str, source_commit: str) -> dict:
    names = release_names(version)
    rows = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if rel.name == names["manifest"]:
            continue
        rows.append(
            {
                "path": rel.as_posix(),
                "size": path.stat().st_size,
                "sha256": sha(path),
            }
        )
    return {
        "schema": f"ai-dfir/package-manifest/v{version_series(version)}",
        "package": "AI-DFIR",
        "version": version,
        "release_series": version_series(version),
        "release_candidate": is_release_candidate(version),
        "source_commit": source_commit,
        "created_utc": utc(),
        "file_count": len(rows),
        "evidence_pack_count": len(list((root / "evidence_packs").rglob("*.json"))),
        "files": rows,
        "note": "Manifest intentionally excludes itself to avoid recursive self-hashing.",
    }


def require_extracted_v17_checks(report: dict) -> None:
    if report.get("status") != "PASS" or report.get("mode") != "full":
        raise RuntimeError("extracted package full release check did not pass")
    checks = report.get("checks")
    if not isinstance(checks, dict):
        raise RuntimeError("extracted package release report has no checks object")
    required = {
        "v17_integrity_selftest": "PASS",
        "v17_offline_case_verification_selftest": "PASS",
        "v17_verification_assurance_selftest": "PASS",
        "v17_release_candidate_selftest": "PASS",
        "v17_provenance_selftest": "PASS",
        "v17_key_policy_selftest": "PASS",
        "v17_timestamp_selftest": "PASS",
        "v17_policy_distribution_selftest": "PASS",
        "v17_policy_quorum_selftest": "PASS",
        "v17_policy_governance_selftest": "PASS",
        "v17_policy_delivery_selftest": "PASS",
        "v17_key_trust_history_selftest": "PASS",
        "v17_delivery_identity_selftest": "PASS",
        "v17_policy_sync_selftest": "PASS",
        "v17_pack_replay_selftest": "PASS",
        "v17_cloudtrail_selftest": "PASS",
        "v17_gcp_audit_selftest": "PASS",
        "v17_azure_activity_selftest": "PASS",
        "v17_log_analytics_selftest": "PASS",
        "v17_log_analytics_context_selftest": "PASS",
        "v17_log_analytics_capture_selftest": "PASS",
        "v17_log_analytics_get_selftest": "PASS",
        "v17_log_analytics_get_capture_selftest": "PASS",
        "v17_log_analytics_resource_selftest": "PASS",
        "v17_log_analytics_form_selftest": "PASS",
        "v17_log_analytics_lossless_selftest": "PASS",
        "v17_gcp_logging_capture_selftest": "PASS",
        "v17_evidence_validation_selftest": "PASS",
        "v17_private_transparency_selftest": "PASS",
        "v17_parser_corpus_selftest": "PASS",
    }
    for name, expected in required.items():
        row = checks.get(name)
        if not isinstance(row, dict) or row.get("status") != expected:
            raise RuntimeError(f"extracted package check failed or missing: {name}")
    regression = checks.get("v17_integrity_regression")
    if not isinstance(regression, dict) or regression.get("status") != "PASS" or regression.get("tests") != 56:
        raise RuntimeError("extracted package must pass all 56 v1.7 regression tests")
    provenance = checks.get("v17_provenance_regression")
    if not isinstance(provenance, dict) or provenance.get("status") != "PASS" or provenance.get("tests") != 30:
        raise RuntimeError("extracted package must pass all 30 provenance/replay regression tests")
    key_policy = checks.get("v17_key_policy_regression")
    if not isinstance(key_policy, dict) or key_policy.get("status") != "PASS" or key_policy.get("tests") != 57:
        raise RuntimeError("extracted package must pass all 57 checkpoint key-policy regression tests")
    timestamps = checks.get("v17_timestamp_regression")
    if not isinstance(timestamps, dict) or timestamps.get("status") != "PASS" or timestamps.get("tests") != 68:
        raise RuntimeError("extracted package must pass all 68 checkpoint timestamp regression tests")
    policy_updates = checks.get("v17_policy_distribution_regression")
    if not isinstance(policy_updates, dict) or policy_updates.get("status") != "PASS" or policy_updates.get("tests") != 66:
        raise RuntimeError("extracted package must pass all 66 authenticated policy update regression tests")
    quorum = checks.get("v17_policy_quorum_regression")
    if not isinstance(quorum, dict) or quorum.get("status") != "PASS" or quorum.get("tests") != 67:
        raise RuntimeError("extracted package must pass all 67 policy issuer quorum regression tests")
    governance = checks.get("v17_policy_governance_regression")
    if not isinstance(governance, dict) or governance.get("status") != "PASS" or governance.get("tests") != 87:
        raise RuntimeError("extracted package must pass all 87 signed issuer governance regression tests")
    delivery = checks.get("v17_policy_delivery_regression")
    if not isinstance(delivery, dict) or delivery.get("status") != "PASS" or delivery.get("tests") != 139:
        raise RuntimeError("extracted package must pass all 139 online policy delivery regression tests")
    history = checks.get("v17_key_trust_history_regression")
    if not isinstance(history, dict) or history.get("status") != "PASS" or history.get("tests") != 85:
        raise RuntimeError("extracted package must pass all 85 historical key-trust regression tests")
    identity = checks.get("v17_delivery_identity_regression")
    if not isinstance(identity, dict) or identity.get("status") != "PASS" or identity.get("tests") != 80:
        raise RuntimeError("extracted package must pass all 80 policy delivery client-identity regression tests")
    scheduling = checks.get("v17_policy_sync_regression")
    if not isinstance(scheduling, dict) or scheduling.get("status") != "PASS" or scheduling.get("tests") != 85:
        raise RuntimeError("extracted package must pass all 85 policy synchronization scheduling regression tests")
    pack_replay = checks.get("v17_pack_replay_regression")
    if not isinstance(pack_replay, dict) or pack_replay.get("status") != "PASS" or pack_replay.get("tests") != 96:
        raise RuntimeError("extracted package must pass all 96 Evidence Pack gate-replay regression tests")
    cloudtrail = checks.get("v17_cloudtrail_regression")
    if not isinstance(cloudtrail, dict) or cloudtrail.get("status") != "PASS" or cloudtrail.get("tests") != 130:
        raise RuntimeError("extracted package must pass all 130 native CloudTrail regression tests")
    gcp_audit = checks.get("v17_gcp_audit_regression")
    if not isinstance(gcp_audit, dict) or gcp_audit.get("status") != "PASS" or gcp_audit.get("tests") != 163:
        raise RuntimeError("extracted package must pass all 163 Google Cloud Audit regression tests")
    azure_activity = checks.get("v17_azure_activity_regression")
    if not isinstance(azure_activity, dict) or azure_activity.get("status") != "PASS" or azure_activity.get("tests") != 207:
        raise RuntimeError("extracted package must pass all 207 Azure Activity Log regression tests")
    log_analytics = checks.get("v17_log_analytics_regression")
    if not isinstance(log_analytics, dict) or log_analytics.get("status") != "PASS" or log_analytics.get("tests") != 224:
        raise RuntimeError("extracted package must pass all 224 Log Analytics regression tests")
    context = checks.get("v17_log_analytics_context_regression")
    if not isinstance(context, dict) or context.get("status") != "PASS" or context.get("tests") != 171:
        raise RuntimeError("extracted package must pass all 171 Log Analytics context regression tests")
    capture = checks.get("v17_log_analytics_capture_regression")
    if not isinstance(capture, dict) or capture.get("status") != "PASS" or capture.get("tests") != 114:
        raise RuntimeError("extracted package must pass all 114 Log Analytics capture regression tests")
    get_context = checks.get("v17_log_analytics_get_regression")
    if not isinstance(get_context, dict) or get_context.get("status") != "PASS" or get_context.get("tests") != 160:
        raise RuntimeError("extracted package must pass all 160 Log Analytics GET context regression tests")
    get_capture = checks.get("v17_log_analytics_get_capture_regression")
    if not isinstance(get_capture, dict) or get_capture.get("status") != "PASS" or get_capture.get("tests") != 143:
        raise RuntimeError("extracted package must pass all 143 Log Analytics GET capture regression tests")
    resource = checks.get("v17_log_analytics_resource_regression")
    if not isinstance(resource, dict) or resource.get("status") != "PASS" or resource.get("tests") != 142:
        raise RuntimeError("extracted package must pass all 142 Log Analytics resource regression tests")
    form = checks.get("v17_log_analytics_form_regression")
    if not isinstance(form, dict) or form.get("status") != "PASS" or form.get("tests") != 123:
        raise RuntimeError("extracted package must pass all 123 Log Analytics form GET regression tests")
    lossless = checks.get("v17_log_analytics_lossless_regression")
    if not isinstance(lossless, dict) or lossless.get("status") != "PASS" or lossless.get("tests") != 171:
        raise RuntimeError("extracted package must pass all 171 lossless Log Analytics regression tests")
    logging_capture = checks.get("v17_gcp_logging_capture_regression")
    if not isinstance(logging_capture, dict) or logging_capture.get("status") != "PASS" or logging_capture.get("tests") != 228:
        raise RuntimeError("extracted package must pass all 228 Google Cloud Logging capture regression tests")
    evidence_validation = checks.get("v17_evidence_validation_regression")
    if not isinstance(evidence_validation, dict) or evidence_validation.get("status") != "PASS" or evidence_validation.get("tests") != 190:
        raise RuntimeError("extracted package must pass all 190 raw-evidence reassessment regression tests")
    private_log = checks.get("v17_private_transparency_regression")
    if not isinstance(private_log, dict) or private_log.get("status") != "PASS" or private_log.get("tests") != 160:
        raise RuntimeError("extracted package must pass all 160 private transparency regression tests")
    corpus = checks.get("v17_parser_corpus_regression")
    if not isinstance(corpus, dict) or corpus.get("status") != "PASS" or corpus.get("tests") != 76:
        raise RuntimeError("extracted package must pass all 76 hostile parser corpus regression tests")
    campaign = checks["v17_parser_corpus_selftest"]
    if campaign.get("cases") != 3318 or campaign.get("profiles") != 12:
        raise RuntimeError("extracted package must pass the pinned 3318-case, 12-profile parser campaign")


def write_archive(staged: Path, destination: Path, root_name: str, *, tar: bool) -> None:
    if tar:
        with tarfile.open(destination, "w:gz") as archive:
            for path in sorted(staged.rglob("*")):
                if path.is_file():
                    archive.add(
                        path,
                        arcname=str(Path(root_name) / path.relative_to(staged)),
                        recursive=False,
                    )
        return
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
        for path in sorted(staged.rglob("*")):
            if path.is_file():
                archive.write(path, arcname=str(Path(root_name) / path.relative_to(staged)))


def write_sha256sums(out: Path) -> None:
    rows = []
    for path in sorted(out.iterdir()):
        if path.is_file() and path.name != "SHA256SUMS":
            rows.append(f"{sha(path)}  {path.name}")
    (out / "SHA256SUMS").write_text("\n".join(rows) + "\n", encoding="utf-8")


def main() -> None:
    version = resolve_version()
    names = release_names(version)
    package_name = names["name"]

    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", default=f"/mnt/data/{package_name}-release")
    parser.add_argument("--skip-source-check", action="store_true")
    args = parser.parse_args()

    validate_release_inputs(ROOT, version)
    source_commit = git_head(ROOT)
    out = Path(args.out_dir).resolve()
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)

    source_result = out / "SOURCE_RELEASE_CHECK.json"
    if args.skip_source_check:
        source_status = "SKIPPED_ALREADY_RUN_IN_CI"
        source_result.write_text(
            json.dumps(
                {
                    "schema": "ai-dfir/release-check/v1.6",
                    "status": source_status,
                    "source_commit": source_commit,
                },
                indent=2,
                sort_keys=True,
            ),
            encoding="utf-8",
        )
    else:
        run_check(ROOT, True, source_result)
        source_status = "PASS"

    with tempfile.TemporaryDirectory(prefix=f"aidfir-v{version_series(version)}-stage-") as tmp:
        staged = Path(tmp) / package_name
        stage_tracked_tree(ROOT, staged)
        validate_release_inputs(staged, version)

        inventory = staged / "DEPENDENCY_LICENSE_INVENTORY.json"
        subprocess.run(
            [
                sys.executable,
                str(staged / "scripts/license_inventory.py"),
                "--root",
                str(staged),
                "--out",
                str(inventory),
            ],
            check=True,
            cwd=staged,
        )
        sbom = staged / "SBOM_CYCLONEDX_1.7.json"
        subprocess.run(
            [
                sys.executable,
                str(staged / "scripts/generate_sbom.py"),
                "--root",
                str(staged),
                "--out",
                str(sbom),
                "--app-version",
                version,
            ],
            check=True,
            cwd=staged,
        )

        manifest = package_manifest(staged, version, source_commit)
        manifest_path = staged / names["manifest"]
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

        zip_path = out / f"{package_name}.zip"
        tar_path = out / f"{package_name}.tar.gz"
        write_archive(staged, zip_path, package_name, tar=False)
        write_archive(staged, tar_path, package_name, tar=True)

        with tempfile.TemporaryDirectory(prefix=f"aidfir-v{version_series(version)}-extracted-") as extract_tmp:
            extract_root = Path(extract_tmp)
            with zipfile.ZipFile(zip_path) as archive:
                archive.extractall(extract_root)
            extracted = extract_root / package_name
            extract_result = out / "EXTRACTED_RELEASE_CHECK.json"
            run_check(extracted, True, extract_result)
            extracted_report = json.loads(extract_result.read_text(encoding="utf-8"))
            if version_series(version) == "1.7":
                require_extracted_v17_checks(extracted_report)

        release_notes = release_notes_path(staged, version)
        core_assets = [
            "LICENSE",
            "NOTICE",
            "SBOM_CYCLONEDX_1.7.json",
            "DEPENDENCY_LICENSE_INVENTORY.json",
            names["manifest"],
            f"CHANGELOG_V{version_series(version)}.md",
        ]
        for rel in core_assets:
            path = staged / rel
            if path.exists():
                shutil.copy2(path, out / path.name)
        shutil.copy2(release_notes, out / release_notes.name)

        series = version_series(version)
        series_assets = [
            f"V{series}_RUNBOOK.md",
            f"PRODUCTION_ASSURANCE_IMPLEMENTATION_MATRIX_V{series}.md",
            f"SOURCES_V{series}.md",
            f"GITHUB_PRODUCTION_GUIDE_V{series}.md",
        ]
        for rel in series_assets:
            path = staged / rel
            if path.exists():
                shutil.copy2(path, out / path.name)

        demo_video = staged / f"docs/demo/{package_name}-demo.mp4"
        if demo_video.exists():
            shutil.copy2(demo_video, out / demo_video.name)

        docs_zip = out / f"{package_name}-Documentation.zip"
        with zipfile.ZipFile(docs_zip, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
            for path in sorted((staged / "docs").rglob("*")):
                if path.is_file():
                    archive.write(path, arcname=str(Path(package_name) / path.relative_to(staged)))
            root_docs = [
                "README.md",
                "INSTALL.md",
                "SECURITY.md",
                "THREAT_MODEL.md",
                "DATA_HANDLING.md",
                "TESTING.md",
                "UPLOAD_CHECKLIST.md",
                f"CHANGELOG_V{series}.md",
                release_notes.name,
                *series_assets,
            ]
            for rel in dict.fromkeys(root_docs):
                path = staged / rel
                if path.exists():
                    archive.write(path, arcname=str(Path(package_name) / rel))

        tests_zip = out / f"{package_name}-Test-Corpus.zip"
        with zipfile.ZipFile(tests_zip, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
            for path in sorted((staged / "tests/fixtures").rglob("*")):
                if path.is_file():
                    archive.write(path, arcname=str(Path(package_name) / path.relative_to(staged)))

        validation = {
            "schema": f"ai-dfir/release-validation/v{series}",
            "status": "PASS",
            "version": version,
            "release_series": series,
            "release_candidate": is_release_candidate(version),
            "source_commit": source_commit,
            "validated_utc": utc(),
            "source_check": source_status,
            "extracted_zip_check": "PASS",
            "zip_sha256": sha(zip_path),
            "tar_gz_sha256": sha(tar_path),
            "package_manifest_sha256": sha(out / names["manifest"]),
            "evidence_packs": manifest["evidence_pack_count"],
            "manifest_files": manifest["file_count"],
        }
        validation_path = out / names["validation"]
        validation_path.write_text(json.dumps(validation, indent=2, sort_keys=True), encoding="utf-8")

        if series == "1.7":
            assurance = {
                "schema": "ai-dfir/release-candidate-assurance/v1.7",
                "status": "PASS",
                "version": version,
                "release_candidate": is_release_candidate(version),
                "source_commit": source_commit,
                "network_required": False,
                "committed_head_only": True,
                "package_manifest": names["manifest"],
                "package_manifest_sha256": sha(out / names["manifest"]),
                "zip_sha256": validation["zip_sha256"],
                "tar_gz_sha256": validation["tar_gz_sha256"],
                "extracted_full_gate": "PASS",
                "v17_regression_tests": 56,
                "v17_known_answer_selftest": "PASS",
                "v17_offline_verification_selftest": "PASS",
                "v17_verification_assurance_selftest": "PASS",
                "v17_provenance_selftest": "PASS",
                "v17_provenance_regression_tests": 30,
                "v17_key_policy_selftest": "PASS",
                "v17_key_policy_regression_tests": 57,
                "v17_timestamp_selftest": "PASS",
                "v17_timestamp_regression_tests": 68,
                "v17_policy_distribution_selftest": "PASS",
                "v17_policy_distribution_regression_tests": 66,
                "v17_policy_quorum_selftest": "PASS",
                "v17_policy_quorum_regression_tests": 67,
                "v17_policy_governance_selftest": "PASS",
                "v17_policy_governance_regression_tests": 87,
                "v17_policy_delivery_selftest": "PASS",
                "v17_policy_delivery_regression_tests": 139,
                "v17_key_trust_history_selftest": "PASS",
                "v17_key_trust_history_regression_tests": 85,
                "v17_delivery_identity_selftest": "PASS",
                "v17_delivery_identity_regression_tests": 80,
                "v17_policy_sync_selftest": "PASS",
                "v17_policy_sync_regression_tests": 85,
                "v17_pack_replay_selftest": "PASS",
                "v17_pack_replay_regression_tests": 96,
                "v17_cloudtrail_selftest": "PASS",
                "v17_cloudtrail_regression_tests": 130,
                "v17_gcp_audit_selftest": "PASS",
                "v17_gcp_audit_regression_tests": 163,
                "v17_azure_activity_selftest": "PASS",
                "v17_azure_activity_regression_tests": 207,
                "v17_log_analytics_selftest": "PASS",
                "v17_log_analytics_regression_tests": 224,
                "v17_log_analytics_context_selftest": "PASS",
                "v17_log_analytics_context_regression_tests": 171,
                "v17_log_analytics_capture_selftest": "PASS",
                "v17_log_analytics_capture_regression_tests": 114,
                "v17_log_analytics_get_selftest": "PASS",
                "v17_log_analytics_get_regression_tests": 160,
                "v17_log_analytics_get_capture_selftest": "PASS",
                "v17_log_analytics_get_capture_regression_tests": 143,
                "v17_log_analytics_resource_selftest": "PASS",
                "v17_log_analytics_resource_regression_tests": 142,
                "v17_log_analytics_form_selftest": "PASS",
                "v17_log_analytics_form_regression_tests": 123,
                "v17_log_analytics_lossless_selftest": "PASS",
                "v17_log_analytics_lossless_regression_tests": 171,
                "v17_gcp_logging_capture_selftest": "PASS",
                "v17_gcp_logging_capture_regression_tests": 228,
                "v17_evidence_validation_selftest": "PASS",
                "v17_evidence_validation_regression_tests": 190,
                "v17_private_transparency_selftest": "PASS",
                "v17_private_transparency_regression_tests": 160,
                "v17_parser_corpus_selftest": "PASS",
                "v17_parser_corpus_regression_tests": 76,
                "v17_parser_corpus_cases": 3318,
            }
            (out / names["assurance"]).write_text(
                json.dumps(assurance, indent=2, sort_keys=True),
                encoding="utf-8",
            )

    write_sha256sums(out)

    bundle = Path(str(out) + "-UPLOAD-BUNDLE.zip")
    bundle.unlink(missing_ok=True)
    with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
        for path in sorted(out.iterdir()):
            if path.is_file():
                archive.write(path, arcname=str(Path(out.name) / path.name))

    print(
        json.dumps(
            {
                **validation,
                "release_dir": str(out),
                "upload_bundle": str(bundle),
                "upload_bundle_sha256": sha(bundle),
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
