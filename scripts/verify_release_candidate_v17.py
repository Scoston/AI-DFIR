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
