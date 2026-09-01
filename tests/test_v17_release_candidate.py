from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.package_release import (
    is_release_candidate,
    package_manifest,
    release_names,
    release_notes_path,
    resolve_version,
    stage_tracked_tree,
    version_series,
)
from scripts.verify_release_candidate_v17 import (
    ReleaseCandidateError,
    verify_release_dir,
    verify_sha256sums,
)


def test_resolve_version_accepts_stable_tag():
    assert resolve_version("v1.7.0") == "1.7.0"


def test_resolve_version_accepts_release_candidate_tag():
    assert resolve_version("v1.7.0-rc1") == "1.7.0-rc1"
    assert is_release_candidate("1.7.0-rc1") is True


@pytest.mark.parametrize("tag", ["1.7.0", "v1.7.0-beta1"])
def test_resolve_version_rejects_invalid_release_tag(tag: str):
    with pytest.raises(ValueError):
        resolve_version(tag)


def test_release_series_and_names_are_versioned():
    assert version_series("1.7.0-rc2") == "1.7"
    names = release_names("1.7.0-rc2")
    assert names["name"] == "AI-DFIR-v1.7.0-rc2"
    assert names["manifest"] == "PACKAGE_MANIFEST_V1.7.json"
    assert names["validation"] == "RELEASE_VALIDATION_V1.7.json"
    assert names["assurance"] == "RELEASE_CANDIDATE_ASSURANCE_V1.7.json"


def test_release_notes_prefers_exact_version(tmp_path: Path):
    series = tmp_path / "RELEASE_NOTES_V1.7.md"
    exact = tmp_path / "RELEASE_NOTES_V1.7.0-rc1.md"
    series.write_text("series\n", encoding="utf-8")
    exact.write_text("exact\n", encoding="utf-8")
    assert release_notes_path(tmp_path, "1.7.0-rc1") == exact


def test_release_notes_uses_series_fallback(tmp_path: Path):
    series = tmp_path / "RELEASE_NOTES_V1.7.md"
    series.write_text("series\n", encoding="utf-8")
    assert release_notes_path(tmp_path, "1.7.0-rc1") == series


def test_release_notes_missing_fails_closed(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        release_notes_path(tmp_path, "1.7.0-rc1")


def test_stage_tracked_tree_excludes_untracked_files(tmp_path: Path):
    import subprocess

    source = tmp_path / "source"
    staged = tmp_path / "staged"
    source.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=source, check=True)
    (source / "tracked.txt").write_text("committed\n", encoding="utf-8")
    (source / "untracked.patch").write_text("must not ship\n", encoding="utf-8")
    subprocess.run(["git", "add", "tracked.txt"], cwd=source, check=True)
    subprocess.run(
        ["git", "-c", "user.email=test@example.com", "-c", "user.name=test", "commit", "-qm", "fixture"],
        cwd=source,
        check=True,
    )
    (source / "tracked.txt").write_text("modified working tree\n", encoding="utf-8")

    stage_tracked_tree(source, staged)

    assert (staged / "tracked.txt").read_text(encoding="utf-8") == "committed\n"
    assert not (staged / "untracked.patch").exists()


def test_package_manifest_uses_v17_schema_and_source_commit(tmp_path: Path):
    (tmp_path / "evidence_packs").mkdir()
    (tmp_path / "a.txt").write_text("a\n", encoding="utf-8")
    manifest = package_manifest(tmp_path, "1.7.0-rc1", "f" * 40)
    assert manifest["schema"] == "ai-dfir/package-manifest/v1.7"
    assert manifest["version"] == "1.7.0-rc1"
    assert manifest["release_candidate"] is True
    assert manifest["source_commit"] == "f" * 40
    assert [row["path"] for row in manifest["files"]] == ["a.txt"]


def test_sha256sums_detects_modified_asset(tmp_path: Path):
    asset = tmp_path / "asset.bin"
    asset.write_bytes(b"one")

    import hashlib

    digest = hashlib.sha256(asset.read_bytes()).hexdigest()
    (tmp_path / "SHA256SUMS").write_text(
        f"{digest}  asset.bin\n",
        encoding="utf-8",
    )

    provenance = tmp_path / "multiple.intoto.jsonl"
    provenance.write_text(
        '{"test": "synthetic-provenance"}\n',
        encoding="utf-8",
    )

    # Known post-packaging SLSA sidecar is permitted.
    verify_sha256sums(tmp_path)

    # Arbitrary unlisted assets remain fail-closed.
    unexpected = tmp_path / "unexpected.bin"
    unexpected.write_bytes(b"unexpected")
    with pytest.raises(
        ReleaseCandidateError,
        match="coverage mismatch",
    ):
        verify_sha256sums(tmp_path)
    unexpected.unlink()

    # Known provenance sidecar must be valid non-empty JSONL.
    provenance.write_text("not-json\n", encoding="utf-8")
    with pytest.raises(
        ReleaseCandidateError,
        match="valid JSONL",
    ):
        verify_sha256sums(tmp_path)

    provenance.write_text(
        '{"test": "synthetic-provenance"}\n',
        encoding="utf-8",
    )

    # Checksummed assets still fail if any byte changes.
    asset.write_bytes(b"two")
    with pytest.raises(
        ReleaseCandidateError,
        match="SHA256 mismatch",
    ):
        verify_sha256sums(tmp_path)


def test_v17_release_verifier_rejects_non_v17_version(tmp_path: Path):
    with pytest.raises(ReleaseCandidateError, match="invalid release version"):
        verify_release_dir(tmp_path, "1.6.0")
