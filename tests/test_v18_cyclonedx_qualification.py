from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from scripts.qualify_cyclonedx_v18 import (
    PINNED_ARCHIVE_SHA256,
    PINNED_VALIDATOR_VERSION,
    qualify,
)


def _fake_validator(tmp_path: Path, *, accept_invalid: bool = False) -> Path:
    path = tmp_path / "fake-sbom-utility"
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import json,sys\n"
        f"ACCEPT_INVALID={accept_invalid!r}\n"
        "args=sys.argv[1:]\n"
        "if len(args)>=2 and args[0]=='schema' and args[1]=='list':\n"
        "    print('CycloneDX v1.7  (latest)  CycloneDX  1.7  schema/cyclonedx/1.7/bom-1.7.schema.json')\n"
        "    raise SystemExit(0)\n"
        "if args and args[0]=='validate':\n"
        "    p=args[args.index('-i')+1]\n"
        "    doc=json.load(open(p,encoding='utf-8'))\n"
        "    valid=(doc.get('bomFormat')=='CycloneDX' and doc.get('specVersion')=='1.7' and doc.get('version',1)>=1)\n"
        "    if valid or ACCEPT_INVALID:\n"
        "        print('[]')\n"
        "        raise SystemExit(0)\n"
        "    print('[{\"type\":\"minimum\",\"field\":\"version\"}]')\n"
        "    raise SystemExit(2)\n"
        "raise SystemExit(1)\n",
        encoding="utf-8",
    )
    os.chmod(path, 0o755)
    return path


def test_qualification_receipt_binds_positive_and_negative_controls(tmp_path: Path) -> None:
    validator = _fake_validator(tmp_path)
    out = tmp_path / "qualification"
    receipt = qualify(
        validator=str(validator),
        out_dir=out,
        validator_version=PINNED_VALIDATOR_VERSION,
        validator_archive_sha256=PINNED_ARCHIVE_SHA256,
        network_isolated=True,
    )
    assert receipt["target"] == {"format": "CycloneDX", "version": "1.7", "built_in_schema_observed": True}
    assert receipt["positive_control"]["exit_code"] == 0
    assert receipt["negative_control"]["exit_code"] == 2
    assert receipt["claims"]["tested_projection_schema_conformant"] is True
    assert receipt["claims"]["qualification_network_namespace_isolated"] is True
    assert receipt["claims"]["production_bom_conformance_implied"] is False
    assert receipt["claims"]["all_future_projections_conform"] is False
    persisted = json.loads((out / "qualification-receipt.json").read_text(encoding="utf-8"))
    assert persisted["receipt_sha256"] == receipt["receipt_sha256"]


def test_negative_control_must_actually_fail(tmp_path: Path) -> None:
    validator = _fake_validator(tmp_path, accept_invalid=True)
    with pytest.raises(RuntimeError, match="negative control"):
        qualify(
            validator=str(validator),
            out_dir=tmp_path / "qualification",
            validator_version=PINNED_VALIDATOR_VERSION,
            validator_archive_sha256=PINNED_ARCHIVE_SHA256,
        )


def test_validator_pin_cannot_be_silently_changed(tmp_path: Path) -> None:
    validator = _fake_validator(tmp_path)
    with pytest.raises(ValueError, match="version"):
        qualify(
            validator=str(validator),
            out_dir=tmp_path / "qualification-a",
            validator_version="0.19.3",
            validator_archive_sha256=PINNED_ARCHIVE_SHA256,
        )
    with pytest.raises(ValueError, match="SHA-256"):
        qualify(
            validator=str(validator),
            out_dir=tmp_path / "qualification-b",
            validator_version=PINNED_VALIDATOR_VERSION,
            validator_archive_sha256="0" * 64,
        )
