from __future__ import annotations

from pathlib import Path

import pytest

import v18_otlp_envelope as otlp
from scripts.qualify_otlp_envelope_v18 import qualify


def test_small_population_qualification_is_bound_and_conservative(tmp_path: Path) -> None:
    report = qualify(spans=32, logs=64, traces=4, out_dir=tmp_path)
    assert report["observations"]["imported_spans"] == 32
    assert report["observations"]["imported_logs"] == 64
    assert report["observations"]["trace_ids"] == 4
    assert report["observations"]["selected_trace_spans"] == 8
    assert report["claims"]["synthetic_population_accepted"] is True
    assert report["claims"]["production_scale_qualified"] is False
    assert report["claims"]["collector_interoperability_qualified"] is False
    assert report["claims"]["telemetry_authenticity_verified"] is False
    assert report["claims"]["business_causality_proven"] is False
    assert (tmp_path / "qualification-report.json").exists()


def test_qualification_population_must_stay_inside_importer_bounds(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(otlp, "MAX_SPANS", 10)
    with pytest.raises(ValueError, match="bounds"):
        qualify(spans=11, logs=2, traces=1, out_dir=tmp_path / "a")
    monkeypatch.setattr(otlp, "MAX_LOG_RECORDS", 10)
    with pytest.raises(ValueError, match="bounds"):
        qualify(spans=2, logs=11, traces=1, out_dir=tmp_path / "b")


def test_trace_count_cannot_exceed_span_count(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="span_count"):
        qualify(spans=2, logs=2, traces=3, out_dir=tmp_path)
