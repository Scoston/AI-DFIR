#!/usr/bin/env python3
"""Internal Atheris child. Use run_coverage_fuzz_v17.py for the bounded CLI."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main():
    if not __debug__:
        raise RuntimeError("fuzz assertions must be enabled")
    import atheris
    # Keep this fixed list here: importing the target first loses import coverage.
    modules = (
        "v17_fuzz_targets", "v17_parser_corpus", "v17_archive_intake_selftest",
        "v17_archive_intake", "v17_cloudtrail", "v17_gcp_audit", "v17_azure_activity",
        "v17_log_analytics", "v17_log_analytics_lossless", "v17_numeric_json",
        "v17_log_analytics_context", "v17_gcp_logging_context", "v17_reconstruction",
        "v17_provenance", "v17_integrity",
        "v17_docx_intake", "v17_docx_intake_selftest",
        "v17_html_intake",
    )
    with atheris.instrument_imports(include=modules):
        import v17_fuzz_targets as targets
    if modules != targets.INSTRUMENTED_MODULES:
        raise AssertionError("instrumentation profile mismatch")

    @atheris.instrument_func
    def test_one_input(data):
        targets.exercise(data)

    with targets.blocked_actions():
        atheris.Setup(sys.argv, test_one_input)
        atheris.Fuzz()


if __name__ == "__main__":
    main()
