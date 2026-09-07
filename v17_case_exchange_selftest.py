#!/usr/bin/env python3
"""Synthetic signed-case CASE/UCO inventory exchange acceptance."""
from __future__ import annotations

import json
import socket
import tempfile
from pathlib import Path
from unittest.mock import patch

from case_export_v17 import export_case
from fleet_crypto import generate
from v17_case_exchange import compare_exchange, export_exchange
from v17_integrity import canonical_json_bytes
from v17_provenance import ProvenanceError
from v17_provenance_selftest import CASE_ID, TENANT_ID, sign_fixture, synthetic_case


def exchange_fixture(root):
    """Fresh public synthetic records and temporary keys, never real evidence."""
    profile, ledger = synthetic_case(root / "case")
    signed, trust = sign_fixture(ledger)
    private, public, package = root / "export.pem", root / "export.pub.pem", root / "case.zip"
    generate(private, public)
    export_case(root / "case", TENANT_ID, CASE_ID, private, package, ledger=ledger,
                signed_checkpoint=signed, trusted_public_keys=trust, provenance=profile)
    return package.read_bytes(), public


def main():
    with tempfile.TemporaryDirectory(prefix="ai-dfir-case-exchange-") as temporary:
        raw, public = exchange_fixture(Path(temporary))
        options = {"expected_tenant": TENANT_ID, "expected_case": CASE_ID}
        with patch.object(socket.socket, "connect", side_effect=AssertionError("network forbidden")), \
             patch.object(socket, "create_connection", side_effect=AssertionError("network forbidden")):
            graph = export_exchange(raw, public, **options)
            encoded = canonical_json_bytes(graph)
            assert compare_exchange(raw, encoded, public, **options)["status"] == "PASS"
            assert canonical_json_bytes(export_exchange(raw, public, **options)) == encoded
            assert len(graph["@graph"]) == 11
            case = next(n for n in graph["@graph"] if n["@type"] == "case-investigation:Investigation")
            assert case["adfir:artifactCount"] == 2 and case["adfir:relationshipCount"] == 1
            assert case["adfir:omittedRecordCount"] == 3 and case["adfir:recordCount"] == 6
            assert case["adfir:sourceCaseIntegrityVerified"] and not case["adfir:executionVerified"]
            graph["@context"]["uco-core"] = "https://example.invalid/replaced/"
            assert compare_exchange(raw, canonical_json_bytes(graph), public, **options)["status"] == "FAIL"
            try:
                export_exchange(raw, public, **{**options, "expected_case": "OTHER"})
            except ProvenanceError:
                pass
            else:
                raise AssertionError("identity substitution accepted")
    print(json.dumps({"status": "PASS", "nodes": 11, "offline": True,
                      "source_verified": True, "graph_unsigned": True}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
