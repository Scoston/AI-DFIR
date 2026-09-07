"""Exact wide numeric values and signed offline replay, using synthetic evidence."""
from __future__ import annotations

import json
from pathlib import Path
import socket
import tempfile
from unittest.mock import patch

from case_export_v17 import verify_case
from v17_log_analytics_lossless import TRANSFORMATION, normalize
from v17_log_analytics_selftest import export_fixture, synthetic_query_case


def synthetic_numeric_response(*, partial=False, resource=False):
    error = ',"error":{"code":"PartialError","message":"synthetic partial result"}' if partial else ""
    permissions = ',"permissions":{"syntheticCounter":9007199254740993}' if resource else ""
    return ('''{"tables":[{"name":"PrimaryResult","columns":[
        {"name":"Wide","type":"long"},{"name":"Decimal","type":"decimal"},
        {"name":"NumericString","type":"long"},{"name":"Real","type":"real"},
        {"name":"Opaque","type":"dynamic"}],"rows":[
        [9223372036854775807,79228162514264337593543950335,"-9223372036854775808",-0.0,
        {"numeric":9007199254740993,"text":"9007199254740993","tag":["number","9007199254740993"]}],
        [-9223372036854775808,0.1234567890123456789012345678,"9007199254740993",1.00000000000000001,null]
        ]}],"statistics":{"counter":9007199254740993}''' + error + permissions + '}').encode()


def synthetic_numeric_case(root, *, partial=False, resource=False):
    fixture = synthetic_query_case(root, partial=partial)
    fixture.update(raw=synthetic_numeric_response(partial=partial, resource=resource), transformation=TRANSFORMATION)
    fixture["metadata"]["input_format"] = "resource-tables" if resource else "tables"
    fixture["output"] = normalize(fixture["raw"], input_format=fixture["metadata"]["input_format"])
    return fixture


def main():
    with tempfile.TemporaryDirectory(prefix="ai-dfir-lossless-") as temporary:
        with patch.object(socket.socket, "connect", side_effect=AssertionError("unexpected lossless replay network")):
            for partial in (False, True):
                for resource in (False, True):
                    fixture = synthetic_numeric_case(Path(temporary) / f"{partial}-{resource}" / "case", partial=partial, resource=resource)
                    cells = fixture["output"]["tables"][0]["rows"][0]["cells"]
                    assert cells[0]["numeric_text"] == "9223372036854775807"
                    assert cells[1]["numeric_text"] == "79228162514264337593543950335"
                    assert cells[2]["json_kind"] == "string" and cells[3]["numeric_text"] == "-0.0"
                    export_fixture(fixture)
                    result = verify_case(fixture["package"], fixture["public"], require_provenance=True, replay_transforms=True)
                    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "PASS"
                    fixture["raw"] = fixture["raw"].replace(b"1.00000000000000001", b"1.00000000000000002")
                    export_fixture(fixture)
                    result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
                    assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "FAIL"
    print(json.dumps({"status": "PASS", "wide_integers_preserved": True, "decimal_text_preserved": True,
                      "numeric_string_distinct": True, "rounded_value_substitution_detected": True, "offline": True}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
