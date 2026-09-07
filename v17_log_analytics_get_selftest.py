"""Synthetic acceptance for bounded workspace GET context and offline replay."""
from __future__ import annotations

import json
import socket
import tempfile
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote

from case_export_v17 import verify_case
from v17_integrity import canonical_json_bytes
from v17_log_analytics_context import normalize
from v17_log_analytics_context_selftest import export_fixture, synthetic_context, synthetic_context_case


def synthetic_get_context(raw):
    context = synthetic_context(raw)
    request = context["request"]
    body = request["body"]
    query_string = "&".join(f"{key}={quote(body[key], safe='')}" for key in ("query", "timespan"))
    request.update(method="GET", url=request["url"] + "?" + query_string, body=None,
                   headers={"accept": "application/json", "prefer": "wait=30"})
    return context


def synthetic_get_case(root: Path, *, partial=False):
    fixture = synthetic_context_case(root, partial=partial)
    fixture["context"] = canonical_json_bytes(synthetic_get_context(fixture["raw"]))
    fixture["metadata"]["input_format"] = "workspace-get"
    fixture["output"] = normalize(fixture["raw"], context_raw=fixture["context"], input_format="workspace-get")
    return fixture


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ai-dfir-query-get-") as temporary:
        with patch.object(socket.socket, "connect", side_effect=AssertionError("unexpected GET replay network")):
            for partial in (False, True):
                fixture = synthetic_get_case(Path(temporary) / str(partial) / "case", partial=partial)
                export_fixture(fixture)
                result = verify_case(fixture["package"], fixture["public"], require_provenance=True, replay_transforms=True)
                replay = result["reconstruction"]["deterministic_replay"]
                transform = replay["transforms"][0]
                assert result["valid"] and replay["status"] == "PASS" and transform["request_context_bound"]
                assert transform["collection_complete"] is (False if partial else None)
                assert not transform["query_execution_verified"] and not transform["request_scope_verified"]
                changed = json.loads(fixture["context"])
                changed["request"]["url"] += "%20"
                fixture["context"] = canonical_json_bytes(changed)
                export_fixture(fixture)
                result = verify_case(fixture["package"], fixture["public"], replay_transforms=True)
                assert result["valid"] and result["reconstruction"]["deterministic_replay"]["status"] == "FAIL"
    print(json.dumps({"status": "PASS", "offline": True, "get_context_substitution_detected": True,
                      "partial_error_preserved": True, "query_execution_verified": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
