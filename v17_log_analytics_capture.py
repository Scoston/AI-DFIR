"""Explicit bounded workspace acquisition with automatic retained query context."""
from __future__ import annotations

import os
from pathlib import Path
import re
from urllib.parse import quote

import requests
from urllib3.exceptions import HTTPError

from v17_integrity import canonical_json_bytes, sha256_bytes
from v17_log_analytics import MAX_INPUT_BYTES, _document
from v17_log_analytics_context import (
    CONTEXT_SCHEMA, GET_REQUEST_HEADERS, MAX_CONTEXT_BYTES, REQUEST_HEADERS, RESPONSE_HEADERS,
    _get_request, _headers, _object, normalize, validate_request,
)

MAX_PARAMS_BYTES = MAX_CONTEXT_BYTES
READ_CHUNK = 64 * 1024
TIMEOUT = (10, 45)
TOKEN_ENV = "AZURE_LOG_ANALYTICS_TOKEN"
TOKEN_RE = re.compile(r"[A-Za-z0-9._~+/-]+=*")
RECEIPT_SCHEMA = "ai-dfir/log-analytics-capture-receipt/v1.7"
OBSERVATION_SCHEMA = "ai-dfir/log-analytics-capture-observation/v1.7"
CAPTURE_METHODS = ("POST", "GET")


class CaptureError(ValueError):
    """A redacted acquisition/configuration/output failure."""


def _request(params_raw, *, method="POST"):
    params = _document(params_raw, MAX_PARAMS_BYTES)
    optional = {"timespan", "prefer", "client_request_id"} | ({"workspaces"} if method == "POST" else set())
    _object(params, {"workspace_id", "kql"}, optional)
    workspace = params["workspace_id"]
    if not isinstance(workspace, str):
        raise CaptureError("invalid acquisition request")
    body = {"query": params["kql"], **{k: params[k] for k in ("timespan", "workspaces") if k in params}}
    headers = {"accept": "application/json"} if method == "GET" else {"content-type": "application/json"}
    for param, header in (("prefer", "prefer"), ("client_request_id", "x-ms-client-request-id")):
        if param in params:
            headers[header] = params[param]
    request = {"method": method, "url": f"https://api.loganalytics.io/v1/workspaces/{workspace}/query",
               "body": body, "headers": headers}
    if method == "GET":
        # Encode decoded operator parameters, then validate the complete URL.
        # No form '+' encoding, arbitrary URL input, or extra workspace scope.
        request["url"] += "?" + "&".join(f"{key}={quote(value, safe='')}" for key, value in body.items())
        request["body"] = None
        _get_request(request)
    else:
        validate_request(request)
    return request


def _selected(headers, allowed, token):
    selected = {key: headers[key] for key in sorted(allowed) if key in headers}
    _headers(selected, allowed)
    if any(token in value for value in selected.values()):
        raise CaptureError("credential contamination in selected observations")
    return selected


def _record_request(prepared, token, *, method="POST"):
    request = {"method": prepared.method, "url": prepared.url,
               "body": prepared.body if method == "GET" else _document(prepared.body, MAX_PARAMS_BYTES),
               "headers": _selected(prepared.headers, GET_REQUEST_HEADERS if method == "GET" else REQUEST_HEADERS, token)}
    if method == "GET":
        _, parameters = _get_request(request)
        # A bearer token may contain '+', '/', or '='. Check decoded values too,
        # so percent encoding cannot hide configured credentials in a GET URL.
        contaminated = token.encode() in canonical_json_bytes(parameters)
    else:
        validate_request(request)
        contaminated = False
    if contaminated or token.encode() in canonical_json_bytes(request):
        raise CaptureError("credential contamination in retained request")
    return request


def _read_body(response):
    # Reject compression instead of allowing an implicit decompression bomb or
    # mislabeling decoded bytes as the observed entity body.
    encoding = response.headers.get("Content-Encoding", "identity")
    if not isinstance(encoding, str) or encoding.lower() != "identity":
        raise CaptureError("unsupported response content encoding")
    length = response.headers.get("Content-Length")
    if length is not None:
        if not isinstance(length, str) or re.fullmatch(r"[0-9]{1,10}", length) is None or int(length) > MAX_INPUT_BYTES:
            raise CaptureError("invalid or excessive response length")
        length = int(length)
    parts, size = [], 0
    while True:
        chunk = response.raw.read(min(READ_CHUNK, MAX_INPUT_BYTES + 1 - size), decode_content=False)
        if not isinstance(chunk, bytes):
            raise CaptureError("invalid response stream")
        if not chunk:
            break
        size += len(chunk)
        if size > MAX_INPUT_BYTES:
            raise CaptureError("response exceeds byte limit")
        parts.append(chunk)
    if length is not None and size != length:
        raise CaptureError("response length mismatch")
    return b"".join(parts)


def _acquire(prepared, recorded, token):
    # HTTPAdapter performs one urllib3 request with redirects/preloading off.
    # Session.send can consume a redirect body even with allow_redirects=False.
    # No Session means no ambient netrc, cookies, or environment proxy/CA merge.
    adapter = requests.adapters.HTTPAdapter(max_retries=0)
    response = None
    try:
        response = adapter.send(prepared, stream=True, timeout=TIMEOUT, verify=True, cert=None, proxies={})
        if (response.url != recorded["url"] or response.history
                or _record_request(response.request, token, method=recorded["method"]) != recorded):
            raise CaptureError("observed request differs from prepared capture")
        status = response.status_code
        if type(status) is not int or not 100 <= status <= 599:
            raise CaptureError("invalid observed HTTP status")
        headers = _selected(response.headers, RESPONSE_HEADERS, token)
        return _read_body(response), status, headers
    finally:
        try:
            if response is not None:
                response.close()
        finally:
            adapter.close()


def _write_new(directory, name, raw):
    descriptor = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return {"path": name, "sha256": sha256_bytes(raw), "size_bytes": len(raw)}


def _publish_receipt(directory, receipt):
    # The final receipt is an exclusive hard link to a fully written file.
    # A failed/interrupted member write never publishes a success receipt.
    _write_new(directory, "receipt.pending.json", canonical_json_bytes(receipt))
    os.link(directory / "receipt.pending.json", directory / "receipt.json")
    try:
        (directory / "receipt.pending.json").unlink()
    except OSError:
        pass  # A leftover staging copy does not invalidate the committed receipt.


def capture(params_raw: bytes, out_dir: str | Path, *, method: str = "POST") -> dict:
    """Acquire once; return a digest-only receipt. Never overwrite an output set.

    CAPTURED means the three required files were written and project correctly;
    collection remains unknown/incomplete. FAILED may retain a bounded response
    and an observation record, but never a compatible projection claim.
    """
    try:
        if not isinstance(method, str) or method not in CAPTURE_METHODS:
            raise CaptureError("unsupported acquisition method")
        requested = _request(params_raw, method=method)
        token = os.environ.get(TOKEN_ENV, "")
        if not token or len(token) > 16384 or TOKEN_RE.fullmatch(token) is None:
            raise CaptureError("missing or invalid acquisition credential")
        body = None if method == "GET" else canonical_json_bytes(requested["body"])
        prepared = requests.Request(method, requested["url"], data=body,
                                    headers={**requested["headers"], "Authorization": "Bearer " + token,
                                             "Accept": "application/json", "Accept-Encoding": "identity"}).prepare()
        recorded = _record_request(prepared, token, method=method)
        if recorded != requested:
            raise CaptureError("prepared request differs from requested profile")
        directory = Path(out_dir)
        directory.mkdir(mode=0o700)  # Parent must already exist and be protected.
        raw, status, headers = _acquire(prepared, recorded, token)
        files = [_write_new(directory, "response.json", raw)]
        context = {"schema": CONTEXT_SCHEMA, "request": recorded,
                   "response": {"status": status, "headers": headers,
                                "body_sha256": sha256_bytes(raw), "body_size_bytes": len(raw)}}
        context_raw = canonical_json_bytes(context)
        try:
            projection = normalize(raw, context_raw=context_raw, input_format="workspace-get" if method == "GET" else "workspace-post")
        except (ValueError, TypeError, RecursionError):
            projection = None
        if projection is not None:
            files.append(_write_new(directory, "context.json", context_raw))
            files.append(_write_new(directory, "projection.json", canonical_json_bytes(projection)))
        else:
            # This explicitly different schema is not a valid replay context.
            observation = {**context, "schema": OBSERVATION_SCHEMA, "replay_context_available": False}
            files.append(_write_new(directory, "capture-observation.json", canonical_json_bytes(observation)))
        try:
            document = _document(raw, MAX_INPUT_BYTES)
            reported_error = isinstance(document, dict) and "error" in document
        except (ValueError, TypeError, RecursionError):
            reported_error = None
        receipt = {
            "schema": RECEIPT_SCHEMA, "status": "CAPTURED" if projection is not None else "FAILED",
            "artifact_set_complete": projection is not None, "files": files, "http_status": status,
            "body_representation": "HTTP-entity-body-without-content-decoding",
            "collection_complete": projection["collection_complete"] if projection is not None else False if status != 200 or reported_error else None,
            "response_error_recorded": reported_error,
            "request_context_bound": projection is not None, "network_attempted": True,
            "source_authenticity_verified": False, "request_scope_verified": False,
            "query_execution_verified": False, "query_reexecuted_during_replay": False,
            "content_policy": "artifact_digests_only",
            **({"request_method": "GET", "input_format": "workspace-get"} if method == "GET" else {}),
            **({key: projection["result"][key] for key in ("response_state", "partial_error_recorded", "row_count")} if projection is not None else {}),
        }
        _publish_receipt(directory, receipt)
        return receipt
    except (ValueError, TypeError, OSError, RecursionError, requests.RequestException, HTTPError):
        raise CaptureError("invalid, unavailable, excessive, or conflicting acquisition input/output") from None
