"""One bounded Google Cloud Logging acquisition with retained request context."""
from __future__ import annotations

import os
from pathlib import Path

import requests
from urllib3.exceptions import HTTPError

from v17_gcp_audit import MAX_INPUT_BYTES, _document
from v17_gcp_logging_context import (
    CONTEXT_SCHEMA, ENDPOINT, MAX_CONTEXT_BYTES, REQUEST_HEADERS, RESPONSE_HEADERS,
    _headers, normalize, validate_request,
)
from v17_integrity import canonical_json_bytes, sha256_bytes
# Shared 8 MiB undecoded body reader and exclusive private artifact publication.
# Endpoint validation and request observations remain provider-specific below.
from v17_log_analytics_capture import CaptureError, TIMEOUT, TOKEN_RE, _publish_receipt, _read_body, _write_new

MAX_PARAMS_BYTES = MAX_CONTEXT_BYTES
TOKEN_ENV = "GOOGLE_OAUTH_ACCESS_TOKEN"
RECEIPT_SCHEMA = "ai-dfir/gcp-logging-capture-receipt/v1.7"
OBSERVATION_SCHEMA = "ai-dfir/gcp-logging-capture-observation/v1.7"


def _request(params_raw):
    request = {"method": "POST", "url": ENDPOINT, "body": _document(params_raw, MAX_PARAMS_BYTES),
               "headers": {"content-type": "application/json"}}
    validate_request(request)
    return request


def _selected(headers, allowed, token):
    selected = {key: headers[key] for key in sorted(allowed) if key in headers}
    _headers(selected, allowed)
    if any(token in value for value in selected.values()):
        raise CaptureError("credential contamination in logging observation")
    return selected


def _record_request(prepared, token):
    request = {"method": prepared.method, "url": prepared.url,
               "body": _document(prepared.body, MAX_PARAMS_BYTES),
               "headers": _selected(prepared.headers, REQUEST_HEADERS, token)}
    validate_request(request)
    if token.encode() in canonical_json_bytes(request):
        raise CaptureError("credential contamination in retained logging request")
    return request


def _acquire(prepared, recorded, token):
    adapter = requests.adapters.HTTPAdapter(max_retries=0)
    response = None
    try:
        # One direct adapter call: no Session, redirect following, retry, ambient
        # netrc/cookies, environment proxy/CA merge, or implicit decompression.
        response = adapter.send(prepared, stream=True, timeout=TIMEOUT, verify=True, cert=None, proxies={})
        if (response.url != ENDPOINT or response.history
                or _record_request(response.request, token) != recorded):
            raise CaptureError("observed logging request differs from prepared capture")
        status = response.status_code
        if type(status) is not int or not 100 <= status <= 599:
            raise CaptureError("invalid observed logging status")
        headers = _selected(response.headers, RESPONSE_HEADERS, token)
        return _read_body(response), status, headers
    finally:
        try:
            if response is not None:
                response.close()
        finally:
            adapter.close()


def capture(params_raw: bytes, out_dir: str | Path) -> dict:
    """Acquire one page; preserve bounded failures without a replay claim."""
    try:
        requested = _request(params_raw)
        token = os.environ.get(TOKEN_ENV, "")
        if not token or len(token) > 16384 or TOKEN_RE.fullmatch(token) is None:
            raise CaptureError("missing or invalid logging acquisition credential")
        prepared = requests.Request("POST", ENDPOINT, data=canonical_json_bytes(requested["body"]),
                                    headers={**requested["headers"], "Authorization": "Bearer " + token,
                                             "Accept": "application/json", "Accept-Encoding": "identity"}).prepare()
        recorded = _record_request(prepared, token)
        if recorded != requested:
            raise CaptureError("prepared logging request differs from requested profile")
        directory = Path(out_dir)
        directory.mkdir(mode=0o700)
        raw, status, headers = _acquire(prepared, recorded, token)
        files = [_write_new(directory, "response.json", raw)]
        context = {"schema": CONTEXT_SCHEMA, "request": recorded,
                   "response": {"status": status, "headers": headers,
                                "body_sha256": sha256_bytes(raw), "body_size_bytes": len(raw)}}
        context_raw = canonical_json_bytes(context)
        try:
            projection = normalize(raw, context_raw=context_raw, input_format="entries-list")
        except (ValueError, TypeError, RecursionError):
            projection = None
        if projection is not None:
            files.append(_write_new(directory, "context.json", context_raw))
            files.append(_write_new(directory, "projection.json", canonical_json_bytes(projection)))
        else:
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
            "input_format": "entries-list", "request_method": "POST", "pages_observed": 1,
            "body_representation": "HTTP-entity-body-without-content-decoding",
            "collection_complete": projection["collection_complete"] if projection is not None else False if status != 200 or reported_error else None,
            "response_error_recorded": reported_error, "request_context_bound": projection is not None,
            "network_attempted": True, "source_authenticity_verified": False, "request_scope_verified": False,
            "query_execution_verified": False, "query_reexecuted_during_replay": False,
            "pagination_chain_verified": False, "content_policy": "artifact_digests_only",
            **({key: projection["result"][key] for key in ("entry_count", "continuation_token_present")} if projection is not None else {}),
        }
        _publish_receipt(directory, receipt)
        return receipt
    except (ValueError, TypeError, OSError, RecursionError, requests.RequestException, HTTPError):
        raise CaptureError("invalid, unavailable, excessive, or conflicting logging acquisition input/output") from None
