"""Explicit HTTPS delivery into an independently anchored governed policy store.

The endpoint supplies untrusted signed metadata, never its own trust anchor.
One bounded response is authenticated and activated atomically. Case verifiers
do not import this module or perform delivery as a side effect of verification.
"""
from __future__ import annotations

import http.client
import ipaddress
import math
import re
import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path
from threading import Event, Timer
from typing import Any
from urllib.parse import urlsplit

import v17_policy_governance as governance
from v17_integrity import sha256_bytes, sha256_object
from v17_policy_distribution import MAX_SIGNED_POLICY_BYTES, PolicyUpdateError, _json, _require, _snapshot, authenticate_key_policy
from v17_policy_quorum import validate_quorum_envelope
from v17_delivery_identity import configure_client_identity

BUNDLE_SCHEMA = "ai-dfir/checkpoint-policy-delivery/v1.7"
DELIVERY_REPORT_SCHEMA = "ai-dfir/checkpoint-policy-delivery-report/v1.7"
MAX_DELIVERY_BYTES = governance.MAX_CHAIN_BYTES + MAX_SIGNED_POLICY_BYTES + 1024
MAX_CA_BYTES = 1024 * 1024
DEFAULT_TIMEOUT = 10.0
_DNS_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_JSON_TYPE = re.compile(r'application/json(?:;\s*charset=(?:utf-8|"utf-8"))?\Z', re.I)


class PolicyDeliveryError(PolicyUpdateError):
    def __init__(self, code: str, detail: str, *, network_attempted: bool = False):
        super().__init__(code, detail)
        self.network_attempted = network_attempted


def validate_delivery_bundle(value: Any) -> dict:
    bundle = _snapshot(value, MAX_DELIVERY_BYTES)
    _require(isinstance(bundle, dict) and set(bundle) == {"schema", "rotations", "signed_policy"}
             and bundle["schema"] == BUNDLE_SCHEMA,
             "policy_delivery_bundle_invalid", "delivery must contain only its schema, complete rotations, and signed policy")
    rotations = _snapshot(bundle["rotations"], governance.MAX_CHAIN_BYTES)
    _require(isinstance(rotations, list) and len(rotations) <= governance.MAX_ROTATIONS,
             "root_chain_invalid", "delivered root chain exceeds its limit or is malformed")
    bundle["rotations"] = [governance.validate_rotation(value) for value in rotations]
    bundle["signed_policy"] = validate_quorum_envelope(bundle["signed_policy"])
    return bundle


def prepare_delivery_bundle(root_anchor: Any, signed_policy: Any, rotations: Any) -> dict:
    """Prepare publisher metadata only after checking the full signed chain."""
    anchor = governance.validate_root(root_anchor)
    bundle = validate_delivery_bundle({"schema": BUNDLE_SCHEMA, "rotations": rotations, "signed_policy": signed_policy})
    root, _, _ = governance._chain(anchor, bundle["rotations"])
    authenticate_key_policy(bundle["signed_policy"], root["issuer_trust"])
    governance._current(root)
    return bundle


def _endpoint(url: Any):
    _require(isinstance(url, str) and 0 < len(url) <= 2048 and url.startswith("https://")
             and all(33 <= ord(char) < 127 for char in url) and "\\" not in url and "?" not in url and "#" not in url,
             "policy_delivery_url_invalid", "use an explicit ASCII HTTPS URL without credentials, query, fragment, or controls")
    try:
        parsed = urlsplit(url)
        host, port = parsed.hostname, parsed.port
        _require(bool(host) and parsed.username is None and parsed.password is None and not parsed.netloc.endswith(":"),
                 "policy_delivery_url_invalid", "invalid delivery host or credentials in URL")
        _require(port is None or 1 <= port <= 65535, "policy_delivery_url_invalid", "invalid delivery port")
        try:
            ipaddress.ip_address(host)
            _require("%" not in host, "policy_delivery_url_invalid", "scoped IP addresses are unsupported")
        except ValueError:
            _require(len(host) <= 253 and all(_DNS_LABEL.fullmatch(label) for label in host.split(".")),
                     "policy_delivery_url_invalid", "invalid delivery hostname")
            _require(not all(re.fullmatch(r"(?:[0-9]+|0[xX][0-9A-Fa-f]+)", label) for label in host.split(".")),
                     "policy_delivery_url_invalid", "use a standard IP literal rather than a legacy numeric address")
        path = parsed.path or "/"
        _require(not path.startswith("//"), "policy_delivery_url_invalid", "ambiguous delivery request path")
        _require(re.search(r"%(?![0-9A-Fa-f]{2})|%(?:0[0-9A-Fa-f]|1[0-9A-Fa-f]|7[fF])", path) is None,
                 "policy_delivery_url_invalid", "invalid escape or encoded control in delivery path")
    except ValueError as exc:
        raise PolicyDeliveryError("policy_delivery_url_invalid", "invalid delivery URL") from exc
    return host, port or 443, path


def _timeout(value: Any) -> float:
    _require(type(value) in (int, float) and 0.1 <= value <= 60 and math.isfinite(value),
             "policy_delivery_timeout_invalid", "timeout must be a finite number from 0.1 through 60 seconds")
    return float(value)


def _tls_context(ca_file: str | Path | None) -> tuple[ssl.SSLContext, str | None]:
    if ca_file is None:
        context, digest = ssl.create_default_context(), None
    else:
        _require(isinstance(ca_file, (str, Path)) and str(ca_file) != "" and Path(ca_file).is_file(),
                 "policy_delivery_ca_invalid", "CA file must be an existing PEM file")
        with Path(ca_file).open("rb") as stream:
            raw = stream.read(MAX_CA_BYTES + 1)
        _require(0 < len(raw) <= MAX_CA_BYTES, "policy_delivery_ca_invalid", "CA file is empty or oversized")
        context, digest = ssl.create_default_context(cadata=raw.decode("ascii")), sha256_bytes(raw)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.keylog_filename = None
    context.set_alpn_protocols(["http/1.1"])
    return context, digest


def _header(response, name: str, *, required: bool = False) -> str | None:
    values = response.headers.get_all(name, [])
    _require(len(values) <= 1 and (not required or len(values) == 1),
             "policy_delivery_headers_invalid", f"missing or repeated {name} header")
    return values[0].strip() if values else None


def _fetch(url: str, endpoint: tuple, timeout: float, context: ssl.SSLContext, ca_digest: str | None) -> tuple[bytes, dict]:
    host, port, path = endpoint
    connection = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
    response = timer = None
    expired = Event()
    try:
        connection.connect()
        transport = connection.sock
        certificate = transport.getpeercert(binary_form=True)
        tls_version = transport.version()

        def abort_response():
            expired.set()
            try:
                transport.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        # Socket timeouts cover connect/TLS inactivity. Once connected, an
        # independent deadline also stops peers that trickle headers or body.
        timer = Timer(timeout, abort_response)
        timer.daemon = True
        timer.start()
        connection.request("GET", path, headers={"Accept": "application/json", "Accept-Encoding": "identity",
                           "Cache-Control": "no-cache", "Connection": "close", "User-Agent": "AI-DFIR/1.7-policy-delivery"})
        response = connection.getresponse()
        _require(response.status == 200, "policy_delivery_http_status", f"delivery returned HTTP {response.status}; redirects are not followed")
        _require(_JSON_TYPE.fullmatch(_header(response, "Content-Type", required=True)) is not None,
                 "policy_delivery_media_type", "delivery must be application/json with optional UTF-8 charset")
        _require(_header(response, "Content-Encoding") in (None, "identity"),
                 "policy_delivery_encoding", "compressed delivery responses are unsupported")
        _require(_header(response, "Transfer-Encoding") is None and _header(response, "Content-Range") is None,
                 "policy_delivery_framing", "chunked or ranged delivery responses are unsupported")
        length = _header(response, "Content-Length", required=True)
        _require(re.fullmatch(r"[0-9]{1,10}", length) is not None and 0 < int(length) <= MAX_DELIVERY_BYTES,
                 "policy_delivery_size", "delivery Content-Length is invalid, empty, or oversized")
        length = int(length)
        body = bytearray()
        while len(body) < length:
            chunk = response.read1(min(64 * 1024, length - len(body)))
            if not chunk:
                break
            body.extend(chunk)
        _require(len(body) == length, "policy_delivery_truncated", "delivery body is incomplete")
    except (PolicyUpdateError, OSError, http.client.HTTPException) as exc:
        if expired.is_set() or isinstance(exc, TimeoutError):
            code, detail = "policy_delivery_timeout", "delivery exceeded its connection timeout or response deadline"
        elif isinstance(exc, PolicyUpdateError):
            code, detail = exc.code, str(exc)
        elif isinstance(exc, ssl.SSLError):
            code, detail = "policy_delivery_tls", "delivery TLS certificate, hostname, or handshake verification failed"
        else:
            code, detail = "policy_delivery_network", "delivery connection or HTTP protocol failed"
        raise PolicyDeliveryError(code, detail, network_attempted=True) from exc
    finally:
        if timer is not None:
            timer.cancel()
            timer.join()
        if response is not None:
            response.close()
        connection.close()
    if expired.is_set():
        raise PolicyDeliveryError("policy_delivery_timeout", "delivery response deadline elapsed", network_attempted=True)
    raw = bytes(body)
    return raw, {"source_url": url, "response_sha256": sha256_bytes(raw), "response_bytes": len(raw),
                 "received_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                 "tls_peer_certificate_sha256": sha256_bytes(certificate), "tls_version": tls_version,
                 "tls_ca_file_sha256": ca_digest, "tls_trust_source": "system-default" if ca_digest is None else "operator-ca-file",
                 "connection_timeout_seconds": timeout, "response_deadline_seconds": timeout,
                 "http_requests": 1, "redirects_followed": 0, "network_performed": True}


def sync_policy(path: str | Path, root_anchor: Any, url: str, *, ca_file: str | Path | None = None,
                timeout: float = DEFAULT_TIMEOUT, minimum_revision=None, minimum_root_version=None,
                client_cert_file=None, client_key_file=None, client_key_password_file=None,
                expected_client_certificate_sha256=None) -> dict:
    """Fetch once from operator configuration, authenticate, and atomically activate.

    Local preflight permits expiry recovery but requires an already initialized,
    authentic governed store. Recovery floors apply to the final candidate under
    the write lock. No DNS, HTTP, TLS, or signature failure is a successful sync.
    """
    try:
        endpoint, seconds = _endpoint(url), _timeout(timeout)
        anchor = governance.validate_root(root_anchor)
        governance._floor(minimum_revision, 2**53 - 1, "policy revision")
        governance._floor(minimum_root_version, 2**53 - 1, "root version")
        governance._read_state(path, anchor)
        context, ca_digest = _tls_context(ca_file)
        identity = configure_client_identity(context, cert_file=client_cert_file, key_file=client_key_file,
                                             password_file=client_key_password_file,
                                             expected_certificate_sha256=expected_client_certificate_sha256)
    except (PolicyUpdateError, OSError, ValueError, TypeError) as exc:
        code = exc.code if isinstance(exc, PolicyUpdateError) else "policy_delivery_config_invalid"
        raise PolicyDeliveryError(code, "local delivery configuration or governed store is invalid") from exc
    raw, receipt = _fetch(url, endpoint, seconds, context, ca_digest)
    receipt["client_identity"] = identity
    try:
        bundle = validate_delivery_bundle(_json(raw, MAX_DELIVERY_BYTES))
        accepted = governance.accept_governed_chain(path, anchor, bundle["signed_policy"], bundle["rotations"],
                                                    minimum_revision=minimum_revision, minimum_root_version=minimum_root_version)
    except (PolicyUpdateError, OSError, ValueError, TypeError) as exc:
        code = exc.code if isinstance(exc, PolicyUpdateError) else "policy_delivery_acceptance_failed"
        raise PolicyDeliveryError(code, "downloaded update was not accepted; the transaction made no policy or root changes",
                                  network_attempted=True) from exc
    return dict(accepted, schema=DELIVERY_REPORT_SCHEMA, delivery=dict(receipt, bundle_sha256=sha256_object(bundle)),
                network_performed=True, latest_available_proven=False, historical_delivery_time_proven=False)
