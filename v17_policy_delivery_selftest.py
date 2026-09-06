#!/usr/bin/env python3
"""Synthetic HTTPS delivery, atomic activation, and subsequent offline verification.

The test CA and private keys exist only in a temporary directory. The server
binds loopback and does not require a public endpoint or deployed service.
"""
from __future__ import annotations

import copy
import ipaddress
import json
import socket
import ssl
import tempfile
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from case_export_v17 import verify_case
from v17_integrity import canonical_json_bytes
from v17_key_policy_selftest import synthetic_export
from v17_policy_delivery import PolicyDeliveryError, prepare_delivery_bundle, sync_policy
from v17_policy_governance import initialize_governed_store
from v17_policy_governance_selftest import synthetic_governance


def synthetic_tls_material(path: Path, *, wrong_host=False, expired=False) -> dict:
    path.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    ca_key, server_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic AI-DFIR Delivery CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=3))
          .not_valid_after(now + timedelta(days=2)).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                     data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                                     encipher_only=None, decipher_only=None), critical=True).sign(ca_key, hashes.SHA256()))
    names = [x509.DNSName("wrong-host.invalid")] if wrong_host else [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    server = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic delivery server")]))
              .issuer_name(ca_name).public_key(server_key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now - timedelta(days=2)).not_valid_after(now + timedelta(days=-1 if expired else 1))
              .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
              .add_extension(x509.SubjectAlternativeName(names), critical=False)
              .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False).sign(ca_key, hashes.SHA256()))
    files = {name: path / name for name in ("ca.pem", "server.pem", "server-key.pem")}
    files["ca.pem"].write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    files["server.pem"].write_bytes(server.public_bytes(serialization.Encoding.PEM))
    files["server-key.pem"].write_bytes(server_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                              serialization.NoEncryption()))
    files["server-key.pem"].chmod(0o600)
    return files


@contextmanager
def synthetic_https(path: Path, body: bytes, *, status=200, headers=None, responder=None, wrong_host=False, expired=False):
    material = synthetic_tls_material(path, wrong_host=wrong_host, expired=expired)

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_GET(self):
            self.server.requests.append({"path": self.path, "headers": dict(self.headers)})
            try:
                if responder is not None:
                    responder(self)
                    return
                self.send_response(status)
                actual = headers if headers is not None else [("Content-Type", "application/json"), ("Content-Length", str(len(self.server.body)))]
                for name, value in actual:
                    self.send_header(name, value)
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(self.server.body)
            except OSError:
                pass  # A timeout or rejection intentionally closes the client.
            finally:
                self.close_connection = True

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(material["server.pem"], material["server-key.pem"])
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.body, server.requests = body, []
    server.url = f"https://127.0.0.1:{server.server_port}/policy.json"
    server.ca_file = material["ca.pem"]
    thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ai-dfir-policy-delivery-") as temporary:
        path = Path(temporary)
        case = synthetic_export(path)
        fixture = synthetic_governance(case, path / "governed.sqlite")
        initialize_governed_store(fixture["path"], fixture["anchor"], fixture["initial"]["envelope"])
        bundle = prepare_delivery_bundle(fixture["anchor"], fixture["policy"], [fixture["rotation"]])
        with synthetic_https(path / "tls", canonical_json_bytes(bundle)) as server:
            accepted = sync_policy(fixture["path"], fixture["anchor"], server.url, ca_file=server.ca_file)
            assert accepted["status"] == "ACCEPTED" and accepted["delivery"]["http_requests"] == 1
            assert sync_policy(fixture["path"], fixture["anchor"], server.url, ca_file=server.ca_file)["status"] == "UNCHANGED"
            before = fixture["path"].read_bytes()
            bad = copy.deepcopy(bundle)
            bad["signed_policy"]["signatures"][0]["signature_hex"] = "00" * 64
            server.body = canonical_json_bytes(bad)
            try:
                sync_policy(fixture["path"], fixture["anchor"], server.url, ca_file=server.ca_file)
            except PolicyDeliveryError as exc:
                assert exc.network_attempted
            else:
                raise AssertionError("invalid downloaded policy was accepted")
            assert fixture["path"].read_bytes() == before
        with patch.object(socket.socket, "connect", side_effect=AssertionError("verification attempted network")):
            result = verify_case(case["package"], case["public"], checkpoint_policy_store=fixture["path"],
                                 policy_root_anchor=fixture["anchor"], require_authenticated_key_policy=True,
                                 minimum_policy_revision=2, minimum_root_version=2, include_reconstruction=True)
            assert result["valid"] and result["reconstruction"]
            assert not result["checkpoint_key_policy"]["authentication"]["network_performed"]
    print(json.dumps({"status": "PASS", "synthetic_https_only": True, "atomic_update": True,
                      "invalid_download_rejected": True, "offline_verification_preserved": True}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
