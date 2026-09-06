#!/usr/bin/env python3
"""Synthetic mutual TLS, signed update acceptance, and offline verification."""
from __future__ import annotations

import copy
import json
import secrets
import socket
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from case_export_v17 import verify_case
from v17_integrity import canonical_json_bytes
from v17_key_policy_selftest import synthetic_export
from v17_policy_delivery import PolicyDeliveryError, prepare_delivery_bundle, sync_policy
from v17_policy_delivery_selftest import synthetic_https
from v17_policy_governance import initialize_governed_store
from v17_policy_governance_selftest import synthetic_governance


def synthetic_client_identity(path: Path, *, encrypted=False, expired=False, future=False, eku=None,
                              ca_leaf=False, can_sign=True, key=None, omit_extension=None) -> dict:
    """Ephemeral client identity; never an operational credential or issuer key."""
    path.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    key = key or ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic AI-DFIR Client CA")])
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=3)).not_valid_after(now + timedelta(days=3))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    builder = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic verifier client")]))
               .issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now + timedelta(days=1) if future else now - timedelta(days=2))
               .not_valid_after(now - timedelta(days=1) if expired else now + timedelta(days=2)))
    for label, extension, critical in (
        ("constraints", x509.BasicConstraints(ca=ca_leaf, path_length=None), True),
        ("usage", x509.KeyUsage(can_sign, False, False, False, False, ca_leaf, ca_leaf, None, None), True),
        ("eku", x509.ExtendedKeyUsage(eku if eku is not None else [ExtendedKeyUsageOID.CLIENT_AUTH]), False),
        ("ski", x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False),
        ("aki", x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False),
    ):
        if label != omit_extension:
            builder = builder.add_extension(extension, critical=critical)
    leaf = builder.sign(ca_key, hashes.SHA256())
    files = {name: path / name for name in ("ca.pem", "client.pem", "client-key.pem", "password.txt")}
    files["ca.pem"].write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    files["client.pem"].write_bytes(leaf.public_bytes(serialization.Encoding.PEM) + ca.public_bytes(serialization.Encoding.PEM))
    password = secrets.token_urlsafe(24).encode("ascii") if encrypted else None
    algorithm = serialization.BestAvailableEncryption(password) if encrypted else serialization.NoEncryption()
    files["client-key.pem"].write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, algorithm))
    files["client-key.pem"].chmod(0o600)
    if encrypted:
        files["password.txt"].write_bytes(password + b"\n")
        files["password.txt"].chmod(0o600)
    options = {"client_cert_file": files["client.pem"], "client_key_file": files["client-key.pem"],
               "client_key_password_file": files["password.txt"] if encrypted else None,
               "expected_client_certificate_sha256": leaf.fingerprint(hashes.SHA256()).hex()}
    return {"files": files, "options": options, "certificate": leaf, "ca": ca, "ca_key": ca_key, "key": key}


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ai-dfir-mtls-selftest-") as temporary:
        root = Path(temporary)
        case = synthetic_export(root)
        fixture = synthetic_governance(case, root / "governed.sqlite")
        initialize_governed_store(fixture["path"], fixture["anchor"], fixture["initial"]["envelope"])
        bundle = prepare_delivery_bundle(fixture["anchor"], fixture["policy"], [fixture["rotation"]])
        client = synthetic_client_identity(root / "client", encrypted=True)
        with synthetic_https(root / "server", canonical_json_bytes(bundle), client_ca_file=client["files"]["ca.pem"]) as server:
            before = fixture["path"].read_bytes()
            try:
                sync_policy(fixture["path"], fixture["anchor"], server.url, ca_file=server.ca_file)
            except PolicyDeliveryError as exc:
                assert exc.network_attempted
            else:
                raise AssertionError("publisher accepted a client without a certificate")
            assert not server.requests and fixture["path"].read_bytes() == before
            accepted = sync_policy(fixture["path"], fixture["anchor"], server.url, ca_file=server.ca_file, **client["options"])
            assert accepted["status"] == "ACCEPTED"
            identity = accepted["delivery"]["client_identity"]
            assert identity["certificate_sha256"] == server.requests[0]["client_certificate_sha256"]
            assert not identity["peer_client_authentication_proven"] and not identity["policy_authority_granted"]
            before = fixture["path"].read_bytes()
            bad = copy.deepcopy(bundle)
            bad["signed_policy"]["signatures"][0]["signature_hex"] = "00" * 64
            server.body = canonical_json_bytes(bad)
            try:
                sync_policy(fixture["path"], fixture["anchor"], server.url, ca_file=server.ca_file, **client["options"])
            except PolicyDeliveryError:
                pass
            else:
                raise AssertionError("client TLS identity supplied policy authority")
            assert fixture["path"].read_bytes() == before
        with patch.object(socket.socket, "connect", side_effect=AssertionError("offline verification attempted network")):
            assert verify_case(case["package"], case["public"], checkpoint_policy_store=fixture["path"],
                               policy_root_anchor=fixture["anchor"], include_reconstruction=True)["valid"]
    print(json.dumps({"status": "PASS", "synthetic_mutual_tls_only": True, "anonymous_client_rejected": True,
                      "encrypted_client_key": True, "policy_authority_independent": True, "offline_verification_preserved": True}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
