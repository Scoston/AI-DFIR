#!/usr/bin/env python3
"""Synthetic RFC 3161 acceptance test. No live TSA or retained private keys."""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from case_export_v17 import verify_case
from v17_integrity import sha256_bytes
from v17_key_policy_selftest import synthetic_export
from v17_provenance_selftest import CASE_ID, TENANT_ID
from v17_timestamp import prepare_timestamp_request


def synthetic_tsa(root: Path) -> dict:
    """Generate a short-lived synthetic CA/TSA, in temporary storage only."""
    root.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AI-DFIR synthetic timestamp CA")])
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AI-DFIR synthetic TSA; no independent time claim")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(days=2)).not_valid_after(now + timedelta(days=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(ca_name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, None, None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    (root / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (root / "tsa.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (root / "tsa.key").write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (root / "tsa.key").chmod(0o600)
    (root / "serial").write_text("01\n", encoding="ascii")
    # Relative paths are fixed test inputs and resolved in this temporary cwd.
    (root / "tsa.cnf").write_text("""[tsa]
default_tsa = test_tsa
[test_tsa]
serial = serial
signer_cert = tsa.pem
signer_key = tsa.key
certs = ca.pem
signer_digest = sha256
default_policy = 1.3.6.1.4.1.55555.1
other_policies = 1.3.6.1.4.1.55555.2
digests = sha256
accuracy = secs:1
ordering = yes
tsa_name = yes
ess_cert_id_chain = yes
ess_cert_id_alg = sha256
""", encoding="ascii")
    return {"root": root, "ca": ca, "ca_key": ca_key, "key": key, "cert": cert,
            "ca_pem": ca.public_bytes(serialization.Encoding.PEM),
            "pin": cert.fingerprint(hashes.SHA256()).hex()}


def synthetic_response(tsa: dict, request: bytes) -> bytes:
    root = tsa["root"]
    (root / "request.tsq").write_bytes(request)
    env = dict(os.environ, OPENSSL_CONF=str(root / "tsa.cnf"))
    subprocess.run([shutil.which("openssl") or "openssl", "ts", "-reply", "-config", "tsa.cnf",
                    "-queryfile", "request.tsq", "-out", "response.tsr"], cwd=root, env=env,
                   stdin=subprocess.DEVNULL, capture_output=True, timeout=15, check=True)
    return (root / "response.tsr").read_bytes()


def timestamp_fixture(case: dict, tsa: dict) -> dict:
    request = prepare_timestamp_request(signed_checkpoint=case["signed"], tenant_id=TENANT_ID,
                                        case_id=CASE_ID, tsa_policy_oid="1.3.6.1.4.1.55555.1")
    return {"timestamp_request": request, "timestamp_response": synthetic_response(tsa, request),
            "tsa_ca_pem": tsa["ca_pem"], "expected_tsa_certificate_sha256": tsa["pin"],
            "expected_timestamp_request_sha256": sha256_bytes(request), "require_checkpoint_timestamp": True}


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ai-dfir-tsa-selftest-") as temporary:
        root = Path(temporary)
        with patch.object(socket.socket, "connect", side_effect=AssertionError("network forbidden")):
            case = synthetic_export(root)
            tsa = synthetic_tsa(root / "tsa")
            options = timestamp_fixture(case, tsa)
            accepted = verify_case(case["package"], case["public"], include_reconstruction=True,
                                   replay_transforms=True, **options)
            assert accepted["valid"], accepted
            assert accepted["checkpoint_timestamp"]["checkpoint_existence_attested"]
            assert accepted["reconstruction"]["deterministic_replay"]["status"] == "PASS"
            other_request = prepare_timestamp_request(signed_checkpoint=case["signed"],
                                                      tenant_id=TENANT_ID, case_id=CASE_ID)
            options["timestamp_response"] = synthetic_response(tsa, other_request)
            denied = verify_case(case["package"], case["public"], include_reconstruction=True, **options)
            assert not denied["valid"] and denied["signature_valid"] and denied["signer_trusted"]
            assert "reconstruction" not in denied
            assert denied["checkpoint_timestamp"]["findings"][0]["code"] == "timestamp_nonce_mismatch"
    print(json.dumps({"status": "PASS", "offline": True, "synthetic_tsa_only": True,
                      "request_replay_rejected": True, "reconstruction_blocked": True}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
