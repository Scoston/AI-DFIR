"""Explicit, bounded client credentials for HTTPS policy delivery only.

Local credential validation does not prove that a peer requested a certificate
or authorized the client. TLS identity never grants checkpoint-policy authority.
"""
from __future__ import annotations

import os
import re
import ssl
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from v17_integrity import sha256_bytes
from v17_policy_distribution import PolicyUpdateError, _HEX, _require

IDENTITY_SCHEMA = "ai-dfir/policy-delivery-client-identity/v1.7"
MAX_CERT_CHAIN_BYTES = 256 * 1024
MAX_PRIVATE_KEY_BYTES = 64 * 1024
MAX_PASSWORD_BYTES = 4096
MAX_CERTIFICATES = 16
# The first base64 character cannot be whitespace. Disjoint leading whitespace
# and body avoid quadratic backtracking on a missing footer after long padding.
_CERT = re.compile(rb"-----BEGIN CERTIFICATE-----[ \t\r\n]+[A-Za-z0-9+/=][A-Za-z0-9+/= \t\r\n]*-----END CERTIFICATE-----")
_KEY = re.compile(rb"-----BEGIN (PRIVATE KEY|ENCRYPTED PRIVATE KEY)-----[ \t\r\n]+[A-Za-z0-9+/=][A-Za-z0-9+/= \t\r\n]*-----END \1-----")


def identity_report() -> dict:
    return {"schema": IDENTITY_SCHEMA, "status": "NOT_CONFIGURED", "certificate_sha256": None,
            "certificate_chain_sha256": None, "certificate_count": None,
            "not_valid_before": None, "not_valid_after": None,
            "peer_client_authentication_proven": False, "policy_authority_granted": False}


def _read(path, limit: int, *, secret: bool = False) -> bytes:
    _require(isinstance(path, (str, Path)) and str(path) != "", "delivery_identity_file_invalid", "credential file path required")
    # Reject links/special files before reading, and verify the opened descriptor
    # as well. Nonblocking open prevents a replacement FIFO from hanging preflight.
    path = Path(path)
    _require(not path.is_symlink() and path.is_file(), "delivery_identity_file_invalid", "regular credential file required")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        _require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= limit,
                 "delivery_identity_file_invalid", "credential file is empty, oversized, or not regular")
        if secret and os.name == "posix":
            _require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) & 0o077 == 0,
                     "delivery_identity_permissions", "secret file must be owned by the current user with no group/other access")
        raw = stream.read(limit + 1)
    _require(0 < len(raw) <= limit, "delivery_identity_file_invalid", "credential file exceeds its bound")
    return raw


def _password(path) -> bytes | None:
    if path is None:
        return None
    raw = _read(path, MAX_PASSWORD_BYTES, secret=True)
    if raw.endswith(b"\r\n"):
        raw = raw[:-2]
    elif raw.endswith(b"\n"):
        raw = raw[:-1]
    _require(bool(raw) and not any(value in raw for value in (b"\x00", b"\r", b"\n")),
             "delivery_identity_password_invalid", "password file must contain one nonempty line without NUL")
    return raw


def _public_bytes(key) -> bytes:
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _strong_key(key) -> bool:
    return ((isinstance(key, rsa.RSAPublicKey) and key.key_size >= 2048)
            or (isinstance(key, ec.EllipticCurvePublicKey) and key.curve.name in {"secp256r1", "secp384r1", "secp521r1"})
            or isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)))


def _certificates(raw: bytes) -> list:
    blocks = _CERT.findall(raw)
    _require(0 < len(blocks) <= MAX_CERTIFICATES and not _CERT.sub(b"", raw).strip(),
             "delivery_identity_chain_invalid", "a bounded certificate-only PEM chain is required")
    certificates = [x509.load_pem_x509_certificate(block) for block in blocks]
    digests = [sha256_bytes(cert.public_bytes(serialization.Encoding.DER)) for cert in certificates]
    _require(len(set(digests)) == len(digests), "delivery_identity_chain_invalid", "duplicate certificates in client chain")
    for cert in certificates:
        _require(_strong_key(cert.public_key()), "delivery_identity_key_weak", "unsupported or weak certificate public key")
        algorithm = cert.signature_hash_algorithm
        _require(algorithm is None or algorithm.name in {"sha256", "sha384", "sha512"},
                 "delivery_identity_signature_weak", "unsupported or weak certificate signature digest")
    return certificates


def configure_client_identity(context: ssl.SSLContext, *, cert_file=None, key_file=None,
                              password_file=None, expected_certificate_sha256=None) -> dict:
    """Load a validated snapshot without exposing secrets or prompting for input."""
    report = identity_report()
    configured = any(value is not None for value in (cert_file, key_file, password_file, expected_certificate_sha256))
    if not configured:
        return report
    try:
        _require(context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
                 and context.minimum_version >= ssl.TLSVersion.TLSv1_2,
                 "delivery_identity_tls_unsafe", "client identity requires authenticated TLS 1.2 or newer")
        _require(cert_file is not None and key_file is not None, "delivery_identity_required", "both client certificate and private key files are required")
        chain, key_raw, password = _read(cert_file, MAX_CERT_CHAIN_BYTES), _read(key_file, MAX_PRIVATE_KEY_BYTES, secret=True), _password(password_file)
        certificates = _certificates(chain)
        leaf = certificates[0]
        now = datetime.now(timezone.utc)
        _require(leaf.not_valid_before_utc <= now < leaf.not_valid_after_utc,
                 "delivery_identity_not_current", "client certificate is not current at the system UTC clock")
        _require(not leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
                 and leaf.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature
                 and list(leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) == [ExtendedKeyUsageOID.CLIENT_AUTH],
                 "delivery_identity_purpose", "a non-CA certificate restricted to TLS client authentication and digital signatures is required")
        digest = sha256_bytes(leaf.public_bytes(serialization.Encoding.DER))
        if expected_certificate_sha256 is not None:
            _require(isinstance(expected_certificate_sha256, str) and _HEX.fullmatch(expected_certificate_sha256) is not None,
                     "delivery_identity_pin_invalid", "client certificate pin must be lowercase SHA-256 of its DER bytes")
            _require(digest == expected_certificate_sha256, "delivery_identity_pin_mismatch", "client certificate differs from its independently retained pin")
        _require(_KEY.fullmatch(key_raw.strip()) is not None, "delivery_identity_key_invalid", "exactly one PKCS8 PEM private key is required")
        private = serialization.load_pem_private_key(key_raw, password=password)
        _require(_public_bytes(private.public_key()) == _public_bytes(leaf.public_key()),
                 "delivery_identity_key_mismatch", "private key does not match the client certificate")
        # OpenSSL's API reads filenames. Load our already validated bytes from a
        # private temporary directory, never reread mutable original paths.
        with tempfile.TemporaryDirectory(prefix="ai-dfir-delivery-identity-") as temporary:
            paths = [Path(temporary) / name for name in ("chain.pem", "identity.pem")]
            for path, raw in zip(paths, (chain, key_raw)):
                descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(raw)
            context.keylog_filename = None
            context.load_cert_chain(str(paths[0]), str(paths[1]), password=lambda: password or b"")
        report.update(status="CONFIGURED", certificate_sha256=digest, certificate_chain_sha256=sha256_bytes(chain),
                      certificate_count=len(certificates), not_valid_before=leaf.not_valid_before_utc.isoformat().replace("+00:00", "Z"),
                      not_valid_after=leaf.not_valid_after_utc.isoformat().replace("+00:00", "Z"))
        return report
    except PolicyUpdateError:
        raise
    except (OSError, ValueError, TypeError, AttributeError, x509.ExtensionNotFound, x509.DuplicateExtension, UnsupportedAlgorithm):
        # Backend exception text may include paths or credential material.
        raise PolicyUpdateError("delivery_identity_invalid", "client credential validation or loading failed") from None
