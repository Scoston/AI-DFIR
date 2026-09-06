from __future__ import annotations

import json
import os
import socket
import ssl
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

import v17_delivery_identity as identity
from case_export_v17 import verify_case
from v17_delivery_identity import configure_client_identity
from v17_delivery_identity_selftest import synthetic_client_identity
from v17_integrity import canonical_json_bytes, sha256_bytes
from v17_key_policy_selftest import synthetic_export
from v17_policy_delivery import PolicyDeliveryError, _tls_context, prepare_delivery_bundle, sync_policy
from v17_policy_delivery_selftest import synthetic_https
from v17_policy_distribution import PolicyUpdateError
from v17_policy_governance import initialize_governed_store, load_governed_store
from v17_policy_governance_selftest import synthetic_governance

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def client(tmp_path):
    return synthetic_client_identity(tmp_path / "client", encrypted=True)


@pytest.fixture
def fixture(tmp_path):
    case = synthetic_export(tmp_path)
    fixture = synthetic_governance(case, tmp_path / "governed.sqlite")
    fixture["case"] = case
    initialize_governed_store(fixture["path"], fixture["anchor"], fixture["initial"]["envelope"])
    fixture["body"] = canonical_json_bytes(prepare_delivery_bundle(fixture["anchor"], fixture["policy"], [fixture["rotation"]]))
    return fixture


def configure(client, context=None, **changes):
    options = client["options"]
    settings = {"cert_file": options["client_cert_file"], "key_file": options["client_key_file"],
                "password_file": options["client_key_password_file"], "expected_certificate_sha256": options["expected_client_certificate_sha256"]}
    return configure_client_identity(context or _tls_context(None)[0], **dict(settings, **changes))


def sync(fixture, server, **options):
    return sync_policy(fixture["path"], fixture["anchor"], server.url, ca_file=server.ca_file, **options)


def test_mutual_tls_uses_exact_client_identity_then_verifies_offline(fixture, client, tmp_path, monkeypatch):
    with synthetic_https(tmp_path / "server", fixture["body"], client_ca_file=client["files"]["ca.pem"]) as server:
        result = sync(fixture, server, **client["options"])
        receipt = result["delivery"]["client_identity"]
        assert result["status"] == "ACCEPTED" and receipt["status"] == "CONFIGURED"
        assert receipt["certificate_sha256"] == server.requests[0]["client_certificate_sha256"] == client["options"]["expected_client_certificate_sha256"]
        assert receipt["certificate_chain_sha256"] == sha256_bytes(client["files"]["client.pem"].read_bytes())
        assert receipt["certificate_count"] == 2 and receipt["not_valid_after"].endswith("Z")
        assert not receipt["peer_client_authentication_proven"] and not receipt["policy_authority_granted"]
        assert result["authentication"]["issuer_root"]["root_version"] == 2
    monkeypatch.setattr(socket.socket, "connect", lambda *args: pytest.fail("offline verifier attempted network"))
    case = fixture["case"]
    verified = verify_case(case["package"], case["public"], checkpoint_policy_store=fixture["path"],
                           policy_root_anchor=fixture["anchor"], include_reconstruction=True)
    assert verified["valid"] and verified["reconstruction"]


@pytest.mark.parametrize("credential", ["missing", "untrusted"])
def test_rejected_client_never_receives_metadata_or_changes_store(fixture, client, tmp_path, credential):
    before = fixture["path"].read_bytes()
    other = synthetic_client_identity(tmp_path / "other")
    with synthetic_https(tmp_path / "server", fixture["body"], client_ca_file=client["files"]["ca.pem"]) as server:
        with pytest.raises(PolicyDeliveryError) as error:
            sync(fixture, server, **({} if credential == "missing" else other["options"]))
        assert error.value.network_attempted and error.value.code in {"policy_delivery_tls", "policy_delivery_network"}
        assert not server.requests
    assert fixture["path"].read_bytes() == before


def test_configured_identity_does_not_claim_peer_authentication(fixture, client, tmp_path):
    # A server that never requests a certificate can still return HTTP 200.
    with synthetic_https(tmp_path / "server", fixture["body"]) as server:
        result = sync(fixture, server, **client["options"])
        assert server.requests[0]["client_certificate_sha256"] is None
        assert result["delivery"]["client_identity"]["status"] == "CONFIGURED"
        assert result["delivery"]["client_identity"]["peer_client_authentication_proven"] is False


def test_ordinary_https_remains_optional_and_configures_no_identity(fixture, tmp_path):
    with synthetic_https(tmp_path / "server", fixture["body"]) as server:
        result = sync(fixture, server)
        assert result["delivery"]["client_identity"] == identity.identity_report()


@pytest.mark.parametrize("failure", ["signature", "rollback", "floor", "scope"])
def test_transport_identity_never_replaces_policy_authority(fixture, client, tmp_path, failure):
    with synthetic_https(tmp_path / "server", fixture["body"], client_ca_file=client["files"]["ca.pem"]) as server:
        assert sync(fixture, server, **client["options"])["status"] == "ACCEPTED"
        before = fixture["path"].read_bytes()
        value = json.loads(fixture["body"])
        options = dict(client["options"])
        if failure == "signature":
            value["signed_policy"]["signatures"][0]["signature_hex"] = "00" * 64
        elif failure == "rollback":
            value = prepare_delivery_bundle(fixture["anchor"], fixture["initial"]["envelope"], [])
        elif failure == "scope":
            value["signed_policy"]["policy"]["tenant_id"] = "ANOTHER-TENANT"
        else:
            options["minimum_revision"] = 3
        server.body = canonical_json_bytes(value)
        with pytest.raises(PolicyDeliveryError) as error:
            sync(fixture, server, **options)
        assert error.value.network_attempted and len(server.requests) == 2
        assert fixture["path"].read_bytes() == before


@pytest.mark.parametrize("tls_problem", ["wrong-host", "expired", "untrusted-ca"])
def test_client_credentials_never_disable_server_authentication(fixture, client, tmp_path, tls_problem):
    before = fixture["path"].read_bytes()
    with synthetic_https(tmp_path / "server", fixture["body"], client_ca_file=client["files"]["ca.pem"],
                         wrong_host=tls_problem == "wrong-host", expired=tls_problem == "expired") as server:
        ca = client["files"]["ca.pem"] if tls_problem == "untrusted-ca" else server.ca_file
        with pytest.raises(PolicyDeliveryError) as error:
            sync_policy(fixture["path"], fixture["anchor"], server.url, ca_file=ca, **client["options"])
        assert error.value.code == "policy_delivery_tls" and not server.requests
    assert fixture["path"].read_bytes() == before


def test_authenticated_redirect_does_not_forward_client_identity(fixture, client, tmp_path):
    before = fixture["path"].read_bytes()
    with synthetic_https(tmp_path / "target", fixture["body"], client_ca_file=client["files"]["ca.pem"]) as target:
        with synthetic_https(tmp_path / "server", b"", client_ca_file=client["files"]["ca.pem"], status=302,
                             headers=[("Location", target.url), ("Content-Length", "0")]) as server:
            with pytest.raises(PolicyDeliveryError) as error:
                sync(fixture, server, **client["options"])
            assert error.value.code == "policy_delivery_http_status" and len(server.requests) == 1
            assert not target.requests
    assert fixture["path"].read_bytes() == before


@pytest.mark.parametrize("missing", ["client_cert_file", "client_key_file"])
def test_partial_identity_fails_before_dns(fixture, client, monkeypatch, missing):
    options = dict(client["options"], **{missing: None})
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args: pytest.fail("preflight attempted DNS"))
    before = fixture["path"].read_bytes()
    with pytest.raises(PolicyDeliveryError) as error:
        sync_policy(fixture["path"], fixture["anchor"], "https://publisher.invalid/policy.json", **options)
    assert error.value.code == "delivery_identity_required" and not error.value.network_attempted
    assert fixture["path"].read_bytes() == before


@pytest.mark.parametrize("field", ["cert_file", "key_file", "password_file"])
@pytest.mark.parametrize("kind", ["empty-path", "missing", "directory", "symlink", "empty", "oversized"])
def test_credential_file_bounds_and_types_fail_closed(client, tmp_path, field, kind):
    path = tmp_path / "invalid-input"
    if kind == "directory":
        path.mkdir()
    elif kind == "symlink":
        path.symlink_to(client["files"]["client-key.pem"])
    elif kind in {"empty", "oversized"}:
        limit = {"cert_file": identity.MAX_CERT_CHAIN_BYTES, "key_file": identity.MAX_PRIVATE_KEY_BYTES,
                 "password_file": identity.MAX_PASSWORD_BYTES}[field]
        path.write_bytes(b"" if kind == "empty" else b"x" * (limit + 1))
        path.chmod(0o600)
    with pytest.raises(PolicyUpdateError):
        configure(client, **{field: "" if kind == "empty-path" else path})


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
@pytest.mark.parametrize("name", ["client-key.pem", "password.txt"])
@pytest.mark.parametrize("mode", [0o640, 0o604])
def test_secrets_reject_group_or_other_access(client, name, mode):
    client["files"][name].chmod(mode)
    with pytest.raises(PolicyUpdateError) as error:
        configure(client)
    assert error.value.code == "delivery_identity_permissions"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires FIFOs")
def test_special_file_cannot_block_credential_preflight(client, tmp_path):
    path = tmp_path / "pipe"
    os.mkfifo(path)
    with pytest.raises(PolicyUpdateError):
        configure(client, key_file=path)


@pytest.mark.parametrize("pin", ["", "0" * 64, "F" * 64, 1])
def test_independent_leaf_pin_is_strict(client, pin):
    with pytest.raises(PolicyUpdateError):
        configure(client, expected_certificate_sha256=pin)


@pytest.mark.parametrize("change", [
    {"expired": True}, {"future": True}, {"ca_leaf": True}, {"can_sign": False},
    {"eku": [ExtendedKeyUsageOID.SERVER_AUTH]},
    {"eku": [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]},
    {"omit_extension": "constraints"}, {"omit_extension": "usage"}, {"omit_extension": "eku"},
])
def test_certificate_must_be_current_and_restricted_to_client_auth(tmp_path, change):
    client = synthetic_client_identity(tmp_path / "client", **change)
    with pytest.raises(PolicyUpdateError):
        configure(client)


@pytest.mark.parametrize("kind", ["weak-rsa", "unsupported-curve"])
def test_weak_or_unsupported_client_keys_fail_preflight(tmp_path, kind):
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024) if kind == "weak-rsa" else ec.generate_private_key(ec.SECP256K1())
    client = synthetic_client_identity(tmp_path / "client", key=key)
    with pytest.raises(PolicyUpdateError) as error:
        configure(client)
    assert error.value.code == "delivery_identity_key_weak"


@pytest.mark.parametrize("kind", ["garbage", "extra-key", "duplicate", "too-many", "wrong-order"])
def test_certificate_chain_cannot_mix_or_hide_other_material(client, kind):
    path = client["files"]["client.pem"]
    raw = path.read_bytes()
    if kind == "garbage":
        raw += b"unparsed material"
    elif kind == "extra-key":
        raw += client["files"]["client-key.pem"].read_bytes()
    elif kind == "duplicate":
        raw += raw
    elif kind == "too-many":
        raw *= identity.MAX_CERTIFICATES
    else:
        raw = client["ca"].public_bytes(serialization.Encoding.PEM) + client["certificate"].public_bytes(serialization.Encoding.PEM)
    path.write_bytes(raw)
    with pytest.raises(PolicyUpdateError):
        configure(client)


@pytest.mark.parametrize("kind", ["missing-password", "wrong-password", "mixed-key", "traditional-format", "trailing-data"])
def test_private_key_and_password_must_match_without_interactive_prompt(client, tmp_path, kind):
    options = {}
    if kind == "missing-password":
        options["password_file"] = None
    elif kind == "wrong-password":
        client["files"]["password.txt"].write_bytes(b"synthetic-invalid-password\n")
    elif kind == "mixed-key":
        other = synthetic_client_identity(tmp_path / "other")
        options.update(key_file=other["files"]["client-key.pem"], password_file=None)
    elif kind == "traditional-format":
        client["files"]["client-key.pem"].write_bytes(client["key"].private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
        options["password_file"] = None
    else:
        with client["files"]["client-key.pem"].open("ab") as stream:
            stream.write(b"extra-material")
    with pytest.raises(PolicyUpdateError):
        configure(client, **options)


@pytest.mark.parametrize("password", [b"\n", b"two\nlines", b"nul\x00value", b"two\rvalues"])
def test_password_file_is_one_nonempty_line(client, password):
    client["files"]["password.txt"].write_bytes(password)
    with pytest.raises(PolicyUpdateError):
        configure(client)


def test_lf_crlf_and_unencrypted_credentials_are_supported(client, tmp_path):
    assert configure(client)["status"] == "CONFIGURED"
    path = client["files"]["password.txt"]
    path.write_bytes(path.read_bytes().rstrip(b"\n") + b"\r\n")
    assert configure(client)["status"] == "CONFIGURED"
    plain = synthetic_client_identity(tmp_path / "plain")
    assert configure(plain)["status"] == "CONFIGURED"


@pytest.mark.parametrize("failure", [False, True])
def test_tls_load_uses_private_snapshots_and_cleans_up_on_failure(client, monkeypatch, failure):
    original = ssl.SSLContext.load_cert_chain
    saved_paths = []
    expected_chain = client["files"]["client.pem"].read_bytes()
    expected_key = client["files"]["client-key.pem"].read_bytes()
    def load(context, certfile, keyfile, password):
        saved_paths.extend((Path(certfile), Path(keyfile)))
        assert Path(certfile).read_bytes() == expected_chain and Path(keyfile).read_bytes() == expected_key
        assert stat.S_IMODE(Path(keyfile).stat().st_mode) == 0o600
        assert stat.S_IMODE(Path(keyfile).parent.stat().st_mode) == 0o700
        client["files"]["client.pem"].write_bytes(b"replaced original")
        client["files"]["client-key.pem"].write_bytes(b"replaced original")
        if failure:
            raise ssl.SSLError("sensitive backend details must not be reported")
        return original(context, certfile, keyfile, password=password)
    monkeypatch.setattr(ssl.SSLContext, "load_cert_chain", load)
    if failure:
        with pytest.raises(PolicyUpdateError) as error:
            configure(client)
        assert "sensitive backend" not in str(error.value)
    else:
        assert configure(client)["status"] == "CONFIGURED"
    assert saved_paths and all(not path.exists() and not path.parent.exists() for path in saved_paths)


def test_tls_secrets_and_credentials_never_appear_in_receipts(fixture, client, tmp_path, monkeypatch):
    key_log = tmp_path / "unexpected-key-log"
    monkeypatch.setenv("SSLKEYLOGFILE", str(key_log))
    monkeypatch.setenv("HTTPS_PROXY", "http://credential-bearing-proxy.invalid:3128")
    with synthetic_https(tmp_path / "server", fixture["body"], client_ca_file=client["files"]["ca.pem"]) as server:
        result = sync(fixture, server, **client["options"])
        rendered = json.dumps(result)
        for name in ("client-key.pem", "password.txt"):
            assert str(client["files"][name]) not in rendered
            assert client["files"][name].read_text().strip() not in rendered
        assert "Authorization" not in server.requests[0]["headers"]
        assert "Cookie" not in server.requests[0]["headers"]
    assert not key_log.exists() or all(not line or line.startswith("#") for line in key_log.read_text().splitlines())


def test_loader_refuses_context_without_server_hostname_verification(client):
    context = _tls_context(None)[0]
    context.check_hostname = False
    with pytest.raises(PolicyUpdateError) as error:
        configure(client, context=context)
    assert error.value.code == "delivery_identity_tls_unsafe"


def cli(fixture, server, anchor, *extra):
    return subprocess.run([sys.executable, str(ROOT / "checkpoint_delivery_v17.py"), "sync", "--store", str(fixture["path"]),
        "--anchor", str(anchor), "--url", server.url, "--ca-file", str(server.ca_file), *map(str, extra)],
        capture_output=True, text=True, timeout=20)


def test_cli_success_and_failure_redact_private_material(fixture, client, tmp_path):
    anchor = tmp_path / "anchor.json"
    anchor.write_bytes(canonical_json_bytes(fixture["anchor"]))
    files = client["files"]
    args = ["--client-cert-file", files["client.pem"], "--client-key-file", files["client-key.pem"],
            "--client-key-password-file", files["password.txt"], "--expected-client-certificate-sha256", client["options"]["expected_client_certificate_sha256"]]
    with synthetic_https(tmp_path / "server", fixture["body"], client_ca_file=files["ca.pem"]) as server:
        good = cli(fixture, server, anchor, *args)
        assert good.returncode == 0, good.stdout + good.stderr
        assert json.loads(good.stdout)["delivery"]["client_identity"]["status"] == "CONFIGURED"
        before = fixture["path"].read_bytes()
        secret = files["password.txt"].read_text().strip()
        bad = cli(fixture, server, anchor, *args, "--expected-client-certificate-sha256", "0" * 64)
        result = json.loads(bad.stdout)
        assert bad.returncode == 1 and result["code"] == "delivery_identity_pin_mismatch" and not result["network_attempted"]
        assert secret not in bad.stdout + bad.stderr and str(files["client-key.pem"]) not in bad.stdout + bad.stderr
        assert fixture["path"].read_bytes() == before and len(server.requests) == 1


@pytest.mark.parametrize("flag", ["--client-cert-file", "--client-key-file", "--client-key-password-file", "--expected-client-certificate-sha256"])
def test_cli_empty_explicit_identity_does_not_fall_back_to_anonymous(fixture, tmp_path, flag):
    anchor = tmp_path / "anchor.json"
    anchor.write_bytes(canonical_json_bytes(fixture["anchor"]))
    with synthetic_https(tmp_path / "server", fixture["body"]) as server:
        result = cli(fixture, server, anchor, flag, "")
        assert result.returncode == 1 and not json.loads(result.stdout)["network_attempted"] and not server.requests


def test_current_store_remains_unchanged_on_credential_error(fixture, client):
    original = load_governed_store(fixture["path"], fixture["anchor"])
    before = fixture["path"].read_bytes()
    with pytest.raises(PolicyDeliveryError):
        sync_policy(fixture["path"], fixture["anchor"], "https://publisher.invalid/policy.json", **dict(client["options"], client_key_file=""))
    current = load_governed_store(fixture["path"], fixture["anchor"])
    assert all(current[key] == original[key] for key in ("root", "policy", "envelope"))
    assert fixture["path"].read_bytes() == before


@pytest.mark.parametrize("kind", ["certificate", "key"])
def test_large_whitespace_without_pem_footer_is_rejected_promptly(client, kind):
    name, limit, label = (("client.pem", identity.MAX_CERT_CHAIN_BYTES, "CERTIFICATE") if kind == "certificate"
                         else ("client-key.pem", identity.MAX_PRIVATE_KEY_BYTES, "PRIVATE KEY"))
    prefix = ("-----BEGIN " + label + "-----\n").encode("ascii")
    client["files"][name].write_bytes(prefix + b" " * (limit - len(prefix) - 1) + b"!")
    program = """import ssl, sys
from v17_delivery_identity import configure_client_identity
from v17_policy_distribution import PolicyUpdateError
try:
    configure_client_identity(ssl.create_default_context(), cert_file=sys.argv[1], key_file=sys.argv[2], password_file=sys.argv[3])
except PolicyUpdateError:
    raise SystemExit(0)
raise SystemExit('malformed PEM accepted')
"""
    result = subprocess.run([sys.executable, "-c", program, str(client["files"]["client.pem"]),
                             str(client["files"]["client-key.pem"]), str(client["files"]["password.txt"])],
                            cwd=ROOT, capture_output=True, text=True, timeout=5)
    assert result.returncode == 0, result.stdout + result.stderr
