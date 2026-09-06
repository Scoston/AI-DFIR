from __future__ import annotations

import copy
import json
import socket
import sqlite3
import ssl
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier

import pytest

import v17_policy_delivery as delivery
import v17_policy_governance as governance
from case_export_v17 import verify_case
from v17_integrity import canonical_json_bytes, sha256_bytes, sha256_object
from v17_key_policy_selftest import synthetic_export
from v17_policy_delivery import BUNDLE_SCHEMA, MAX_DELIVERY_BYTES, PolicyDeliveryError, prepare_delivery_bundle, sync_policy
from v17_policy_delivery_selftest import synthetic_https
from v17_policy_distribution import PolicyUpdateError, accept_policy_update
from v17_policy_governance import accept_governed_chain, accept_governed_update, initialize_governed_store, load_governed_store
from v17_policy_governance_selftest import approved_policy, approved_rotation, root_fixture, synthetic_governance
from v17_policy_quorum_selftest import synthetic_quorum

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def fixture(tmp_path):
    case = synthetic_export(tmp_path)
    value = synthetic_governance(case, tmp_path / "governed.sqlite")
    value["case"] = case
    initialize_governed_store(value["path"], value["anchor"], value["initial"]["envelope"])
    return value


def bundle(f):
    return prepare_delivery_bundle(f["anchor"], f["policy"], [f["rotation"]])


def sync(f, server, **kwargs):
    return sync_policy(f["path"], f["anchor"], server.url, ca_file=server.ca_file, **kwargs)


def state(f):
    return load_governed_store(f["path"], f["anchor"])


def third_generation(f):
    third = synthetic_quorum(f["case"], f["path"])
    root = root_fixture(third["trust"], 3, issued_at=f["anchor"]["issued_at"])
    rotation = approved_rotation(f["root"], root, f["replacement"]["keys"][:2], third["keys"][:2])
    policy = approved_policy(dict(third["policy"], revision=3), third["keys"][:2], third["trust"])
    return prepare_delivery_bundle(f["anchor"], policy, [f["rotation"], rotation])


def write_json(path, value):
    path.write_bytes(canonical_json_bytes(value))
    return path


def cli(*args):
    return subprocess.run([sys.executable, str(ROOT / "checkpoint_delivery_v17.py"), *map(str, args)],
                          cwd=ROOT, capture_output=True, text=True, timeout=20)


def test_https_update_records_transport_and_preserves_offline_case_verification(fixture, tmp_path, monkeypatch):
    raw = canonical_json_bytes(bundle(fixture))
    with synthetic_https(tmp_path / "tls", raw) as server:
        assert server.socket.context.minimum_version >= ssl.TLSVersion.TLSv1_2
        result = sync(fixture, server)
        assert result["status"] == "ACCEPTED" and result["network_performed"]
        receipt = result["delivery"]
        assert receipt["response_sha256"] == sha256_bytes(raw) and receipt["response_bytes"] == len(raw)
        assert receipt["bundle_sha256"] == sha256_object(json.loads(raw))
        assert receipt["tls_ca_file_sha256"] == sha256_bytes(server.ca_file.read_bytes())
        assert receipt["tls_trust_source"] == "operator-ca-file" and receipt["tls_version"] in {"TLSv1.2", "TLSv1.3"}
        assert len(receipt["tls_peer_certificate_sha256"]) == 64
        assert receipt["http_requests"] == 1 and receipt["redirects_followed"] == 0
        assert server.requests[0]["path"] == "/policy.json"
        assert "Authorization" not in server.requests[0]["headers"] and "Cookie" not in server.requests[0]["headers"]
        assert not result["latest_available_proven"] and not result["historical_delivery_time_proven"]
        assert not result["authentication"]["network_performed"]
    monkeypatch.setattr(socket.socket, "connect", lambda *a, **k: pytest.fail("offline verification attempted network"))
    result = verify_case(fixture["case"]["package"], fixture["case"]["public"], checkpoint_policy_store=fixture["path"],
                         policy_root_anchor=fixture["anchor"], minimum_policy_revision=2, minimum_root_version=2,
                         require_authenticated_key_policy=True, include_reconstruction=True)
    assert result["valid"] and result["reconstruction"]


def test_exact_delivery_retry_preserves_acceptance_times_and_store(fixture, tmp_path):
    with synthetic_https(tmp_path / "tls", canonical_json_bytes(bundle(fixture))) as server:
        first = sync(fixture, server)
        before = fixture["path"].read_bytes()
        second = sync(fixture, server)
    assert second["status"] == "UNCHANGED" and fixture["path"].read_bytes() == before
    assert second["authentication"]["accepted_at"] == first["authentication"]["accepted_at"]
    assert second["authentication"]["issuer_root"]["root_accepted_at"] == first["authentication"]["issuer_root"]["root_accepted_at"]


def test_policy_only_delivery_with_empty_chain(fixture, tmp_path):
    first = fixture["initial"]
    policy = approved_policy(dict(first["policy"], revision=7), first["keys"][:2], first["trust"])
    value = prepare_delivery_bundle(fixture["anchor"], policy, [])
    with synthetic_https(tmp_path / "tls", canonical_json_bytes(value)) as server:
        assert sync(fixture, server)["status"] == "ACCEPTED"
    assert state(fixture)["root"]["version"] == 1 and state(fixture)["policy"]["revision"] == 7


def test_catchup_across_two_rotations_installs_only_final_policy(fixture, tmp_path, monkeypatch):
    value = third_generation(fixture)
    revisions = []
    original = governance._write_policy

    def record(connection, authenticated):
        revisions.append(authenticated["policy"]["revision"])
        return original(connection, authenticated)

    monkeypatch.setattr(governance, "_write_policy", record)
    with synthetic_https(tmp_path / "tls", canonical_json_bytes(value)) as server:
        sync(fixture, server, minimum_revision=3, minimum_root_version=3)
    assert revisions == [3] and state(fixture)["root"]["version"] == 3
    assert state(fixture)["authentication"]["issuer_root"]["rotations_verified"] == 2


def test_full_chain_can_extend_current_prefix_or_carry_newer_same_root_policy(fixture, tmp_path):
    accept_governed_update(fixture["path"], fixture["anchor"], fixture["policy"], rotation=fixture["rotation"])
    original_time = state(fixture)["authentication"]["issuer_root"]["root_accepted_at"]
    q = fixture["replacement"]
    value = prepare_delivery_bundle(fixture["anchor"], approved_policy(dict(q["policy"], revision=3), q["keys"][:2], q["trust"]), [fixture["rotation"]])
    with synthetic_https(tmp_path / "tls", canonical_json_bytes(value)) as server:
        assert sync(fixture, server)["status"] == "ACCEPTED"
        assert state(fixture)["authentication"]["issuer_root"]["root_accepted_at"] == original_time
        third = third_generation(fixture)
        # The root change still needs a policy above the now retained revision.
        server.body = canonical_json_bytes(third)
        with pytest.raises(PolicyDeliveryError, match="not accepted"):
            sync(fixture, server)


def test_expired_intermediate_root_does_not_block_current_successor(fixture, tmp_path):
    fixture["root"]["expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    fixture["rotation"] = approved_rotation(fixture["anchor"], fixture["root"], fixture["initial"]["keys"][:2], fixture["replacement"]["keys"][:2])
    value = third_generation(fixture)
    with synthetic_https(tmp_path / "tls", canonical_json_bytes(value)) as server:
        assert sync(fixture, server)["status"] == "ACCEPTED"
    assert state(fixture)["root"]["version"] == 3


@pytest.mark.parametrize("expired_part", ["root", "policy"])
def test_expired_local_state_can_recover_without_resetting_history(fixture, tmp_path, expired_part):
    real = governance.datetime

    # Authenticate local signatures without requiring local freshness, then
    # accept a separately current replacement at the actual system clock.
    if expired_part == "root":
        fixture["anchor"]["expires_at"] = (real.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        fixture["rotation"] = approved_rotation(fixture["anchor"], fixture["root"], fixture["initial"]["keys"][:2], fixture["replacement"]["keys"][:2])
        with sqlite3.connect(fixture["path"]) as connection:
            digest = sha256_object(fixture["anchor"])
            connection.execute("UPDATE issuer_governance SET anchor_sha256=?,root_sha256=?", (digest, digest))
    else:
        old = fixture["initial"]
        policy = dict(old["policy"], expires_at=(real.now(timezone.utc) - timedelta(minutes=1)).isoformat())
        expired = approved_policy(policy, old["keys"][:2], old["trust"])
        with sqlite3.connect(fixture["path"]) as connection:
            connection.execute("UPDATE checkpoint_policy SET policy_sha256=?,envelope_sha256=?,envelope_json=?",
                               (sha256_object(policy), sha256_object(expired), canonical_json_bytes(expired).decode()))
    with pytest.raises(PolicyUpdateError):
        state(fixture)
    with synthetic_https(tmp_path / "tls", canonical_json_bytes(bundle(fixture))) as server:
        assert sync(fixture, server)["status"] == "ACCEPTED"
    assert state(fixture)["policy"]["revision"] == 2


@pytest.mark.parametrize("damage,expected", [
    ("policy_signature", "policy_issuer_signature_invalid"),
    ("previous_quorum", "root_rotation_quorum_not_met"),
    ("replacement_quorum", "root_rotation_quorum_not_met"),
    ("predecessor", "root_rotation_predecessor_mismatch"),
    ("wrong_anchor", "root_rotation_predecessor_mismatch"),
    ("expired_policy", "signed_policy_not_current"),
    ("expired_root", "issuer_root_not_current"),
    ("future_root", "issuer_root_not_current"),
    ("low_revision", "policy_revision_conflict"),
])
def test_download_authentication_failure_preserves_existing_store(fixture, tmp_path, damage, expected):
    value = bundle(fixture)
    if damage == "policy_signature":
        value["signed_policy"]["signatures"][0]["signature_hex"] = "00" * 64
    elif damage.endswith("quorum"):
        value["rotations"][0]["signatures"][damage.split("_")[0]] = []
    elif damage == "predecessor":
        value["rotations"][0]["previous_root_sha256"] = "00" * 32
    elif damage == "wrong_anchor":
        value = bundle(synthetic_governance(fixture["case"], fixture["path"]))
    elif damage in {"expired_root", "future_root"}:
        root = copy.deepcopy(fixture["root"])
        root["expires_at" if damage == "expired_root" else "issued_at"] = (datetime.now(timezone.utc) + timedelta(minutes=-1 if damage == "expired_root" else 1)).isoformat()
        value["rotations"] = [approved_rotation(fixture["anchor"], root, fixture["initial"]["keys"][:2], fixture["replacement"]["keys"][:2])]
    else:
        q = fixture["replacement"]
        policy = dict(q["policy"], revision=1 if damage == "low_revision" else 2)
        if damage == "expired_policy":
            policy["expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        value["signed_policy"] = approved_policy(policy, q["keys"][:2], q["trust"])
    before = fixture["path"].read_bytes()
    with synthetic_https(tmp_path / "tls", canonical_json_bytes(value)) as server:
        with pytest.raises(PolicyDeliveryError) as error:
            sync(fixture, server)
        assert error.value.network_attempted and error.value.code == expected
    assert fixture["path"].read_bytes() == before


def test_older_chain_and_policy_cannot_rollback_synced_store(fixture, tmp_path):
    old = bundle(fixture)
    with synthetic_https(tmp_path / "tls", canonical_json_bytes(third_generation(fixture))) as server:
        sync(fixture, server)
        before = fixture["path"].read_bytes()
        server.body = canonical_json_bytes(old)
        with pytest.raises(PolicyDeliveryError) as error:
            sync(fixture, server)
    assert error.value.code == "root_chain_rollback" and fixture["path"].read_bytes() == before


def test_signed_alternate_chain_cannot_replace_accepted_prefix(fixture):
    accept_governed_chain(fixture["path"], fixture["anchor"], fixture["policy"], [fixture["rotation"]])
    alternate = synthetic_governance(fixture["case"], fixture["path"])
    alternate["anchor"] = fixture["anchor"]
    alternate["rotation"] = approved_rotation(fixture["anchor"], alternate["root"], fixture["initial"]["keys"][:2], alternate["replacement"]["keys"][:2])
    before = fixture["path"].read_bytes()
    with pytest.raises(PolicyUpdateError) as error:
        accept_governed_chain(fixture["path"], fixture["anchor"], alternate["policy"], [alternate["rotation"]])
    assert error.value.code == "root_chain_conflict" and fixture["path"].read_bytes() == before


@pytest.mark.parametrize("floor", ["minimum_revision", "minimum_root_version"])
def test_recovery_floor_is_checked_before_atomic_activation(fixture, tmp_path, floor):
    before = fixture["path"].read_bytes()
    with synthetic_https(tmp_path / "tls", canonical_json_bytes(bundle(fixture))) as server:
        with pytest.raises(PolicyDeliveryError) as error:
            sync(fixture, server, **{floor: 3})
    assert error.value.code == "governance_below_floor" and fixture["path"].read_bytes() == before


@pytest.mark.parametrize("floor", ["minimum_revision", "minimum_root_version"])
@pytest.mark.parametrize("value", [0, -1, True, 1.5, "2", 2**53])
def test_invalid_recovery_floor_never_contacts_endpoint(fixture, monkeypatch, floor, value):
    monkeypatch.setattr(delivery, "_fetch", lambda *a: pytest.fail("invalid local floor triggered network"))
    with pytest.raises(PolicyDeliveryError) as error:
        sync_policy(fixture["path"], fixture["anchor"], "https://updates.example/policy.json", **{floor: value})
    assert not error.value.network_attempted and error.value.code == "governance_floor_invalid"


def test_write_failure_after_both_tables_rolls_back_whole_delivery(fixture, tmp_path, monkeypatch):
    before = fixture["path"].read_bytes()
    original = governance._write_root

    def fail(*args):
        original(*args)
        raise sqlite3.OperationalError("synthetic interruption after root write")

    monkeypatch.setattr(governance, "_write_root", fail)
    with synthetic_https(tmp_path / "tls", canonical_json_bytes(third_generation(fixture))) as server:
        with pytest.raises(PolicyDeliveryError) as error:
            sync(fixture, server)
    assert error.value.code == "governance_store_write_failed" and fixture["path"].read_bytes() == before


def test_competing_online_updates_cannot_mix_root_and_policy(fixture, tmp_path, monkeypatch):
    rival = synthetic_governance(fixture["case"], fixture["path"])
    rival["anchor"] = fixture["anchor"]
    rival["rotation"] = approved_rotation(fixture["anchor"], rival["root"], fixture["initial"]["keys"][:2], rival["replacement"]["keys"][:2])
    barrier = Barrier(2)
    original = governance.accept_governed_chain

    def together(*args, **kwargs):
        barrier.wait(timeout=5)
        return original(*args, **kwargs)

    monkeypatch.setattr(governance, "accept_governed_chain", together)
    with synthetic_https(tmp_path / "tls1", canonical_json_bytes(bundle(fixture))) as first:
        with synthetic_https(tmp_path / "tls2", canonical_json_bytes(bundle(rival))) as second:
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(sync, fixture, server) for server in (first, second)]
                results = []
                for future in futures:
                    try:
                        results.append(future.result()["status"])
                    except PolicyDeliveryError as exc:
                        results.append(exc.code)
    assert sorted(results) == ["ACCEPTED", "root_chain_conflict"]
    checked = state(fixture)
    assert checked["policy"]["revision"] == checked["root"]["version"] == 2
    assert checked["authentication"]["issuer_trust_sha256"] == sha256_object(checked["root"]["issuer_trust"])


@pytest.mark.parametrize("url", [
    "http://updates.example/policy.json", "file:///tmp/policy.json", "ftp://updates.example/policy.json", "",
    " https://updates.example/policy.json", "https://updates.example/\r\nHeader:value", "https://updates.example/\tfile",
    "https://user:secret@updates.example/policy.json", "https://updates.example/policy.json?token=secret", "https://updates.example/path?",
    "https://updates.example/policy.json#fragment", "https://updates.example\\@other.example/path", "https:///no-host",
    "https://updates.example:0/path", "https://updates.example:65536/path", "https://updates.example:/path", "https://[broken/path",
    "https://updates..example/path", "https://updates.example./path", "https://-updates.example/path", "https://éxample.com/path",
    "https://updates.example/%0d%0aheader", "https://updates.example/%00", "https://updates.example/%XY", "https://updates.example/%",
    "https://[fe80::1%eth0]/path", "https://updates.example/" + "a" * 2048,
    "https://127.1/path", "https://0177.0.0.1/path", "https://0x7f000001/path", "https://updates.example//other/path",
])
def test_unsafe_or_ambiguous_url_is_rejected_before_network(fixture, monkeypatch, url):
    monkeypatch.setattr(delivery, "_fetch", lambda *a: pytest.fail("invalid URL triggered network"))
    with pytest.raises(PolicyDeliveryError) as error:
        sync_policy(fixture["path"], fixture["anchor"], url)
    assert error.value.code == "policy_delivery_url_invalid" and not error.value.network_attempted


@pytest.mark.parametrize("value", [0, -1, True, "10", float("nan"), float("inf"), 61, 10**500])
def test_invalid_timeout_is_rejected_before_network(fixture, monkeypatch, value):
    monkeypatch.setattr(delivery, "_fetch", lambda *a: pytest.fail("invalid timeout triggered network"))
    with pytest.raises(PolicyDeliveryError) as error:
        sync_policy(fixture["path"], fixture["anchor"], "https://updates.example/policy.json", timeout=value)
    assert error.value.code == "policy_delivery_timeout_invalid" and not error.value.network_attempted


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308, 401, 403, 404, 500, 204, 206, 304])
def test_redirects_and_non_200_responses_are_not_followed_or_accepted(fixture, tmp_path, status):
    before = fixture["path"].read_bytes()
    headers = [("Location", "https://127.0.0.1:1/private"), ("Content-Length", "0")]
    with synthetic_https(tmp_path / "tls", b"", status=status, headers=headers) as server:
        with pytest.raises(PolicyDeliveryError) as error:
            sync(fixture, server)
        assert len(server.requests) == 1
    assert error.value.code == "policy_delivery_http_status" and fixture["path"].read_bytes() == before


@pytest.mark.parametrize("bad_headers,code", [
    ([("Content-Type", "text/html"), ("Content-Length", "2")], "policy_delivery_media_type"),
    ([("Content-Type", "application/json; charset=latin1"), ("Content-Length", "2")], "policy_delivery_media_type"),
    ([("Content-Type", "application/json"), ("Content-Type", "application/json"), ("Content-Length", "2")], "policy_delivery_headers_invalid"),
    ([("Content-Type", "application/json")], "policy_delivery_headers_invalid"),
    ([("Content-Length", "2")], "policy_delivery_headers_invalid"),
    ([("Content-Type", "application/json"), ("Content-Length", "2"), ("Content-Length", "2")], "policy_delivery_headers_invalid"),
    ([("Content-Type", "application/json"), ("Content-Length", "2"), ("Content-Encoding", "gzip")], "policy_delivery_encoding"),
    ([("Content-Type", "application/json"), ("Content-Length", "2"), ("Transfer-Encoding", "chunked")], "policy_delivery_framing"),
    ([("Content-Type", "application/json"), ("Content-Length", "2"), ("Content-Range", "bytes 0-1/2")], "policy_delivery_framing"),
    ([("Content-Type", "application/json"), ("Content-Length", str(MAX_DELIVERY_BYTES + 1))], "policy_delivery_size"),
    ([("Content-Type", "application/json"), ("Content-Length", "0")], "policy_delivery_size"),
    ([("Content-Type", "application/json"), ("Content-Length", "-1")], "policy_delivery_size"),
    ([("Content-Type", "application/json"), ("Content-Length", "2,2")], "policy_delivery_size"),
])
def test_invalid_http_framing_or_encoding_is_rejected(fixture, tmp_path, bad_headers, code):
    before = fixture["path"].read_bytes()
    with synthetic_https(tmp_path / "tls", b"{}", headers=bad_headers) as server:
        with pytest.raises(PolicyDeliveryError) as error:
            sync(fixture, server)
    assert error.value.code == code and fixture["path"].read_bytes() == before


@pytest.mark.parametrize("raw", [b"not json", b"\xff", b'{"schema":1,"schema":2}', b"NaN", b"[]", b"{}", b"[" * 1200, b"{} {}"])
def test_malformed_downloads_never_mutate_store(fixture, tmp_path, raw):
    before = fixture["path"].read_bytes()
    with synthetic_https(tmp_path / "tls", raw) as server:
        with pytest.raises(PolicyDeliveryError) as error:
            sync(fixture, server)
    assert error.value.network_attempted and fixture["path"].read_bytes() == before


@pytest.mark.parametrize("extra", ["anchor", "issuer_trust", "url", "next", "minimum_root_version"])
def test_download_cannot_supply_trust_network_targets_or_recovery_floors(fixture, tmp_path, extra):
    value = bundle(fixture)
    value[extra] = fixture["anchor"] if extra == "anchor" else "https://other.invalid"
    before = fixture["path"].read_bytes()
    with synthetic_https(tmp_path / "tls", canonical_json_bytes(value)) as server:
        with pytest.raises(PolicyDeliveryError) as error:
            sync(fixture, server)
        assert len(server.requests) == 1
    assert error.value.code == "policy_delivery_bundle_invalid" and fixture["path"].read_bytes() == before


def test_truncated_response_is_rejected_without_a_partial_update(fixture, tmp_path):
    raw = canonical_json_bytes(bundle(fixture))
    before = fixture["path"].read_bytes()
    with synthetic_https(tmp_path / "tls", raw[:-20], headers=[("Content-Type", "application/json"), ("Content-Length", str(len(raw)))]) as server:
        with pytest.raises(PolicyDeliveryError) as error:
            sync(fixture, server)
    assert error.value.code == "policy_delivery_truncated" and fixture["path"].read_bytes() == before


@pytest.mark.parametrize("phase", ["headers", "body"])
def test_response_deadline_stops_a_trickling_server(fixture, tmp_path, phase):
    def trickle(handler):
        if phase == "headers":
            data = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n"
        else:
            handler.send_response(200)
            handler.send_header("Content-Type", "application/json")
            handler.send_header("Content-Length", "100")
            handler.end_headers()
            data = b"x" * 100
        for byte in data:
            handler.wfile.write(bytes([byte]))
            handler.wfile.flush()
            time.sleep(0.02)

    before = fixture["path"].read_bytes()
    with synthetic_https(tmp_path / "tls", b"", responder=trickle) as server:
        start = time.monotonic()
        with pytest.raises(PolicyDeliveryError) as error:
            sync(fixture, server, timeout=0.2)
        assert time.monotonic() - start < 3
    assert error.value.code == "policy_delivery_timeout" and fixture["path"].read_bytes() == before


@pytest.mark.parametrize("kind", ["untrusted_ca", "hostname", "expired"])
def test_tls_authentication_cannot_be_bypassed(fixture, tmp_path, kind):
    before = fixture["path"].read_bytes()
    with synthetic_https(tmp_path / "tls", canonical_json_bytes(bundle(fixture)), wrong_host=kind == "hostname", expired=kind == "expired") as server:
        with pytest.raises(PolicyDeliveryError) as error:
            sync_policy(fixture["path"], fixture["anchor"], server.url, ca_file=None if kind == "untrusted_ca" else server.ca_file)
        assert server.requests == []
    assert error.value.code == "policy_delivery_tls" and error.value.network_attempted and fixture["path"].read_bytes() == before


def test_proxy_environment_and_netrc_do_not_change_transport(fixture, tmp_path, monkeypatch):
    for name in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(name, "http://127.0.0.1:1")
    monkeypatch.setenv("NETRC", str(tmp_path / "unexpected-credentials"))
    with synthetic_https(tmp_path / "tls", canonical_json_bytes(bundle(fixture))) as server:
        assert sync(fixture, server)["status"] == "ACCEPTED"
        assert "Authorization" not in server.requests[0]["headers"]


@pytest.mark.parametrize("problem", ["missing", "legacy", "anchor", "corrupt", "signature"])
def test_bad_local_store_stops_before_network(fixture, tmp_path, monkeypatch, problem):
    path, anchor = fixture["path"], fixture["anchor"]
    if problem == "missing":
        path = tmp_path / "missing.sqlite"
    elif problem == "legacy":
        path = tmp_path / "legacy.sqlite"
        accept_policy_update(path, fixture["initial"]["envelope"], fixture["initial"]["trust"], initialize=True)
    elif problem == "anchor":
        anchor = copy.deepcopy(anchor)
        anchor["version"] = 2
    elif problem == "corrupt":
        path.write_bytes(b"not sqlite")
    else:
        value = copy.deepcopy(fixture["initial"]["envelope"])
        value["signatures"][0]["signature_hex"] = "00" * 64
        with sqlite3.connect(path) as connection:
            connection.execute("UPDATE checkpoint_policy SET envelope_json=?,envelope_sha256=?",
                               (canonical_json_bytes(value).decode(), sha256_object(value)))
    before = path.read_bytes() if path.exists() else None
    monkeypatch.setattr(delivery, "_fetch", lambda *a: pytest.fail("invalid local store triggered network"))
    with pytest.raises(PolicyDeliveryError) as error:
        sync_policy(path, anchor, "https://updates.example/policy.json")
    assert not error.value.network_attempted
    assert (path.read_bytes() if path.exists() else None) == before


@pytest.mark.parametrize("kind", ["empty", "invalid", "oversized", "missing", "directory"])
def test_invalid_ca_file_is_rejected_before_network(fixture, tmp_path, monkeypatch, kind):
    path = tmp_path / "bad-ca.pem"
    if kind == "directory":
        path.mkdir()
    elif kind != "missing":
        path.write_bytes(b"" if kind == "empty" else b"x" * (delivery.MAX_CA_BYTES + 1 if kind == "oversized" else 5))
    monkeypatch.setattr(delivery, "_fetch", lambda *a: pytest.fail("invalid CA triggered network"))
    with pytest.raises(PolicyDeliveryError) as error:
        sync_policy(fixture["path"], fixture["anchor"], "https://updates.example/policy.json", ca_file=path)
    assert not error.value.network_attempted


def test_bundle_cli_then_sync_cli_support_the_complete_operator_workflow(fixture, tmp_path):
    anchor = write_json(tmp_path / "anchor.json", fixture["anchor"])
    policy = write_json(tmp_path / "policy.json", fixture["policy"])
    rotation = write_json(tmp_path / "rotation.json", fixture["rotation"])
    out = tmp_path / "delivery.json"
    built = cli("bundle", "--anchor", anchor, "--signed-policy", policy, "--rotation", rotation, "--out", out)
    assert built.returncode == 0, built.stdout + built.stderr
    assert json.loads(built.stdout)["network_performed"] is False
    with synthetic_https(tmp_path / "tls", out.read_bytes()) as server:
        result = cli("sync", "--anchor", anchor, "--store", fixture["path"], "--url", server.url, "--ca-file", server.ca_file,
                     "--minimum-policy-revision", "2", "--minimum-root-version", "2")
        assert result.returncode == 0, result.stdout + result.stderr
        assert json.loads(result.stdout)["status"] == "ACCEPTED"


def test_bundle_cli_refuses_overwrite_and_incomplete_signatures(fixture, tmp_path):
    anchor = write_json(tmp_path / "anchor.json", fixture["anchor"])
    policy = write_json(tmp_path / "policy.json", fixture["policy"])
    rotation = write_json(tmp_path / "rotation.json", fixture["rotation"])
    out = tmp_path / "delivery.json"
    out.write_bytes(b"preserved")
    args = ("bundle", "--anchor", anchor, "--signed-policy", policy, "--rotation", rotation, "--out", out)
    assert cli(*args).returncode == 3 and out.read_bytes() == b"preserved"
    bad = copy.deepcopy(fixture["rotation"])
    bad["signatures"]["replacement"] = []
    write_json(rotation, bad)
    out.unlink()
    assert cli(*args).returncode == 1 and not out.exists()


def test_sync_cli_failure_reports_attempted_network_and_preserves_store(fixture, tmp_path):
    anchor = write_json(tmp_path / "anchor.json", fixture["anchor"])
    before = fixture["path"].read_bytes()
    with synthetic_https(tmp_path / "tls", b"{}") as server:
        result = cli("sync", "--anchor", anchor, "--store", fixture["path"], "--url", server.url, "--ca-file", server.ca_file)
    assert result.returncode == 1 and json.loads(result.stdout)["network_attempted"] is True
    assert fixture["path"].read_bytes() == before


def test_bundle_cannot_skip_or_exceed_root_chain_limit(fixture):
    with pytest.raises(PolicyUpdateError):
        prepare_delivery_bundle(fixture["anchor"], fixture["policy"], [fixture["rotation"]] * 65)
    value = third_generation(fixture)
    with pytest.raises(PolicyUpdateError):
        prepare_delivery_bundle(fixture["anchor"], value["signed_policy"], value["rotations"][1:])


def test_trusted_root_is_snapshotted_before_network(fixture, tmp_path, monkeypatch):
    anchor = copy.deepcopy(fixture["anchor"])
    original = delivery._fetch

    def mutate_caller(*args):
        anchor["version"] = 999
        return original(*args)

    monkeypatch.setattr(delivery, "_fetch", mutate_caller)
    with synthetic_https(tmp_path / "tls", canonical_json_bytes(bundle(fixture))) as server:
        assert sync_policy(fixture["path"], anchor, server.url, ca_file=server.ca_file)["status"] == "ACCEPTED"
    assert state(fixture)["root"]["version"] == 2


def test_full_chain_catchup_preserves_an_already_accepted_prefix(fixture, tmp_path):
    accept_governed_chain(fixture["path"], fixture["anchor"], fixture["policy"], [fixture["rotation"]])
    with synthetic_https(tmp_path / "tls", canonical_json_bytes(third_generation(fixture))) as server:
        assert sync(fixture, server, minimum_revision=3, minimum_root_version=3)["status"] == "ACCEPTED"
    assert state(fixture)["root"]["version"] == state(fixture)["policy"]["revision"] == 3


def test_store_is_rechecked_after_download_before_activation(fixture, tmp_path, monkeypatch):
    original = delivery._fetch
    observed = {}

    def concurrent_update(*args):
        response = original(*args)
        first = fixture["initial"]
        newer = approved_policy(dict(first["policy"], revision=9), first["keys"][:2], first["trust"])
        accept_governed_update(fixture["path"], fixture["anchor"], newer)
        observed["store"] = fixture["path"].read_bytes()
        return response

    monkeypatch.setattr(delivery, "_fetch", concurrent_update)
    with synthetic_https(tmp_path / "tls", canonical_json_bytes(bundle(fixture))) as server:
        with pytest.raises(PolicyDeliveryError) as error:
            sync(fixture, server)
    assert error.value.code == "policy_revision_rollback"
    assert fixture["path"].read_bytes() == observed["store"]
    assert state(fixture)["root"]["version"] == 1 and state(fixture)["policy"]["revision"] == 9


@pytest.mark.parametrize("failure", [socket.gaierror("synthetic DNS failure"), ConnectionRefusedError("synthetic refusal"), TimeoutError("synthetic timeout")])
def test_connection_failure_does_not_report_a_successful_cached_sync(fixture, monkeypatch, failure):
    before = fixture["path"].read_bytes()

    def fail(*args, **kwargs):
        raise failure

    monkeypatch.setattr(delivery.http.client.HTTPSConnection, "connect", fail)
    with pytest.raises(PolicyDeliveryError) as error:
        sync_policy(fixture["path"], fixture["anchor"], "https://updates.example/policy.json")
    assert error.value.network_attempted and error.value.code in {"policy_delivery_network", "policy_delivery_timeout"}
    assert fixture["path"].read_bytes() == before and state(fixture)["policy"]["revision"] == 1
