"""Cryptographic, trust-boundary, and offline CLI regressions for private logs."""
from __future__ import annotations

import copy
import hashlib
import json
import os
import socket
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import private_transparency_v17 as cli
import transparency_anchor_v14 as legacy
import v17_merkle as merkle
import v17_private_transparency as log
from v17_integrity import canonical_json_bytes, sha256_bytes, sha256_object
from v17_private_transparency_selftest import CASE_ID, TIMESTAMP, synthetic_history, synthetic_trust, verify


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def deny(*args, **kwargs):
        raise AssertionError("private transparency must not use a network")
    monkeypatch.setattr(socket.socket, "connect", deny)
    monkeypatch.setattr(socket, "create_connection", deny)


def independent_root(data):
    """Iterative history-tree construction, independent of production helpers."""
    stack = []
    for index, raw in enumerate(data):
        value = hashlib.sha256(b"\x00" + raw).digest()
        count = index
        while count & 1:
            value = hashlib.sha256(b"\x01" + stack.pop() + value).digest()
            count >>= 1
        stack.append(value)
    if not stack:
        return hashlib.sha256(b"").digest()
    value = stack.pop()
    while stack:
        value = hashlib.sha256(b"\x01" + stack.pop() + value).digest()
    return value


@pytest.mark.parametrize("size", [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129])
def test_independent_history_roots_and_every_leaf_and_prefix(size):
    data = [f"leaf-{i}".encode() for i in range(size)]
    leaves = [merkle.leaf_hash(raw) for raw in data]
    expected = independent_root(data)
    assert merkle.root(leaves) == expected
    for index in range(size):
        proof = merkle.inclusion_proof(leaves, index)
        assert merkle.verify_inclusion(leaves[index], index, size, proof, expected)
        assert not merkle.verify_inclusion(b"x" * 32, index, size, proof, expected)
        assert not merkle.verify_inclusion(leaves[index], index, size, proof + [b"x" * 32], expected)
        if proof:
            assert not merkle.verify_inclusion(leaves[index], index, size, proof[:-1], expected)
    for previous in range(size + 1):
        proof = merkle.consistency_proof(leaves, previous)
        old = independent_root(data[:previous])
        assert merkle.verify_consistency(previous, size, old, expected, proof)
        assert not merkle.verify_consistency(previous, size, b"x" * 32, expected, proof)
        assert not merkle.verify_consistency(previous, size, old, expected, proof + [b"x" * 32])


def test_fixed_hash_vectors_and_empty_tree_edges():
    assert merkle.EMPTY_ROOT.hex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert merkle.leaf_hash(b"").hex() == "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
    assert merkle.leaf_hash(b"a" * 64) != hashlib.sha256(b"\x01" + b"a" * 64).digest()
    assert not merkle.verify_consistency(0, 0, merkle.EMPTY_ROOT, b"x" * 32, [])


@pytest.mark.parametrize("invalid", [True, -1, 1.0, "1", None, [], 65537])
def test_merkle_integer_bounds(invalid):
    with pytest.raises(ValueError):
        merkle.verify_inclusion(b"x" * 32, 0, invalid, [], b"x" * 32)
    with pytest.raises(ValueError):
        merkle.inclusion_proof([b"x" * 32], invalid)
    with pytest.raises(ValueError):
        merkle.consistency_proof([b"x" * 32], invalid)


@pytest.mark.parametrize("path", [[b"x"], ["0" * 64], [b"x" * 32] * 18, None, {}])
def test_merkle_malformed_proof_bounds(path):
    with pytest.raises(ValueError):
        merkle.verify_inclusion(b"x" * 32, 0, 1, path, b"x" * 32)
    with pytest.raises(ValueError):
        merkle.verify_consistency(1, 2, b"x" * 32, b"x" * 32, path)


def test_merkle_leaf_and_tree_limits():
    for invalid in (b"x" * 4097, "text"):
        with pytest.raises(ValueError):
            merkle.leaf_hash(invalid)
    with pytest.raises(ValueError):
        merkle.root([b"x" * 32] * 65537)
    assert not merkle.verify_consistency(2, 1, b"x" * 32, b"x" * 32, [])


@pytest.fixture
def history():
    return synthetic_history()


def receipt(history, *, previous=3, index=4):
    prior = None if previous is None else history["heads"][previous]
    return log.make_receipt(history["states"][-1], history["heads"][-1], index, history["trust"],
                            expected_trust_sha256=history["pin"], previous_head=prior)


@pytest.mark.parametrize("previous", [None, 0, 1, 3, 4, 6, 7])
def test_signed_inclusion_and_optional_prefix_consistency(history, previous):
    value = receipt(history, previous=previous)
    prior = None if previous is None else history["heads"][previous]
    result = verify(value, history, previous=prior)
    assert result["status"] == "PASS"
    assert result["inclusion_proof_verified"] and result["log_signature_verified"]
    assert result["prefix_consistency_verified"] == (previous is not None)
    assert result["witness_signatures_verified"] == result["required_witnesses"] == 2
    for key in ("operator_independence_verified", "independent_timestamp_verified", "global_fork_freedom_verified", "source_authenticity_verified", "network_performed"):
        assert result[key] is False


@pytest.mark.parametrize("threshold", [0, 1, 2])
def test_configured_quorum_threshold(threshold):
    history = synthetic_history(1, threshold=threshold)
    result = verify(receipt(history, previous=0, index=0), history, previous=history["heads"][0])
    assert result["witness_signatures_verified"] == threshold
    assert result["witness_quorum_satisfied"]


def set_path(value, path, replacement):
    for key in path[:-1]:
        value = value[key]
    value[path[-1]] = replacement


@pytest.mark.parametrize("path,replacement", [
    (("schema",), "other"), (("inclusion_verified",), True),
    (("leaf_index",), True), (("leaf_index",), -1), (("leaf_index",), 7), (("leaf_index",), 0),
    (("inclusion_path", 0), "0" * 64), (("inclusion_path",), []),
    (("inclusion_path",), ["0" * 64] * 18),
    (("consistency_path", 0), "0" * 64), (("consistency_path",), []),
    (("consistency_path",), ["0" * 64] * 18), (("previous_head_sha256",), "0" * 64),
    (("head", "root_sha256"), "0" * 64), (("head", "tree_size"), 8),
    (("head", "log_id"), "OTHER-LOG"), (("head", "issued_at"), "2026-09-08T00:00:00Z"),
    (("head", "log_signature", "signature_hex"), "0" * 128),
    (("head", "witness_signatures"), []),
    (("head", "witness_signatures", 0, "signature_hex"), "0" * 128),
])
def test_tampered_receipts_fail(history, path, replacement):
    value = receipt(history)
    set_path(value, path, replacement)
    with pytest.raises(ValueError):
        verify(value, history, previous=history["heads"][3])


@pytest.mark.parametrize("field,value", [("expected_case_id", "WRONG"), ("expected_subject_sha256", "0" * 64),
                                         ("expected_subject_size_bytes", 0), ("expected_subject_size_bytes", True)])
def test_subject_expectations_must_be_independent(history, field, value):
    proof = receipt(history)
    options = dict(expected_case_id=CASE_ID, expected_subject_sha256=proof["subject"]["subject_sha256"],
                   expected_subject_size_bytes=proof["subject"]["subject_size_bytes"])
    options[field] = value
    with pytest.raises(ValueError):
        log.verify_receipt(proof, history["trust"], expected_trust_sha256=history["pin"], previous_head=history["heads"][3], **options)


@pytest.mark.parametrize("mode", ["missing-prior", "wrong-prior", "unrequested-prior", "stripped-binding", "duplicate-witness", "reordered-proof"])
def test_receipt_binding_and_signature_ambiguities(history, mode):
    value = receipt(history)
    previous = history["heads"][3]
    if mode == "missing-prior": previous = None
    if mode == "wrong-prior": previous = history["heads"][2]
    if mode == "unrequested-prior": value = receipt(history, previous=None)
    if mode == "stripped-binding": value["previous_head_sha256"] = None
    if mode == "duplicate-witness": value["head"]["witness_signatures"][1] = value["head"]["witness_signatures"][0]
    if mode == "reordered-proof": value["inclusion_path"].reverse()
    with pytest.raises(ValueError):
        verify(value, history, previous=previous)


def test_validly_signed_fork_cannot_prove_old_retained_history(history):
    state, head = log.append(history["states"][3], history["heads"][3], log.entry(CASE_ID, "f" * 64, 17),
                              history["log"], history["trust"], expected_trust_sha256=history["pin"], issued_at=TIMESTAMP)
    for key in history["witnesses"]:
        head = log.cosign_head(head, key, history["trust"], expected_trust_sha256=history["pin"], state=state, previous_head=history["heads"][3])
    proof = log.make_receipt(state, head, 3, history["trust"], expected_trust_sha256=history["pin"], previous_head=history["heads"][3])
    assert verify(proof, history, previous=history["heads"][3])["prefix_consistency_verified"]
    with pytest.raises(ValueError):
        log.make_receipt(history["states"][7], history["heads"][7], 4, history["trust"], expected_trust_sha256=history["pin"], previous_head=head)
    with pytest.raises(ValueError):
        log.make_receipt(state, head, 3, history["trust"], expected_trust_sha256=history["pin"], previous_head=history["heads"][7])


@pytest.mark.parametrize("mode", ["schema", "id", "boolean-threshold", "negative-threshold", "high-threshold", "log-as-witness", "duplicate", "key-id", "key-bytes", "extra", "too-many"])
def test_invalid_trust_is_rejected_even_with_matching_pin(mode):
    trust, _, _, _ = synthetic_trust()
    if mode == "schema": trust["schema"] = "other"
    if mode == "id": trust["log_id"] = "../log"
    if mode == "boolean-threshold": trust["witness_threshold"] = True
    if mode == "negative-threshold": trust["witness_threshold"] = -1
    if mode == "high-threshold": trust["witness_threshold"] = 3
    if mode == "log-as-witness": trust["witness_keys"][0] = trust["log_key"]
    if mode == "duplicate": trust["witness_keys"][1] = trust["witness_keys"][0]
    if mode == "key-id": trust["log_key"]["key_id"] = "sha256:" + "0" * 64
    if mode == "key-bytes": trust["log_key"]["public_key_hex"] = "00"
    if mode == "extra": trust["command"] = "ignored-command"
    if mode == "too-many": trust["witness_keys"] *= 17
    with pytest.raises(ValueError):
        log.validate_trust(trust, expected_trust_sha256=sha256_object(trust))


@pytest.mark.parametrize("pin", [None, True, "", "0" * 64, "A" * 64])
def test_trust_pin_cannot_be_adopted_from_input(history, pin):
    with pytest.raises(ValueError):
        log.verify_head(history["heads"][7], history["trust"], expected_trust_sha256=pin)


def test_missing_witness_quorum_blocks_head_append_and_receipt(history):
    head = copy.deepcopy(history["heads"][7]); head["witness_signatures"].pop()
    options = dict(expected_trust_sha256=history["pin"])
    with pytest.raises(ValueError): log.verify_head(head, history["trust"], **options)
    with pytest.raises(ValueError): log.make_receipt(history["states"][7], head, 0, history["trust"], **options)
    with pytest.raises(ValueError):
        log.append(history["states"][7], head, log.entry(CASE_ID, "f" * 64, 0), history["log"], history["trust"], issued_at=TIMESTAMP, **options)


@pytest.mark.parametrize("mode", ["no-state", "no-prior", "changed-state", "conflicting-prior", "duplicate", "wrong-role"])
def test_witness_checks_retained_state_before_signing(history, mode):
    state = copy.deepcopy(history["states"][7]); previous = history["heads"][6]
    head = copy.deepcopy(history["heads"][7]); head["witness_signatures"] = []
    key = history["witnesses"][0]
    if mode == "no-state": state = None
    if mode == "no-prior": previous = None
    if mode == "changed-state": state["entries"][0]["subject_sha256"] = "f" * 64
    if mode == "conflicting-prior":
        previous = copy.deepcopy(previous); previous["root_sha256"] = "f" * 64
    if mode == "duplicate": head = history["heads"][7]
    if mode == "wrong-role": key = history["log"]
    with pytest.raises(ValueError):
        log.cosign_head(head, key, history["trust"], expected_trust_sha256=history["pin"], state=state, previous_head=previous)


@pytest.mark.parametrize("mode", ["changed-state", "log-id", "pin", "empty-root", "time", "wrong-key"])
def test_append_rejects_conflicting_state_and_signing_authority(history, mode):
    state = copy.deepcopy(history["states"][7]); head = history["heads"][7]
    key = history["log"]; timestamp = TIMESTAMP
    if mode == "changed-state": state["entries"].pop()
    if mode == "log-id": state["log_id"] = "other"
    if mode == "pin": state["trust_sha256"] = "f" * 64
    if mode == "empty-root":
        state = history["states"][0]; head = copy.deepcopy(history["heads"][0]); head["root_sha256"] = "f" * 64
    if mode == "time": timestamp = "2026-09-06T00:00:00Z"
    if mode == "wrong-key": key = history["witnesses"][0]
    with pytest.raises(ValueError):
        log.append(state, head, log.entry(CASE_ID, "f" * 64, 0), key, history["trust"], expected_trust_sha256=history["pin"], issued_at=timestamp)


def test_append_is_immutable_and_duplicate_entries_keep_positions():
    h = synthetic_history(1, threshold=0)
    original = copy.deepcopy(h["states"][-1])
    state, head = log.append(original, h["heads"][-1], original["entries"][0], h["log"], h["trust"], expected_trust_sha256=h["pin"], issued_at=TIMESTAMP)
    assert original == h["states"][-1] and len(original["entries"]) == 1
    assert state["entries"][0] == state["entries"][1]
    for index in (0, 1):
        proof = log.make_receipt(state, head, index, h["trust"], expected_trust_sha256=h["pin"])
        assert verify(proof, h)["leaf_index"] == index


@pytest.mark.parametrize("case,digest,size", [
    ("../case", "f" * 64, 0), ("", "f" * 64, 0), ("c" * 129, "f" * 64, 0),
    ("case", "F" * 64, 0), ("case", "f" * 63, 0), ("case", None, 0),
    ("case", "f" * 64, True), ("case", "f" * 64, -1),
    ("case", "f" * 64, 9007199254740992), ("case", "f" * 64, 1.0),
])
def test_subject_schema_bounds(case, digest, size):
    with pytest.raises(ValueError): log.entry(case, digest, size)


@pytest.mark.parametrize("field,value", [
    ("schema", "other"), ("tree_size", True), ("tree_size", -1), ("tree_size", 4097),
    ("issued_at", "2026-09-07T00:00:00+00:00"), ("issued_at", None),
    ("root_sha256", "F" * 64), ("trust_sha256", "0" * 64), ("witness_signatures", {}),
])
def test_head_schema_rejects_unsupported_values(history, field, value):
    head = copy.deepcopy(history["heads"][7]); head[field] = value
    with pytest.raises(ValueError):
        log.verify_head(head, history["trust"], expected_trust_sha256=history["pin"])


def test_witness_signature_role_is_bound(history):
    head = copy.deepcopy(history["heads"][7])
    key = history["witnesses"][0]; ident = history["trust"]["witness_keys"][0]["key_id"]
    signature = key.sign(log._material(head, "log", ident)).hex()
    head["witness_signatures"] = [item for item in head["witness_signatures"] if item["key_id"] != ident]
    head["witness_signatures"].append({"key_id": ident, "signature_hex": signature})
    with pytest.raises(ValueError):
        log.verify_head(head, history["trust"], expected_trust_sha256=history["pin"])


def test_maximum_state_and_witness_limits():
    trust, key, _, pin = synthetic_trust(threshold=0, witnesses=32)
    log.validate_trust(trust, expected_trust_sha256=pin)
    state, _ = log.initialize(trust, key, expected_trust_sha256=pin, issued_at=TIMESTAMP)
    subject = log.entry("c" * 128, "f" * 64, 9007199254740991)
    state["entries"] = [subject] * 4096
    leaves = [merkle.leaf_hash(canonical_json_bytes(subject))] * 4096
    head = log._new_head(leaves, trust, pin, key, TIMESTAMP)
    proof = log.make_receipt(state, head, 4095, trust, expected_trust_sha256=pin)
    result = log.verify_receipt(proof, trust, expected_trust_sha256=pin, expected_case_id=subject["case_id"],
                                expected_subject_sha256=subject["subject_sha256"], expected_subject_size_bytes=subject["subject_size_bytes"])
    assert result["tree_size"] == 4096
    with pytest.raises(ValueError): log.append(state, head, subject, key, trust, expected_trust_sha256=pin, issued_at=TIMESTAMP)
    state["entries"].append(subject)
    with pytest.raises(ValueError): log.make_receipt(state, head, 0, trust, expected_trust_sha256=pin)


def write_json(path, value):
    path.write_bytes(canonical_json_bytes(value))
    return path


def write_key(path, key, password=None):
    encryption = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, encryption))
    path.chmod(0o600)
    return path


def call_cli(monkeypatch, capsys, command, trust, pin, *args):
    monkeypatch.setattr(sys, "argv", ["private_transparency_v17.py", command, "--trust", str(trust), "--expected-trust-sha256", pin, *map(str, args)])
    code = cli.main(); captured = capsys.readouterr()
    assert not captured.err
    return code, json.loads(captured.out)


@pytest.mark.parametrize("threshold", [0, 1, 2])
def test_cli_complete_snapshot_witness_proof_and_verify_flow(tmp_path, monkeypatch, capsys, threshold):
    trust, key, witnesses, pin = synthetic_trust(threshold=threshold)
    trusted = write_json(tmp_path / "trust.json", trust)
    log_key = write_key(tmp_path / "log.pem", key)
    witness_keys = [write_key(tmp_path / f"witness-{i}.pem", key) for i, key in enumerate(witnesses)]
    folder = tmp_path / "initial"
    code, result = call_cli(monkeypatch, capsys, "init", trusted, pin, "--private-key", log_key, "--issued-at", TIMESTAMP, "--out-dir", folder)
    assert code == (2 if threshold else 0)
    assert result["inclusion_receipt_issued"] is False
    assert json.loads((folder / "receipt.json").read_bytes()) == result
    prior = folder / "head.json"
    for index, witness in enumerate(witness_keys[:threshold]):
        output = tmp_path / f"initial-witness-{index}.json"
        code, report = call_cli(monkeypatch, capsys, "cosign", trusted, pin, "--head", prior, "--private-key", witness, "--out", output)
        assert code == (0 if index + 1 == threshold else 2)
        prior = output
    code, _ = call_cli(monkeypatch, capsys, "check-head", trusted, pin, "--head", prior)
    assert code == 0
    subject = tmp_path / "subject.bin"; subject.write_bytes(b"SYNTHETIC-SUBJECT\x00\xff")
    next_dir = tmp_path / "next"
    code, _ = call_cli(monkeypatch, capsys, "append", trusted, pin, "--private-key", log_key, "--issued-at", TIMESTAMP,
                        "--out-dir", next_dir, "--state", folder / "state.json", "--previous-head", prior, "--case", CASE_ID, "--subject", subject)
    assert code == (2 if threshold else 0)
    candidate = next_dir / "head.json"
    for index, witness in enumerate(witness_keys[:threshold]):
        output = tmp_path / f"next-witness-{index}.json"
        code, _ = call_cli(monkeypatch, capsys, "cosign", trusted, pin, "--head", candidate, "--private-key", witness,
                            "--state", next_dir / "state.json", "--previous-head", prior, "--out", output)
        assert code == (0 if index + 1 == threshold else 2)
        candidate = output
    proof = tmp_path / "proof.json"
    code, _ = call_cli(monkeypatch, capsys, "proof", trusted, pin, "--state", next_dir / "state.json", "--head", candidate,
                        "--index", 0, "--previous-head", prior, "--out", proof)
    assert code == 0
    code, result = call_cli(monkeypatch, capsys, "verify", trusted, pin, "--receipt", proof, "--subject", subject, "--case", CASE_ID, "--previous-head", prior)
    assert code == 0 and result["prefix_consistency_verified"] and not result["network_performed"]
    subject.write_bytes(b"ALTERED")
    code, result = call_cli(monkeypatch, capsys, "verify", trusted, pin, "--receipt", proof, "--subject", subject, "--case", CASE_ID, "--previous-head", prior)
    assert code == 1 and result["status"] == "FAIL"
    if os.name == "posix":
        assert folder.stat().st_mode & 0o777 == 0o700
        assert proof.stat().st_mode & 0o777 == 0o600
        assert (folder / "state.json").stat().st_mode & 0o777 == 0o600


@pytest.fixture
def cli_files(tmp_path):
    trust, key, _, pin = synthetic_trust(threshold=0)
    trusted = write_json(tmp_path / "trust.json", trust)
    private = write_key(tmp_path / "log.pem", key)
    return trust, key, pin, trusted, private


@pytest.mark.parametrize("mode", ["encrypted", "wrong-password", "missing-password", "password-permissions", "key-permissions", "multiple-keys", "wrong-key", "wrong-kind"])
def test_cli_protected_private_keys(tmp_path, monkeypatch, capsys, cli_files, mode):
    _, key, pin, trusted, private = cli_files
    password = tmp_path / "password.txt"; password.write_bytes(b"synthetic-password\n"); password.chmod(0o600)
    args = []
    if mode in {"encrypted", "wrong-password", "missing-password", "password-permissions"}:
        write_key(private, key, b"synthetic-password")
        if mode != "missing-password": args = ["--key-password-file", password]
    if mode == "wrong-password": password.write_bytes(b"wrong\n")
    if mode == "password-permissions": password.chmod(0o644)
    if mode == "key-permissions": private.chmod(0o644)
    if mode == "multiple-keys": private.write_bytes(private.read_bytes() * 2)
    if mode == "wrong-key": write_key(private, Ed25519PrivateKey.generate())
    if mode == "wrong-kind":
        from cryptography.hazmat.primitives.asymmetric import ec
        write_key(private, ec.generate_private_key(ec.SECP256R1()))
    folder = tmp_path / "out"
    code, result = call_cli(monkeypatch, capsys, "init", trusted, pin, "--private-key", private, "--issued-at", TIMESTAMP, "--out-dir", folder, *args)
    assert code == (0 if mode == "encrypted" else 1)
    if code:
        assert result["status"] == "FAIL" and not folder.exists()
    assert "synthetic-password" not in json.dumps(result) and str(tmp_path) not in json.dumps(result)


@pytest.mark.parametrize("kind", ["symlink", "fifo", "directory", "oversized", "empty", "duplicate-json"])
def test_cli_rejects_nonregular_or_ambiguous_inputs(tmp_path, monkeypatch, capsys, cli_files, kind):
    _, _, pin, trusted, private = cli_files
    source = tmp_path / "invalid.json"
    if kind == "symlink": source.symlink_to(trusted)
    if kind == "fifo": os.mkfifo(source)
    if kind == "directory": source.mkdir()
    if kind == "oversized": source.write_bytes(b" " * (log.MAX_TRUST_BYTES + 1))
    if kind == "empty": source.write_bytes(b"")
    if kind == "duplicate-json": source.write_bytes(b'{"schema":"one","schema":"two"}')
    folder = tmp_path / "out"
    code, result = call_cli(monkeypatch, capsys, "init", source, pin, "--private-key", private, "--issued-at", TIMESTAMP, "--out-dir", folder)
    assert code == 1 and not folder.exists() and result["network_performed"] is False


@pytest.mark.parametrize("mode", ["existing-directory", "second-write", "receipt-write", "interrupt"])
def test_snapshot_failure_never_publishes_a_success_receipt(tmp_path, monkeypatch, capsys, cli_files, mode):
    _, _, pin, trusted, private = cli_files
    folder = tmp_path / "out"
    if mode == "existing-directory":
        folder.mkdir(); (folder / "preserved").write_bytes(b"retain")
    elif mode == "second-write":
        original = cli._write_new
        def fail_second(directory, name, raw):
            if name == "head.json": raise OSError("SENSITIVE-PATH-AND-PAYLOAD")
            return original(directory, name, raw)
        monkeypatch.setattr(cli, "_write_new", fail_second)
    elif mode == "receipt-write":
        def fail(*args): raise OSError("SENSITIVE-PATH-AND-PAYLOAD")
        monkeypatch.setattr(cli, "_publish_receipt", fail)
    else:
        def interrupt(*args, **kwargs): raise KeyboardInterrupt()
        monkeypatch.setattr(cli, "initialize", interrupt)
    code, result = call_cli(monkeypatch, capsys, "init", trusted, pin, "--private-key", private, "--issued-at", TIMESTAMP, "--out-dir", folder)
    assert code == (130 if mode == "interrupt" else 1)
    assert not (folder / "receipt.json").exists()
    assert "SENSITIVE" not in json.dumps(result)
    if mode == "existing-directory": assert (folder / "preserved").read_bytes() == b"retain"


@pytest.mark.parametrize("output_kind", ["file", "symlink"])
def test_proof_output_never_overwrites_existing_data(tmp_path, monkeypatch, capsys, history, output_kind):
    trusted = write_json(tmp_path / "trust.json", history["trust"])
    state = write_json(tmp_path / "state.json", history["states"][7])
    head = write_json(tmp_path / "head.json", history["heads"][7])
    target = tmp_path / "preserved"; target.write_bytes(b"ORIGINAL")
    output = target
    if output_kind == "symlink": output = tmp_path / "link"; output.symlink_to(target)
    code, result = call_cli(monkeypatch, capsys, "proof", trusted, history["pin"], "--state", state, "--head", head, "--index", 0, "--out", output)
    assert code == 1 and target.read_bytes() == b"ORIGINAL" and result["status"] == "FAIL"


@pytest.mark.parametrize("limit", [log.MAX_TRUST_BYTES, log.MAX_HEAD_BYTES, log.MAX_RECEIPT_BYTES, log.MAX_STATE_BYTES])
def test_document_limits_are_applied_before_parsing(tmp_path, limit):
    path = tmp_path / "large.json"; path.write_bytes(b" " * (limit + 1))
    with pytest.raises(ValueError): cli._json(path, limit)


def test_empty_subject_can_be_anchored_and_verified(tmp_path, monkeypatch, capsys, cli_files):
    trust, key, pin, trusted, _ = cli_files
    state, head = log.initialize(trust, key, expected_trust_sha256=pin, issued_at=TIMESTAMP)
    state, head = log.append(state, head, log.entry(CASE_ID, sha256_bytes(b""), 0), key, trust, expected_trust_sha256=pin, issued_at=TIMESTAMP)
    proof = log.make_receipt(state, head, 0, trust, expected_trust_sha256=pin)
    retained = write_json(tmp_path / "proof.json", proof)
    subject = tmp_path / "empty"; subject.write_bytes(b"")
    code, result = call_cli(monkeypatch, capsys, "verify", trusted, pin, "--receipt", retained, "--subject", subject, "--case", CASE_ID)
    assert code == 0 and result["subject_size_bytes"] == 0


@pytest.mark.parametrize("asserted", [True, False, "true", None])
def test_legacy_receipt_boolean_never_proves_inclusion(tmp_path, monkeypatch, capsys, asserted):
    from fleet_crypto import generate
    private = tmp_path / "private.pem"; public = tmp_path / "public.pem"; generate(private, public)
    subject = tmp_path / "subject"; subject.write_bytes(b"SYNTHETIC-LEGACY")
    submission = tmp_path / "submission.json"; legacy.create([subject], private, submission)
    retained = write_json(tmp_path / "receipt.json", {"subject_sha256": [sha256_bytes(subject.read_bytes())], "log_id": "recorded-log", "inclusion_verified": asserted})
    result = legacy.verify_receipt(submission, public, retained)
    assert not result["valid"] and not result["inclusion_proof_verified"]
    assert any(item["type"] == "transparency_inclusion_proof_unverified" for item in result["findings"])
    output = tmp_path / "validation.json"
    monkeypatch.setattr(sys, "argv", ["transparency_anchor_v14.py", "verify-receipt", "--submission", str(submission), "--public-key", str(public), "--receipt", str(retained), "--out", str(output)])
    with pytest.raises(SystemExit) as exc: legacy.main()
    assert exc.value.code == 1 and json.loads(output.read_bytes())["valid"] is False
