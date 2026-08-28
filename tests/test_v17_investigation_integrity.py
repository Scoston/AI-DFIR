from dataclasses import replace

from v17_integrity import (
    EvidenceArtifact,
    InvestigationLedger,
    canonical_json_bytes,
    sha256_object,
)


def build_ledger() -> InvestigationLedger:
    ledger = InvestigationLedger("CASE-001")

    ledger.append(
        event_type="EVIDENCE_ACQUIRED",
        timestamp="2026-08-28T18:00:00Z",
        actor="collector:test",
        payload={
            "artifact_id": "ART-001",
            "sha256": "abc123",
        },
    )

    ledger.append(
        event_type="PACK_EXECUTED",
        timestamp="2026-08-28T18:00:05Z",
        actor="ai-dfir",
        payload={
            "evidence_pack": "EP-001",
            "artifact_id": "ART-001",
        },
    )

    ledger.append(
        event_type="ANALYST_REVIEWED",
        timestamp="2026-08-28T18:01:00Z",
        actor="analyst:test",
        payload={
            "finding_id": "F-001",
            "disposition": "confirmed",
        },
    )

    return ledger


def test_rfc8785_canonical_key_order_is_stable():
    a = {"b": 2, "a": 1}
    b = {"a": 1, "b": 2}

    assert canonical_json_bytes(a) == canonical_json_bytes(b)
    assert sha256_object(a) == sha256_object(b)


def test_evidence_content_change_changes_identity():
    first = EvidenceArtifact.from_bytes(
        case_id="CASE-001",
        artifact_id="ART-001",
        content=b"original evidence",
    )

    changed = EvidenceArtifact.from_bytes(
        case_id="CASE-001",
        artifact_id="ART-001",
        content=b"modified evidence",
    )

    assert first.sha256 != changed.sha256
    assert first.integrity_id != changed.integrity_id


def test_valid_ledger_and_checkpoint_pass():
    ledger = build_ledger()

    checkpoint = ledger.checkpoint(
        created_at="2026-08-28T18:02:00Z"
    )

    valid, errors = ledger.verify(checkpoint)

    assert valid
    assert errors == []


def test_modified_payload_fails():
    ledger = build_ledger()
    events = list(ledger.events)

    events[1] = replace(
        events[1],
        payload={"evidence_pack": "EP-TAMPERED"},
    )

    tampered = InvestigationLedger("CASE-001", events)

    valid, errors = tampered.verify()

    assert not valid
    assert any(
        "entry_hash mismatch" in error
        for error in errors
    )


def test_modified_previous_hash_fails():
    ledger = build_ledger()
    events = list(ledger.events)

    events[2] = replace(
        events[2],
        previous_hash="0" * 64,
    )

    tampered = InvestigationLedger("CASE-001", events)

    valid, errors = tampered.verify()

    assert not valid
    assert any(
        "previous_hash mismatch" in error
        for error in errors
    )


def test_middle_event_removed_fails():
    ledger = build_ledger()
    events = list(ledger.events)

    del events[1]

    tampered = InvestigationLedger("CASE-001", events)

    valid, errors = tampered.verify()

    assert not valid
    assert errors


def test_tail_event_removed_fails_against_checkpoint():
    ledger = build_ledger()

    checkpoint = ledger.checkpoint(
        created_at="2026-08-28T18:02:00Z"
    )

    truncated = InvestigationLedger(
        "CASE-001",
        ledger.events[:-1],
    )

    valid, errors = truncated.verify(checkpoint)

    assert not valid

    assert any(
        "event_count mismatch" in error
        for error in errors
    )

    assert any(
        "head_hash mismatch" in error
        for error in errors
    )


def test_reordered_events_fail():
    ledger = build_ledger()
    events = list(ledger.events)

    events[0], events[1] = events[1], events[0]

    tampered = InvestigationLedger("CASE-001", events)

    valid, errors = tampered.verify()

    assert not valid
    assert errors


def test_checkpoint_event_count_tamper_fails():
    ledger = build_ledger()

    checkpoint = ledger.checkpoint(
        created_at="2026-08-28T18:02:00Z"
    )

    tampered_checkpoint = replace(
        checkpoint,
        event_count=checkpoint.event_count + 1,
    )

    valid, errors = ledger.verify(tampered_checkpoint)

    assert not valid
    assert any(
        "event_count mismatch" in error
        for error in errors
    )


def test_checkpoint_head_hash_tamper_fails():
    ledger = build_ledger()

    checkpoint = ledger.checkpoint(
        created_at="2026-08-28T18:02:00Z"
    )

    tampered_checkpoint = replace(
        checkpoint,
        head_hash="0" * 64,
    )

    valid, errors = ledger.verify(tampered_checkpoint)

    assert not valid
    assert any(
        "head_hash mismatch" in error
        for error in errors
    )


def test_checkpoint_wrong_case_fails():
    ledger = build_ledger()

    checkpoint = ledger.checkpoint(
        created_at="2026-08-28T18:02:00Z"
    )

    wrong_case = replace(
        checkpoint,
        case_id="CASE-OTHER",
    )

    valid, errors = ledger.verify(wrong_case)

    assert not valid
    assert any(
        "case_id mismatch" in error
        for error in errors
    )