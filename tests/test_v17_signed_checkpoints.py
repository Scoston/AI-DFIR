from dataclasses import replace

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from v17_integrity import InvestigationLedger
from v17_signing import (
    SignedLedgerCheckpoint,
    key_id_from_public_key_bytes,
    public_key_bytes,
    verify_signed_checkpoint,
)


TEST_PRIVATE_KEY = bytes(range(1, 33))
OTHER_TEST_PRIVATE_KEY = bytes(range(33, 65))


def make_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        TEST_PRIVATE_KEY
    )


def make_other_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(
        OTHER_TEST_PRIVATE_KEY
    )


def build_signed_checkpoint():
    ledger = InvestigationLedger("CASE-SIGNED-001")

    ledger.append(
        event_type="EVIDENCE_ACQUIRED",
        timestamp="2026-08-28T20:00:00Z",
        actor="collector:test",
        payload={
            "artifact_id": "ART-001",
            "sha256": "abc123",
        },
    )

    ledger.append(
        event_type="ANALYST_REVIEWED",
        timestamp="2026-08-28T20:01:00Z",
        actor="analyst:test",
        payload={
            "finding_id": "F-001",
            "disposition": "confirmed",
        },
    )

    checkpoint = ledger.checkpoint(
        created_at="2026-08-28T20:02:00Z"
    )

    signed = SignedLedgerCheckpoint.sign(
        checkpoint=checkpoint,
        private_key=make_private_key(),
        signed_at="2026-08-28T20:03:00Z",
    )

    return ledger, signed


def trusted_keys_for(
    signed: SignedLedgerCheckpoint,
) -> dict[str, bytes]:
    return {
        signed.key_id: bytes.fromhex(
            signed.public_key_hex
        )
    }


def test_signed_checkpoint_signature_verifies():
    _, signed = build_signed_checkpoint()

    valid, errors = signed.verify_signature()

    assert valid
    assert errors == []


def test_signed_checkpoint_trusted_key_verifies():
    _, signed = build_signed_checkpoint()

    valid, errors = signed.verify_trusted(
        trusted_keys_for(signed)
    )

    assert valid
    assert errors == []


def test_checkpoint_substitution_breaks_signature():
    _, signed = build_signed_checkpoint()

    tampered_checkpoint = replace(
        signed.checkpoint,
        head_hash="0" * 64,
    )

    tampered = replace(
        signed,
        checkpoint=tampered_checkpoint,
    )

    valid, errors = tampered.verify_signature()

    assert not valid
    assert any(
        "Ed25519 verification failed" in error
        for error in errors
    )


def test_signature_tamper_fails():
    _, signed = build_signed_checkpoint()

    replacement = (
        "00"
        if not signed.signature_hex.startswith("00")
        else "01"
    )

    tampered = replace(
        signed,
        signature_hex=(
            replacement + signed.signature_hex[2:]
        ),
    )

    valid, errors = tampered.verify_signature()

    assert not valid
    assert errors


def test_signed_at_tamper_fails():
    _, signed = build_signed_checkpoint()

    tampered = replace(
        signed,
        signed_at="2026-08-28T21:03:00Z",
    )

    valid, errors = tampered.verify_signature()

    assert not valid
    assert errors


def test_public_key_substitution_fails():
    _, signed = build_signed_checkpoint()

    other_public_key = public_key_bytes(
        make_other_private_key().public_key()
    )

    tampered = replace(
        signed,
        public_key_hex=other_public_key.hex(),
    )

    valid, errors = tampered.verify_signature()

    assert not valid

    assert any(
        "key_id mismatch" in error
        for error in errors
    )


def test_untrusted_key_fails_trust_verification():
    _, signed = build_signed_checkpoint()

    valid, errors = signed.verify_trusted({})

    assert not valid

    assert any(
        "key_id is not trusted" in error
        for error in errors
    )


def test_tail_truncation_fails_combined_verification():
    ledger, signed = build_signed_checkpoint()

    truncated = InvestigationLedger(
        ledger.case_id,
        ledger.events[:-1],
    )

    valid, errors = verify_signed_checkpoint(
        ledger=truncated,
        signed_checkpoint=signed,
        trusted_public_keys=trusted_keys_for(signed),
    )

    assert not valid

    assert any(
        "event_count mismatch" in error
        for error in errors
    )

    assert any(
        "head_hash mismatch" in error
        for error in errors
    )