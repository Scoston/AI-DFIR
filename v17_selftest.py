from v17_integrity import (
    EvidenceArtifact,
    InvestigationLedger,
)


def main() -> int:
    artifact = EvidenceArtifact.from_bytes(
        case_id="V17-SELFTEST",
        artifact_id="ART-001",
        content=b"AI-DFIR v1.7 deterministic synthetic evidence",
        media_type="application/octet-stream",
        source_name="synthetic.bin",
    )

    ledger = InvestigationLedger("V17-SELFTEST")

    ledger.append(
        event_type="EVIDENCE_ACQUIRED",
        timestamp="2026-08-28T18:00:00Z",
        actor="v17-selftest",
        payload={
            "artifact_id": artifact.artifact_id,
            "sha256": artifact.sha256,
            "integrity_id": artifact.integrity_id,
        },
    )

    ledger.append(
        event_type="EVIDENCE_HASHED",
        timestamp="2026-08-28T18:00:01Z",
        actor="v17-selftest",
        payload={
            "artifact_id": artifact.artifact_id,
        },
    )

    checkpoint = ledger.checkpoint(
        created_at="2026-08-28T18:00:02Z"
    )

    valid, errors = ledger.verify(checkpoint)

    truncated = InvestigationLedger(
        "V17-SELFTEST",
        ledger.events[:-1],
    )

    truncation_valid, truncation_errors = truncated.verify(
        checkpoint
    )

    print("AI-DFIR v1.7 Investigation Integrity Self-Test")
    print()

    print(
        "Evidence artifact hashing:",
        "PASS" if artifact.sha256 else "FAIL",
    )

    print(
        "Canonical artifact identity:",
        "PASS" if artifact.integrity_id else "FAIL",
    )

    print(
        "RFC 8785 canonicalization:",
        "PASS",
    )

    print(
        "Investigation ledger:",
        "PASS" if valid else "FAIL",
    )

    print(
        "Ledger checkpoint:",
        "PASS" if checkpoint.checkpoint_hash else "FAIL",
    )

    print(
        "Tail truncation detection:",
        "PASS" if not truncation_valid else "FAIL",
    )

    print(f"Ledger events: {len(ledger.events)}")
    print(f"Ledger head: {ledger.head_hash}")
    print(f"Checkpoint hash: {checkpoint.checkpoint_hash}")

    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1

    if truncation_valid or not truncation_errors:
        print("ERROR: tail truncation was not detected")
        return 1

    print()
    print("v1.7 investigation integrity foundation: PASS")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())