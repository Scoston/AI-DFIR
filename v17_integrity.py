from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable

import rfc8785


HASH_ALGORITHM = "sha256"
CANONICALIZATION = "RFC8785"
CHECKPOINT_SCHEMA = "ai-dfir/investigation-ledger-checkpoint/v1.7"


def canonical_json_bytes(value: Any) -> bytes:
    """Return RFC 8785 canonical JSON encoded as UTF-8 bytes."""
    return rfc8785.dumps(value)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_object(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


@dataclass(frozen=True)
class EvidenceArtifact:
    case_id: str
    artifact_id: str
    sha256: str
    media_type: str | None = None
    source_name: str | None = None
    acquired_at: str | None = None
    classification: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_bytes(
        cls,
        *,
        case_id: str,
        artifact_id: str,
        content: bytes,
        media_type: str | None = None,
        source_name: str | None = None,
        acquired_at: str | None = None,
        classification: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> "EvidenceArtifact":
        return cls(
            case_id=case_id,
            artifact_id=artifact_id,
            sha256=sha256_bytes(content),
            media_type=media_type,
            source_name=source_name,
            acquired_at=acquired_at,
            classification=classification,
            metadata=metadata or {},
        )

    @property
    def integrity_id(self) -> str:
        return sha256_object(asdict(self))


@dataclass(frozen=True)
class EvidenceRelationship:
    case_id: str
    parent_artifact_id: str
    child_artifact_id: str
    relationship_type: str
    transformation: str | None = None
    transformation_version: str | None = None
    actor: str | None = None
    created_at: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def integrity_id(self) -> str:
        return sha256_object(asdict(self))


@dataclass(frozen=True)
class AIProvenanceRecord:
    case_id: str
    invocation_id: str
    provider: str
    model: str
    model_version: str | None = None
    request_id: str | None = None
    timestamp: str | None = None
    policy_config_id: str | None = None
    evidence_refs: tuple[str, ...] = ()
    retrieval_refs: tuple[str, ...] = ()
    tool_calls: tuple[str, ...] = ()
    structured_output: dict[str, Any] = field(default_factory=dict)
    confidence: float | None = None

    @property
    def integrity_id(self) -> str:
        return sha256_object(asdict(self))


@dataclass(frozen=True)
class AnalystDecisionRecord:
    case_id: str
    decision_id: str
    analyst_id: str
    target_id: str
    disposition: str
    timestamp: str
    rationale: str | None = None
    evidence_refs: tuple[str, ...] = ()

    @property
    def integrity_id(self) -> str:
        return sha256_object(asdict(self))


@dataclass(frozen=True)
class InvestigationEvent:
    sequence: int
    case_id: str
    event_type: str
    timestamp: str
    actor: str
    payload: dict[str, Any]
    previous_hash: str | None
    entry_hash: str

    @staticmethod
    def hash_material(
        *,
        sequence: int,
        case_id: str,
        event_type: str,
        timestamp: str,
        actor: str,
        payload: dict[str, Any],
        previous_hash: str | None,
    ) -> dict[str, Any]:
        return {
            "sequence": sequence,
            "case_id": case_id,
            "event_type": event_type,
            "timestamp": timestamp,
            "actor": actor,
            "payload": payload,
            "previous_hash": previous_hash,
        }

    @classmethod
    def create(
        cls,
        *,
        sequence: int,
        case_id: str,
        event_type: str,
        timestamp: str,
        actor: str,
        payload: dict[str, Any],
        previous_hash: str | None,
    ) -> "InvestigationEvent":
        material = cls.hash_material(
            sequence=sequence,
            case_id=case_id,
            event_type=event_type,
            timestamp=timestamp,
            actor=actor,
            payload=payload,
            previous_hash=previous_hash,
        )

        return cls(
            **material,
            entry_hash=sha256_object(material),
        )

    def verify_hash(self) -> bool:
        material = self.hash_material(
            sequence=self.sequence,
            case_id=self.case_id,
            event_type=self.event_type,
            timestamp=self.timestamp,
            actor=self.actor,
            payload=self.payload,
            previous_hash=self.previous_hash,
        )

        return self.entry_hash == sha256_object(material)


@dataclass(frozen=True)
class LedgerCheckpoint:
    case_id: str
    event_count: int
    head_hash: str | None
    created_at: str
    schema: str = CHECKPOINT_SCHEMA
    hash_algorithm: str = HASH_ALGORITHM
    canonicalization: str = CANONICALIZATION

    @property
    def checkpoint_hash(self) -> str:
        """
        Hash suitable for later signing or external anchoring.

        This hash alone is not an external trust anchor.
        """
        return sha256_object(asdict(self))


class InvestigationLedger:
    def __init__(
        self,
        case_id: str,
        events: Iterable[InvestigationEvent] | None = None,
    ):
        self.case_id = case_id
        self._events: list[InvestigationEvent] = list(events or [])

    @property
    def events(self) -> tuple[InvestigationEvent, ...]:
        return tuple(self._events)

    @property
    def head_hash(self) -> str | None:
        if not self._events:
            return None
        return self._events[-1].entry_hash

    def append(
        self,
        *,
        event_type: str,
        timestamp: str,
        actor: str,
        payload: dict[str, Any],
    ) -> InvestigationEvent:
        event = InvestigationEvent.create(
            sequence=len(self._events) + 1,
            case_id=self.case_id,
            event_type=event_type,
            timestamp=timestamp,
            actor=actor,
            payload=payload,
            previous_hash=self.head_hash,
        )

        self._events.append(event)
        return event

    def checkpoint(self, *, created_at: str) -> LedgerCheckpoint:
        return LedgerCheckpoint(
            case_id=self.case_id,
            event_count=len(self._events),
            head_hash=self.head_hash,
            created_at=created_at,
        )

    def verify(
        self,
        checkpoint: LedgerCheckpoint | None = None,
    ) -> tuple[bool, list[str]]:
        errors: list[str] = []
        expected_previous: str | None = None

        for expected_sequence, event in enumerate(self._events, start=1):
            if event.case_id != self.case_id:
                errors.append(
                    f"event {expected_sequence}: case_id mismatch "
                    f"({event.case_id!r} != {self.case_id!r})"
                )

            if event.sequence != expected_sequence:
                errors.append(
                    f"event {expected_sequence}: sequence mismatch "
                    f"({event.sequence} != {expected_sequence})"
                )

            if event.previous_hash != expected_previous:
                errors.append(
                    f"event {expected_sequence}: previous_hash mismatch"
                )

            if not event.verify_hash():
                errors.append(
                    f"event {expected_sequence}: entry_hash mismatch"
                )

            expected_previous = event.entry_hash

        if checkpoint is not None:
            if checkpoint.schema != CHECKPOINT_SCHEMA:
                errors.append("checkpoint: unsupported schema")

            if checkpoint.case_id != self.case_id:
                errors.append("checkpoint: case_id mismatch")

            if checkpoint.hash_algorithm != HASH_ALGORITHM:
                errors.append("checkpoint: unsupported hash_algorithm")

            if checkpoint.canonicalization != CANONICALIZATION:
                errors.append("checkpoint: unsupported canonicalization")

            if checkpoint.event_count != len(self._events):
                errors.append(
                    "checkpoint: event_count mismatch "
                    f"({checkpoint.event_count} != {len(self._events)})"
                )

            if checkpoint.head_hash != self.head_hash:
                errors.append("checkpoint: head_hash mismatch")

        return (not errors, errors)

    def to_jsonl(self) -> str:
        if not self._events:
            return ""

        return (
            "\n".join(
                canonical_json_bytes(asdict(event)).decode("utf-8")
                for event in self._events
            )
            + "\n"
        )