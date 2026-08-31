from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from v17_integrity import (
    InvestigationLedger,
    LedgerCheckpoint,
    canonical_json_bytes,
    sha256_bytes,
)


SIGNED_CHECKPOINT_SCHEMA = "ai-dfir/signed-ledger-checkpoint/v1.7"
SIGNATURE_ALGORITHM = "Ed25519"
KEY_ID_ALGORITHM = "sha256"


def public_key_bytes(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def key_id_from_public_key_bytes(value: bytes) -> str:
    return f"{KEY_ID_ALGORITHM}:{sha256_bytes(value)}"


@dataclass(frozen=True)
class SignedLedgerCheckpoint:
    checkpoint: LedgerCheckpoint
    key_id: str
    public_key_hex: str
    signature_hex: str
    signed_at: str
    schema: str = SIGNED_CHECKPOINT_SCHEMA
    signature_algorithm: str = SIGNATURE_ALGORITHM

    @staticmethod
    def signature_material(
        *,
        checkpoint: LedgerCheckpoint,
        key_id: str,
        signed_at: str,
    ) -> dict[str, str]:
        return {
            "schema": SIGNED_CHECKPOINT_SCHEMA,
            "signature_algorithm": SIGNATURE_ALGORITHM,
            "key_id": key_id,
            "signed_at": signed_at,
            "checkpoint_hash": checkpoint.checkpoint_hash,
        }

    @classmethod
    def sign(
        cls,
        *,
        checkpoint: LedgerCheckpoint,
        private_key: Ed25519PrivateKey,
        signed_at: str,
    ) -> "SignedLedgerCheckpoint":
        public_key = private_key.public_key()
        raw_public_key = public_key_bytes(public_key)
        key_id = key_id_from_public_key_bytes(raw_public_key)

        material = cls.signature_material(
            checkpoint=checkpoint,
            key_id=key_id,
            signed_at=signed_at,
        )

        signature = private_key.sign(
            canonical_json_bytes(material)
        )

        return cls(
            checkpoint=checkpoint,
            key_id=key_id,
            public_key_hex=raw_public_key.hex(),
            signature_hex=signature.hex(),
            signed_at=signed_at,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "signature_algorithm": self.signature_algorithm,
            "key_id": self.key_id,
            "public_key_hex": self.public_key_hex,
            "signature_hex": self.signature_hex,
            "signed_at": self.signed_at,
            "checkpoint": asdict(self.checkpoint),
        }

    def verify_signature(self) -> tuple[bool, list[str]]:
        errors: list[str] = []

        if self.schema != SIGNED_CHECKPOINT_SCHEMA:
            errors.append("signature: unsupported schema")

        if self.signature_algorithm != SIGNATURE_ALGORITHM:
            errors.append(
                "signature: unsupported signature_algorithm"
            )

        try:
            raw_public_key = bytes.fromhex(
                self.public_key_hex
            )
        except ValueError:
            errors.append("signature: malformed public key")
            return False, errors

        if len(raw_public_key) != 32:
            errors.append(
                "signature: invalid Ed25519 public key length"
            )
            return False, errors

        derived_key_id = key_id_from_public_key_bytes(
            raw_public_key
        )

        if self.key_id != derived_key_id:
            errors.append("signature: key_id mismatch")

        try:
            signature = bytes.fromhex(self.signature_hex)
        except ValueError:
            errors.append("signature: malformed signature")
            return False, errors

        if len(signature) != 64:
            errors.append(
                "signature: invalid Ed25519 signature length"
            )
            return False, errors

        material = self.signature_material(
            checkpoint=self.checkpoint,
            key_id=self.key_id,
            signed_at=self.signed_at,
        )

        try:
            public_key = Ed25519PublicKey.from_public_bytes(
                raw_public_key
            )
            public_key.verify(
                signature,
                canonical_json_bytes(material),
            )
        except (InvalidSignature, ValueError):
            errors.append(
                "signature: Ed25519 verification failed"
            )

        return not errors, errors

    def verify_trusted(
        self,
        trusted_public_keys: Mapping[str, bytes],
    ) -> tuple[bool, list[str]]:
        valid, errors = self.verify_signature()

        if not valid:
            return False, errors

        trusted_key = trusted_public_keys.get(self.key_id)

        if trusted_key is None:
            errors.append(
                "signature: key_id is not trusted"
            )
            return False, errors

        raw_public_key = bytes.fromhex(
            self.public_key_hex
        )

        if trusted_key != raw_public_key:
            errors.append(
                "signature: trusted public key mismatch"
            )

        return not errors, errors


def verify_signed_checkpoint(
    *,
    ledger: InvestigationLedger,
    signed_checkpoint: SignedLedgerCheckpoint,
    trusted_public_keys: Mapping[str, bytes],
) -> tuple[bool, list[str]]:
    ledger_valid, ledger_errors = ledger.verify(
        signed_checkpoint.checkpoint
    )

    signature_valid, signature_errors = (
        signed_checkpoint.verify_trusted(
            trusted_public_keys
        )
    )

    errors = ledger_errors + signature_errors

    return (
        ledger_valid and signature_valid,
        errors,
    )