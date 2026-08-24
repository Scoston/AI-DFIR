#!/usr/bin/env python3
"""Ed25519 node identity and canonical signed fleet messages."""
from __future__ import annotations
import argparse, base64, hashlib, json, os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def key_id(pub):
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()[:32]


def generate(private_path: Path, public_path: Path):
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_bytes(priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    os.chmod(private_path, 0o600)
    public_path.write_bytes(pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    return key_id(pub)


def load_private(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def load_public(path: Path):
    return serialization.load_pem_public_key(path.read_bytes())


def sign_payload(private_path: Path, payload: dict):
    priv = load_private(private_path)
    body = canonical(payload)
    sig = priv.sign(body)
    return {
        "payload": payload,
        "signature": base64.b64encode(sig).decode("ascii"),
        "key_id": key_id(priv.public_key()),
        "algorithm": "Ed25519",
        "payload_sha256": hashlib.sha256(body).hexdigest(),
    }


def verify_envelope(public_path: Path, envelope: dict):
    pub = load_public(public_path)
    if envelope.get("algorithm") != "Ed25519":
        raise ValueError("Unsupported signature algorithm")
    if envelope.get("key_id") != key_id(pub):
        raise ValueError("Key ID mismatch")
    body = canonical(envelope["payload"])
    digest = hashlib.sha256(body).hexdigest()
    if digest != envelope.get("payload_sha256"):
        raise ValueError("Payload SHA-256 mismatch")
    sig = base64.b64decode(envelope["signature"])
    pub.verify(sig, body)
    return envelope["payload"]


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)
    p = sp.add_parser("keygen")
    p.add_argument("--private", required=True)
    p.add_argument("--public", required=True)
    args = ap.parse_args()
    if args.cmd == "keygen":
        kid = generate(Path(args.private), Path(args.public))
        print(json.dumps({"key_id": kid, "private": args.private, "public": args.public}, indent=2))


if __name__ == "__main__":
    main()
