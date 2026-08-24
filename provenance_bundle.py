#!/usr/bin/env python3
"""
AI-DFIR v0.4 execution-provenance bundle.

Uses:
- in-toto Statement v1 shape
- a CUSTOM AI-DFIR predicate type
- DSSE pre-authentication encoding (PAE)
- Ed25519 signatures

This is not labeled as SLSA build provenance because an inference execution is
not a software build. SLSA/in-toto concepts are reused for verifiable provenance.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "urn:ai-dfir:execution-provenance:v0.4"
PAYLOAD_TYPE = "application/vnd.in-toto+json"


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_file(path: Path, chunk=8 * 1024 * 1024):
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def file_descriptor(path: Path, base: Path | None = None):
    p = path.resolve()
    st = p.stat()
    return {
        "path": str(p.relative_to(base.resolve())) if base else str(p),
        "size": st.st_size,
        "sha256": sha256_file(p),
    }


def tree_descriptor(path: Path):
    path = path.resolve()
    rows = []
    for p in sorted(path.rglob("*")):
        if p.is_file():
            rows.append(file_descriptor(p, path))
    tree_hash = hashlib.sha256(canonical_json(rows)).hexdigest()
    return {
        "path": str(path),
        "kind": "directory",
        "file_count": len(rows),
        "tree_sha256": tree_hash,
        "files": rows,
    }


def describe_path(path: Path):
    path = path.resolve()
    if path.is_dir():
        return tree_descriptor(path)
    d = file_descriptor(path)
    d["kind"] = "file"
    return d


def parse_named_paths(values: List[str]):
    result = []
    for v in values:
        if "=" not in v:
            raise ValueError(f"Expected NAME=PATH, got {v!r}")
        name, raw = v.split("=", 1)
        p = Path(raw)
        if not p.exists():
            raise FileNotFoundError(p)
        result.append((name, p))
    return result


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    # DSSE PAE("DSSEv1", payloadType, payload)
    return (
        b"DSSEv1 "
        + str(len(payload_type.encode("utf-8"))).encode("ascii")
        + b" "
        + payload_type.encode("utf-8")
        + b" "
        + str(len(payload)).encode("ascii")
        + b" "
        + payload
    )


def key_id(public_key: Ed25519PublicKey):
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()[:32]


def keygen(private_path: Path, public_path: Path):
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_bytes(
        priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    os.chmod(private_path, 0o600)
    public_path.write_bytes(
        pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    print(f"Private key: {private_path}")
    print(f"Public key:  {public_path}")
    print(f"Key ID:      {key_id(pub)}")


def load_private(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def load_public(path: Path):
    return serialization.load_pem_public_key(path.read_bytes())


def copy_evidence(named_paths, evidence_dir: Path):
    copied = []
    evidence_dir.mkdir(parents=True, exist_ok=True)
    for name, src in named_paths:
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in name)
        target = evidence_dir / safe
        if src.is_dir():
            shutil.copytree(src, target, dirs_exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, target)
        copied.append((name, target))
    return copied


def bundle(args):
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    evidence_dir = out / "evidence"

    materials_src = parse_named_paths(args.material or [])
    artifacts_src = parse_named_paths(args.artifact or [])

    # Copy evidence into a self-contained case package by default. Large model
    # checkpoints should normally be supplied as materials with --no-copy.
    if args.no_copy:
        materials = materials_src
        artifacts = artifacts_src
    else:
        materials = copy_evidence(materials_src, evidence_dir / "materials")
        artifacts = copy_evidence(artifacts_src, evidence_dir / "artifacts")

    material_desc = [{"name": n, **describe_path(p)} for n, p in materials]
    artifact_desc = [{"name": n, **describe_path(p)} for n, p in artifacts]
    if not args.no_copy:
        for desc in material_desc + artifact_desc:
            pp = Path(desc["path"])
            desc["path"] = str(pp.relative_to(out))

    evidence_manifest = {
        "schema": "ai-dfir/evidence-manifest/v0.4",
        "created_utc": utc_now(),
        "case_id": args.case_id,
        "inference_id": args.inference_id,
        "materials": material_desc,
        "artifacts": artifact_desc,
        "privacy": {
            "prompt_text_included": False,
            "response_text_included": False,
            "note": "Content is included only if explicitly supplied as an evidence artifact.",
        },
    }
    manifest_path = out / "evidence_manifest.json"
    manifest_path.write_text(json.dumps(evidence_manifest, indent=2, sort_keys=True), encoding="utf-8")
    manifest_digest = sha256_file(manifest_path)

    subject = [{
        "name": f"ai-dfir-case/{args.case_id}/inference/{args.inference_id}",
        "digest": {"sha256": manifest_digest},
    }]

    predicate = {
        "caseId": args.case_id,
        "inferenceId": args.inference_id,
        "createdUtc": utc_now(),
        "evidenceManifest": {
            "path": manifest_path.name,
            "sha256": manifest_digest,
        },
        "materials": [
            {
                "name": d["name"],
                "digest": {
                    "sha256": d.get("sha256") or d.get("tree_sha256")
                },
                "kind": d["kind"],
            }
            for d in material_desc
        ],
        "artifacts": [
            {
                "name": d["name"],
                "digest": {
                    "sha256": d.get("sha256") or d.get("tree_sha256")
                },
                "kind": d["kind"],
            }
            for d in artifact_desc
        ],
        "executionContext": {
            "model": args.model,
            "modelRevision": args.model_revision,
            "host": args.host,
            "gpuAttestationEvidencePresent": bool(args.gpu_attestation),
            "toolTracePresent": bool(args.tool_trace),
        },
    }

    if args.gpu_attestation:
        p = Path(args.gpu_attestation)
        predicate["gpuAttestation"] = {
            "sha256": sha256_file(p),
            "path": str(p.resolve()),
        }
    if args.tool_trace:
        p = Path(args.tool_trace)
        predicate["toolTrace"] = {
            "sha256": sha256_file(p),
            "path": str(p.resolve()),
        }

    statement = {
        "_type": STATEMENT_TYPE,
        "subject": subject,
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }
    statement_bytes = canonical_json(statement)
    statement_path = out / "statement.json"
    statement_path.write_bytes(statement_bytes + b"\n")

    priv = load_private(Path(args.private_key))
    pub = priv.public_key()
    sig = priv.sign(dsse_pae(PAYLOAD_TYPE, statement_bytes))

    envelope = {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(statement_bytes).decode("ascii"),
        "signatures": [{
            "keyid": key_id(pub),
            "sig": base64.b64encode(sig).decode("ascii"),
        }],
    }
    env_path = out / "attestation.dsse.json"
    env_path.write_text(json.dumps(envelope, indent=2, sort_keys=True), encoding="utf-8")

    pub_path = out / "signing_public_key.pem"
    pub_path.write_bytes(
        pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    head = {
        "case_id": args.case_id,
        "inference_id": args.inference_id,
        "evidence_manifest_sha256": manifest_digest,
        "statement_sha256": hashlib.sha256(statement_bytes).hexdigest(),
        "dsse_envelope_sha256": sha256_file(env_path),
        "signing_key_id": key_id(pub),
        "created_utc": utc_now(),
    }
    (out / "BUNDLE_HEAD.json").write_text(json.dumps(head, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(head, indent=2, sort_keys=True))


def verify_bundle(bundle_dir: Path, public_key_path: Path | None):
    env_path = bundle_dir / "attestation.dsse.json"
    env = json.loads(env_path.read_text(encoding="utf-8"))
    payload_type = env["payloadType"]
    payload = base64.b64decode(env["payload"])
    statement = json.loads(payload)

    pub_path = public_key_path or (bundle_dir / "signing_public_key.pem")
    pub = load_public(pub_path)
    sig = base64.b64decode(env["signatures"][0]["sig"])
    pub.verify(sig, dsse_pae(payload_type, payload))

    manifest_path = bundle_dir / statement["predicate"]["evidenceManifest"]["path"]
    expected = statement["predicate"]["evidenceManifest"]["sha256"]
    actual = sha256_file(manifest_path)
    if expected != actual:
        raise RuntimeError("Evidence manifest digest mismatch")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    mismatches = []
    # Verify copied/local evidence if it is accessible.
    for section in ("materials", "artifacts"):
        for d in manifest.get(section, []):
            p = Path(d["path"])
            if not p.is_absolute():
                p = bundle_dir / p
            if not p.exists():
                continue
            actual_desc = describe_path(p)
            want = d.get("sha256") or d.get("tree_sha256")
            got = actual_desc.get("sha256") or actual_desc.get("tree_sha256")
            if want != got:
                mismatches.append({"name": d["name"], "expected": want, "actual": got})

    if mismatches:
        raise RuntimeError(f"Evidence file/tree digest mismatch: {mismatches}")

    result = {
        "valid": True,
        "key_id": key_id(pub),
        "statement_type": statement.get("_type"),
        "predicate_type": statement.get("predicateType"),
        "case_id": statement["predicate"].get("caseId"),
        "inference_id": statement["predicate"].get("inferenceId"),
        "manifest_sha256": actual,
        "envelope_sha256": sha256_file(env_path),
    }
    print(json.dumps(result, indent=2, sort_keys=True))


def selftest(out: Path):
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    kpriv = out / "key.pem"
    kpub = out / "key.pub.pem"
    keygen(kpriv, kpub)

    sample = out / "sample.txt"
    sample.write_text("forensic evidence\n", encoding="utf-8")
    bundle_dir = out / "bundle"

    class A:
        pass
    a = A()
    a.out = str(bundle_dir)
    a.material = [f"sample={sample}"]
    a.artifact = []
    a.no_copy = False
    a.case_id = "SELFTEST"
    a.inference_id = "INF-001"
    a.model = "synthetic"
    a.model_revision = "test"
    a.host = "localhost"
    a.gpu_attestation = None
    a.tool_trace = None
    a.private_key = str(kpriv)
    bundle(a)
    verify_bundle(bundle_dir, kpub)

    # Tamper with the copied evidence. Verification must fail.
    copied = bundle_dir / "evidence" / "materials" / "sample"
    copied.write_text("tampered\n", encoding="utf-8")
    rejected = False
    try:
        verify_bundle(bundle_dir, kpub)
    except Exception:
        rejected = True
    if not rejected:
        raise RuntimeError("selftest failed: tampered evidence accepted")

    result = {"status": "PASS", "tampered_evidence_rejected": True}
    (out / "SELFTEST.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))


def main():
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd", required=True)

    p = sp.add_parser("keygen")
    p.add_argument("--private", required=True)
    p.add_argument("--public", required=True)

    p = sp.add_parser("bundle")
    p.add_argument("--case-id", required=True)
    p.add_argument("--inference-id", required=True)
    p.add_argument("--private-key", required=True)
    p.add_argument("--model", default=None)
    p.add_argument("--model-revision", default=None)
    p.add_argument("--host", default=None)
    p.add_argument("--material", action="append", default=[],
                   help="Repeatable NAME=PATH input/provenance material")
    p.add_argument("--artifact", action="append", default=[],
                   help="Repeatable NAME=PATH produced evidence artifact")
    p.add_argument("--gpu-attestation", default=None)
    p.add_argument("--tool-trace", default=None)
    p.add_argument("--no-copy", action="store_true",
                   help="Reference and digest evidence in place instead of copying")
    p.add_argument("--out", required=True)

    p = sp.add_parser("verify")
    p.add_argument("--bundle", required=True)
    p.add_argument("--public-key", default=None)

    p = sp.add_parser("selftest")
    p.add_argument("--out", required=True)

    args = ap.parse_args()
    if args.cmd == "keygen":
        keygen(Path(args.private), Path(args.public))
    elif args.cmd == "bundle":
        bundle(args)
    elif args.cmd == "verify":
        verify_bundle(
            Path(args.bundle),
            Path(args.public_key) if args.public_key else None,
        )
    elif args.cmd == "selftest":
        selftest(Path(args.out))


if __name__ == "__main__":
    main()
