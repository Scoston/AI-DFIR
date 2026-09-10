#!/usr/bin/env python3
"""Bounded synthetic qualification for AI-DFIR v1.8 credential lineage."""
from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import v18_agent_execution_record as aer
import v18_credential_lineage as lineage

SCHEMA = "ai-dfir/credential-lineage-qualification/v1.8"
MAX_HOPS = 2_000
MAX_PRINCIPALS = 64
OBSERVED_AT = "2026-09-10T14:00:00Z"


def _b64(value: object) -> str:
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _jwt(index: int, principal: str, scopes: list[str], audience: str) -> bytes:
    claims = {
        "iss": "https://synthetic-idp.example",
        "sub": principal,
        "aud": audience,
        "client_id": f"synthetic-client-{index % 16}",
        "scope": " ".join(scopes),
        "iat": 1789048800 + index,
        "exp": 1789056000 + index,
        "jti": f"synthetic-jti-{index:06d}",
    }
    if index > 0:
        claims["act"] = {"sub": f"principal-{(index - 1) % 16:02d}", "client_id": f"synthetic-client-{(index - 1) % 16}"}
    if index % 97 == 0:
        claims["exp"] = 1
    if index % 131 == 0:
        claims["nbf"] = 4102444800
    header = {"alg": "RS256", "typ": "at+jwt", "kid": f"synthetic-kid-{index % 4}"}
    return f"{_b64(header)}.{_b64(claims)}.c3ludGhldGljLXNpZw".encode("ascii")


def qualify(*, hops: int, principal_count: int, out_dir: Path) -> dict:
    if not 2 <= hops <= MAX_HOPS:
        raise ValueError("hops must be between 2 and 2000")
    if not 2 <= principal_count <= MAX_PRINCIPALS:
        raise ValueError("principal_count must be between 2 and 64")

    out_dir.mkdir(parents=True, exist_ok=True)
    principals = [
        lineage.principal(
            f"principal-{index:02d}", kind="human" if index == 0 else "agent",
            observed_at=OBSERVED_AT, provider="synthetic-idp" if index == 0 else "synthetic-agent-runtime",
            attributes={"synthetic": True, "ordinal": index},
        )
        for index in range(principal_count)
    ]

    credentials = []
    jwt_structures = []
    raw_tokens = []
    for index in range(hops + 1):
        scopes = ["read", "investigate"]
        if index % 3:
            scopes.append("contain")
        if index % 5 == 0:
            scopes.append("admin")
        principal_id = f"principal-{index % principal_count:02d}"
        raw = _jwt(index, principal_id, scopes, f"api-{index % 8}")
        raw_tokens.append(raw)
        credential_id = f"credential-{index:06d}"
        credentials.append(lineage.credential_observation(
            credential_id, raw, credential_type="oauth-access-token", observed_at=OBSERVED_AT,
            scheme="Bearer", source_locator=f"synthetic-exchange:{index}",
            metadata={"synthetic": True, "transport": "https", "ordinal": index},
        ))
        jwt_structures.append(lineage.jwt_structure(raw, observed_at=OBSERVED_AT, credential_id=credential_id))

    mechanisms = sorted(lineage.HOP_MECHANISMS - {"other"})
    hop_records = []
    presentations = []
    for index in range(hops):
        source = f"principal-{index % principal_count:02d}"
        target = f"principal-{(index + 1) % principal_count:02d}"
        scopes = ["read", "investigate"] + (["contain"] if index % 2 == 0 else [])
        hop_records.append(lineage.delegation_hop(
            f"hop-{index:06d}", mechanism=mechanisms[index % len(mechanisms)], observed_at=OBSERVED_AT,
            input_credential_id=f"credential-{index:06d}", output_credential_id=f"credential-{index + 1:06d}",
            source_principal_id=source, target_principal_id=target,
            issuer="https://synthetic-idp.example", audience=f"api-{(index + 1) % 8}", scopes=scopes,
            authorization_decision="allowed" if index % 4 else "unknown",
            policy_context={"synthetic": True, "policy_revision": f"rev-{index % 7}"},
            approval_context={"synthetic": True, "approval_observed": index % 11 == 0},
        ))
        presentations.append(lineage.presentation(
            f"presentation-{index:06d}", credential_id=f"credential-{index + 1:06d}",
            presenter_principal_id=target, observed_at=OBSERVED_AT,
            target=f"synthetic-api:/resource/{index}", audience=f"api-{(index + 1) % 8}", scopes=scopes,
            authorization_decision="allowed" if index % 4 else "not-observed",
        ))

    # Deliberately reuse the last credential across two distinct observed presenters.
    presentations.extend([
        lineage.presentation("presentation-reuse-a", credential_id=f"credential-{hops:06d}",
                             presenter_principal_id="principal-00", observed_at=OBSERVED_AT,
                             target="synthetic-api:/reuse/a", authorization_decision="not-observed"),
        lineage.presentation("presentation-reuse-b", credential_id=f"credential-{hops:06d}",
                             presenter_principal_id="principal-01", observed_at=OBSERVED_AT,
                             target="synthetic-api:/reuse/b", authorization_decision="not-observed"),
    ])

    report = lineage.build_lineage(
        lineage_id="synthetic/credential-lineage-v18-qualification",
        credentials=credentials, principals=principals, hops=hop_records,
        presentations=presentations, jwt_structures=jwt_structures,
    )
    lineage.validate_lineage(report)
    bundle = lineage.to_aer(report, record_id="synthetic/credential-lineage-v18-aer")
    lineage.validate_aer_binding(bundle, report=report)

    serialized = aer.canonical_bytes({"report": report, "bundle": bundle})
    leaked_raw_credentials = sum(raw in serialized for raw in raw_tokens)
    if leaked_raw_credentials:
        raise RuntimeError("synthetic reusable credential material leaked into retained lineage evidence")

    delegation_edges = [edge for edge in bundle["aer"]["edges"] if edge["relationship"] == "delegated_authority"]
    presentation_edges = [edge for edge in bundle["aer"]["edges"] if edge["edge_id"].startswith("edge:presentation:")]
    if any(edge["relationship"] == "delegated_authority" for edge in presentation_edges):
        raise RuntimeError("credential presentation was inflated into delegated authority")

    scope_expansions = sum(item["scope_expansion_observed"] for item in report["diagnostics"]["scope_changes"])
    scope_reductions = sum(item["scope_reduction_observed"] for item in report["diagnostics"]["scope_changes"])
    expired = sum(item["expired_at_observation"] for item in report["diagnostics"]["jwt_temporal_observations"])
    not_yet_valid = sum(item["not_yet_valid_at_observation"] for item in report["diagnostics"]["jwt_temporal_observations"])
    multi_presenter = sum(item["multiple_presenters"] for item in report["diagnostics"]["credential_fingerprint_reuse"])

    receipt = {
        "schema": SCHEMA,
        "profile": {
            "credential_lineage_schema": lineage.LINEAGE_SCHEMA,
            "aer_binding_schema": lineage.AER_BINDING_SCHEMA,
            "jwt_profile": "compact-three-part-structural-observation",
            "delegation_models": ["RFC 8693 actor/subject pivots", "cloud/service impersonation observations"],
        },
        "population": {
            "hops": hops, "credentials": len(credentials), "principals": len(principals),
            "jwt_structures": len(jwt_structures), "presentations": len(presentations),
        },
        "observations": {
            "delegated_authority_edges": len(delegation_edges),
            "presentation_edges": len(presentation_edges),
            "scope_expansions": scope_expansions,
            "scope_reductions": scope_reductions,
            "expired_structural_tokens": expired,
            "not_yet_valid_structural_tokens": not_yet_valid,
            "multi_presenter_fingerprints": multi_presenter,
            "raw_credential_values_retained": False,
            "presentation_inflated_to_delegation": False,
            "missing_credential_ids": len(report["diagnostics"]["missing_credential_ids"]),
            "missing_principal_ids": len(report["diagnostics"]["missing_principal_ids"]),
            "aer_nodes": len(bundle["aer"]["nodes"]),
            "aer_edges": len(bundle["aer"]["edges"]),
        },
        "bindings": {
            "lineage_sha256": report["lineage_sha256"],
            "aer_record_sha256": bundle["aer"]["record_sha256"],
            "aer_bundle_sha256": bundle["bundle_sha256"],
        },
        "claims": {
            "synthetic_profile_qualified": True,
            "credential_authenticity_verified": False,
            "jwt_signature_verified": False,
            "issuer_trust_verified": False,
            "principal_control_proven": False,
            "human_intent_proven": False,
            "lineage_complete": False,
            "live_provider_interoperability_verified": False,
            "production_scale_qualified": False,
            "private_reasoning_captured": False,
        },
    }
    receipt["receipt_sha256"] = aer.sha256_bytes(aer.canonical_bytes(receipt))
    (out_dir / "qualification-receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "lineage-summary.json").write_text(json.dumps({
        "lineage_sha256": report["lineage_sha256"],
        "credentials": len(report["credentials"]), "principals": len(report["principals"]),
        "hops": len(report["hops"]), "presentations": len(report["presentations"]),
        "scope_expansions": scope_expansions, "scope_reductions": scope_reductions,
        "multi_presenter_fingerprints": multi_presenter,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out_dir / "aer-summary.json").write_text(json.dumps({
        "record_sha256": bundle["aer"]["record_sha256"], "bundle_sha256": bundle["bundle_sha256"],
        "nodes": len(bundle["aer"]["nodes"]), "edges": len(bundle["aer"]["edges"]),
        "delegated_authority_edges": len(delegation_edges), "presentation_edges": len(presentation_edges),
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hops", type=int, default=512)
    parser.add_argument("--principals", type=int, default=16)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    receipt = qualify(hops=args.hops, principal_count=args.principals, out_dir=args.out_dir)
    print(json.dumps({"status": "PASS", "receipt_sha256": receipt["receipt_sha256"],
                      **receipt["population"], **receipt["observations"]}, sort_keys=True))


if __name__ == "__main__":
    main()
