from __future__ import annotations

import base64
import json
from copy import deepcopy

import pytest

import v18_credential_lineage as lineage

T0 = "2026-09-10T13:00:00Z"
T1 = "2026-09-10T13:00:01Z"
T2 = "2026-09-10T13:00:02Z"


def _b64(value: object) -> str:
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _jwt(claims: dict, header: dict | None = None) -> bytes:
    return f"{_b64(header or {'alg': 'RS256', 'typ': 'at+jwt', 'kid': 'kid-1'})}.{_b64(claims)}.c2ln".encode()


def _sample():
    raw_a = _jwt({
        "iss": "https://issuer.example", "sub": "human-1", "aud": "broker",
        "client_id": "client-1", "scope": "read investigate", "iat": 1789045200,
        "exp": 1789048800, "jti": "jti-a",
    })
    raw_b = _jwt({
        "iss": "https://issuer.example", "sub": "agent-1", "aud": ["identity-api"],
        "client_id": "agent-client", "scope": "read investigate disable", "iat": 1789045201,
        "exp": 1789048801, "jti": "jti-b", "act": {"sub": "human-1", "client_id": "client-1"},
    })
    credentials = [
        lineage.credential_observation("cred-a", raw_a, credential_type="oauth-access-token", observed_at=T0,
                                       scheme="Bearer", metadata={"transport": "https", "header_present": True}),
        lineage.credential_observation("cred-b", raw_b, credential_type="oauth-access-token", observed_at=T1,
                                       scheme="Bearer", metadata={"transport": "https", "header_present": True}),
    ]
    principals = [
        lineage.principal("human-1", kind="human", observed_at=T0, provider="synthetic-idp"),
        lineage.principal("agent-1", kind="agent", observed_at=T1, provider="synthetic-agent"),
    ]
    jwts = [
        lineage.jwt_structure(raw_a, observed_at=T0, credential_id="cred-a"),
        lineage.jwt_structure(raw_b, observed_at=T1, credential_id="cred-b"),
    ]
    hops = [lineage.delegation_hop(
        "hop-1", mechanism="oauth-token-exchange", observed_at=T1,
        input_credential_id="cred-a", output_credential_id="cred-b",
        source_principal_id="human-1", target_principal_id="agent-1",
        issuer="https://issuer.example", audience="identity-api",
        scopes=["read", "investigate", "disable"], authorization_decision="allowed",
        policy_context={"policy_revision": "rev-7"}, approval_context={"approval_id": "approval-1"},
    )]
    presentations = [
        lineage.presentation("present-1", credential_id="cred-b", presenter_principal_id="agent-1",
                             observed_at=T2, target="identity-api:/users/alice:disable",
                             audience="identity-api", scopes=["disable"], authorization_decision="allowed"),
        lineage.presentation("present-2", credential_id="cred-b", presenter_principal_id="human-1",
                             observed_at=T2, target="identity-api:/users/bob:read",
                             audience="identity-api", scopes=["read"], authorization_decision="not-observed"),
    ]
    return credentials, principals, jwts, hops, presentations


def test_credential_fingerprint_does_not_retain_raw_secret():
    raw = b"synthetic-high-entropy-bearer-value"
    record = lineage.credential_observation("cred-1", raw, credential_type="opaque", observed_at=T0,
                                            metadata={"transport": "https"})
    serialized = json.dumps(record, sort_keys=True)
    assert raw.decode() not in serialized
    assert record["claims"]["raw_credential_retained"] is False
    assert lineage.validate_credential(record)


@pytest.mark.parametrize("key", ["token", "access-token", "refresh_token", "client_secret", "password", "api_key"])
def test_credential_metadata_rejects_secret_shaped_fields(key):
    with pytest.raises(ValueError, match="forbidden secret field"):
        lineage.credential_observation("cred-1", b"opaque", credential_type="opaque", observed_at=T0,
                                       metadata={"nested": {key: "must-not-be-retained"}})


def test_jwt_is_structural_only_and_rfc8693_actor_is_observable():
    raw = _jwt({"iss": "issuer", "sub": "agent", "aud": "api", "scope": "read write",
                "act": {"sub": "human", "client_id": "cli"}, "private": "not-normalized"})
    record = lineage.jwt_structure(raw, observed_at="2026-09-10T09:00:00-04:00", credential_id="cred-1")
    assert record["observed_at"] == T0
    assert record["claims"]["act"] == {"sub": "human", "client_id": "cli"}
    assert record["unmapped_claim_names"] == ["private"]
    assert all(value is False for value in record["verification"].values())
    assert record["raw_token_retained"] is False


def test_jwt_rejects_naive_time_and_non_base64url_alphabet():
    raw = _jwt({"sub": "agent"})
    with pytest.raises(ValueError, match="explicit UTC offset"):
        lineage.jwt_structure(raw, observed_at="2026-09-10T13:00:00")
    parts = raw.decode().split(".")
    malformed = f"{parts[0]}!.{parts[1]}.{parts[2]}".encode()
    with pytest.raises(ValueError, match="base64url"):
        lineage.jwt_structure(malformed, observed_at=T0)


def test_lineage_detects_scope_expansion_reuse_and_projects_only_explicit_delegation():
    credentials, principals, jwts, hops, presentations = _sample()
    report = lineage.build_lineage(lineage_id="case-1/lineage-1", credentials=credentials,
                                   principals=principals, hops=hops, presentations=presentations,
                                   jwt_structures=jwts)
    assert lineage.validate_lineage(report)
    assert report["diagnostics"]["scope_changes"][0]["scope_expansion_observed"] is True
    reuse = report["diagnostics"]["credential_fingerprint_reuse"]
    reused = [item for item in reuse if item["multiple_presenters"]]
    assert len(reused) == 1
    assert reused[0]["presenter_principal_ids"] == ["agent-1", "human-1"]

    bundle = lineage.to_aer(report, record_id="case-1/credential-lineage")
    assert lineage.validate_aer_binding(bundle, report=report)
    delegation_edges = [edge for edge in bundle["aer"]["edges"] if edge["relationship"] == "delegated_authority"]
    presentation_edges = [edge for edge in bundle["aer"]["edges"] if edge["edge_id"].startswith("edge:presentation:")]
    assert len(delegation_edges) == 2
    assert all(edge["relationship"] == "correlated_with" for edge in presentation_edges)
    assert bundle["claims"]["mere_presentation_treated_as_delegation"] is False


def test_principal_and_credential_ids_use_separate_aer_namespaces():
    raw = b"opaque-value"
    credentials = [lineage.credential_observation("same-id", raw, credential_type="opaque", observed_at=T0)]
    principals = [lineage.principal("same-id", kind="agent", observed_at=T0)]
    report = lineage.build_lineage(lineage_id="collision", credentials=credentials, principals=principals)
    bundle = lineage.to_aer(report, record_id="collision/aer")
    ids = {node["node_id"] for node in bundle["aer"]["nodes"]}
    assert "credential-lineage:identity:principal:same-id" in ids
    assert "credential-lineage:identity:credential:same-id" in ids


def test_missing_parents_become_unknown_evidence_nodes():
    credential = lineage.credential_observation("cred-out", b"opaque", credential_type="opaque", observed_at=T1)
    hop = lineage.delegation_hop(
        "hop-missing", mechanism="on-behalf-of", observed_at=T1,
        input_credential_id="cred-missing", output_credential_id="cred-out",
        source_principal_id="principal-missing", target_principal_id="agent-missing",
    )
    report = lineage.build_lineage(lineage_id="missing", credentials=[credential], principals=[], hops=[hop])
    assert report["diagnostics"]["missing_credential_ids"] == ["cred-missing"]
    assert report["diagnostics"]["missing_principal_ids"] == ["agent-missing", "principal-missing"]
    bundle = lineage.to_aer(report, record_id="missing/aer")
    unknown = [node for node in bundle["aer"]["nodes"] if node["kind"] == "unknown"]
    assert len(unknown) == 3


def test_cycle_duplicate_and_tamper_are_rejected():
    credentials, principals, jwts, hops, presentations = _sample()
    reverse = lineage.delegation_hop(
        "hop-2", mechanism="delegated-session", observed_at=T2,
        input_credential_id="cred-b", output_credential_id="cred-a",
        source_principal_id="agent-1", target_principal_id="human-1",
    )
    with pytest.raises(ValueError, match="cyclic credential delegation graph"):
        lineage.build_lineage(lineage_id="cycle", credentials=credentials, principals=principals,
                              hops=hops + [reverse], jwt_structures=jwts)
    with pytest.raises(ValueError, match="duplicate credential_id"):
        lineage.build_lineage(lineage_id="duplicate", credentials=credentials + [credentials[0]], principals=principals)

    forged = deepcopy(credentials[0])
    forged["byte_length"] += 1
    with pytest.raises(ValueError, match="record_sha256 mismatch"):
        lineage.validate_credential(forged)


def test_principal_records_are_revalidated_inside_lineage():
    credential = lineage.credential_observation("cred", b"opaque", credential_type="opaque", observed_at=T0)
    principal = lineage.principal("agent", kind="agent", observed_at=T0)
    forged = deepcopy(principal)
    forged["kind"] = "human"
    with pytest.raises(ValueError, match="record_sha256 mismatch"):
        lineage.build_lineage(lineage_id="forged-principal", credentials=[credential], principals=[forged])
