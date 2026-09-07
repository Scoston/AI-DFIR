"""One-way CASE/UCO 1.5.0 inventory view of a verified immutable case ZIP.

The optional view is unsigned. Comparing it requires the original signed case
and an independently selected export verification key. It is not an importer,
an RDF reasoner, or evidence of custody, source truth, or recorded execution.
"""
from __future__ import annotations

import io
import os
import stat
import uuid
import zipfile
from pathlib import Path

from case_export_v17 import verify_case
from v17_integrity import canonical_json_bytes, sha256_bytes, sha256_object
from v17_log_analytics import _document
from v17_provenance import PROVENANCE_PATH, ProvenanceError
from v17_reconstruction import strict_json

PROFILE = "ai-dfir/case-uco-exchange/v1.7"
ONTOLOGY_VERSION = "1.5.0"
MAX_ARCHIVE_BYTES = 64 * 1024**2
MAX_TOTAL_UNCOMPRESSED = 128 * 1024**2
MAX_MEMBER_BYTES = 16 * 1024**2
MAX_MEMBERS = 4096
MAX_OUTPUT_BYTES = 16 * 1024**2
MAX_GRAPH_NODES = 32000
CONTEXT = {
    "adfir": "https://github.com/Scoston/AI-DFIR/ns/case-exchange/1.7/",
    "case-investigation": "https://ontology.caseontology.org/case/investigation/",
    "uco-core": "https://ontology.unifiedcyberontology.org/uco/core/",
    "uco-observable": "https://ontology.unifiedcyberontology.org/uco/observable/",
    "uco-types": "https://ontology.unifiedcyberontology.org/uco/types/",
    "xsd": "http://www.w3.org/2001/XMLSchema#",
}
# A profile-controlled vocabulary, never selected by archive content. Every
# property with input-derived text is a literal; none is coerced to an IRI.
VERIFICATION_OPTIONS = frozenset({
    "checkpoint_key_policy", "require_checkpoint_key_policy", "key_policy_evaluated_at",
    "expected_key_policy_sha256", "checkpoint_policy_store", "policy_issuer_trust",
    "require_authenticated_key_policy", "minimum_policy_revision", "policy_root_anchor",
    "minimum_root_version", "key_trust_history", "require_key_trust_history",
    "timestamp_request", "timestamp_response", "tsa_ca_pem", "expected_tsa_certificate_sha256",
    "expected_timestamp_request_sha256", "require_checkpoint_timestamp",
})


def read_archive(path):
    """Read a bounded regular file once; symlinks may name regular inputs."""
    fd = os.open(Path(path), os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_ARCHIVE_BYTES:
            raise ProvenanceError("case exchange requires a bounded regular archive")
        raw = stream.read(MAX_ARCHIVE_BYTES + 1)
    if not 0 < len(raw) <= MAX_ARCHIVE_BYTES:
        raise ProvenanceError("case exchange archive exceeds byte limits")
    return raw


def _identity(value):
    return (isinstance(value, str) and bool(value.strip()) and len(value) <= 4096
            and not any(ord(c) < 32 or ord(c) == 127 for c in value))


def _ref(ident):
    return {"@id": ident}


def _node_id(zip_digest, kind, identity):
    # Structured canonical input prevents delimiter/namespace aliasing. ZIP
    # bytes deliberately scope instances: different exports do not collapse.
    name = canonical_json_bytes([PROFILE, zip_digest, kind, identity]).decode("utf-8")
    return "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, name))


def export_exchange(raw, export_public_key, *, expected_tenant, expected_case, **verification_options):
    """Verify a byte snapshot before emitting a selected CASE/UCO graph.

    All optional verifier policy/timestamp/history controls are retained. No
    caller can disable provenance, identity checks, or archive safety limits.
    Only the exact verified byte snapshot is reopened for retained metadata.
    """
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_ARCHIVE_BYTES:
        raise ProvenanceError("case exchange requires bounded immutable archive bytes")
    if not _identity(expected_tenant) or not _identity(expected_case):
        raise ProvenanceError("case exchange requires explicit tenant and case identity")
    if set(verification_options) - VERIFICATION_OPTIONS:
        raise ProvenanceError("unsupported case exchange verification option")
    report = verify_case(
        raw, export_public_key, expected_tenant=expected_tenant, expected_case=expected_case,
        require_provenance=True, include_reconstruction=True, replay_transforms=False,
        max_members=MAX_MEMBERS, max_total_uncompressed=MAX_TOTAL_UNCOMPRESSED,
        max_member_uncompressed=MAX_MEMBER_BYTES, max_compression_ratio=1000.0,
        **verification_options,
    )
    if report.get("valid") is not True or report.get("provenance_integrity") != "PASS":
        raise ProvenanceError("signed case verification failed")
    digest = sha256_bytes(raw)
    if report["zip_sha256"] != digest:
        raise ProvenanceError("case verification snapshot mismatch")
    reconstruction = report["reconstruction"]
    # verify_case consumed this same immutable byte value, including provenance
    # validation and all artifact digests. No filesystem members are extracted.
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        bundle = strict_json(archive.read(PROVENANCE_PATH))
        sizes = {row["path"]: archive.getinfo(row["path"]).file_size for row in bundle["artifacts"]}
    bound = {row["record_hash"]: row for row in reconstruction["timeline"] if row["record_id"] is not None}
    node_id = lambda kind, ident: _node_id(digest, kind, ident)
    artifact_ids = {row["record"]["artifact_id"]: node_id("artifact", row["record"]["artifact_id"])
                    for row in bundle["artifacts"]}
    nodes = []

    def content(ident, byte_digest, size, **properties):
        facet_id, hash_id = node_id("content-facet", ident), node_id("sha256", ident)
        nodes.extend([
            {"@id": facet_id, "@type": "uco-observable:ContentDataFacet",
             "uco-observable:sizeInBytes": size, "uco-observable:hash": [_ref(hash_id)]},
            {"@id": hash_id, "@type": "uco-types:Hash", "uco-types:hashMethod": "SHA256",
             "uco-types:hashValue": {"@type": "xsd:hexBinary", "@value": byte_digest}},
        ])
        obj = {"@id": ident, "@type": "uco-observable:ObservableObject",
               "uco-core:hasFacet": [_ref(facet_id)], **properties}
        nodes.append(obj)
        return obj

    archive_id = node_id("archive", "source")
    content(archive_id, digest, len(raw), **{"uco-core:name": "Verified source case ZIP",
        "adfir:role": "signed-source-archive"})
    members = [_ref(archive_id)]
    for row in bundle["artifacts"]:
        record, event = row["record"], bound[row["record_hash"]]
        ident = artifact_ids[record["artifact_id"]]
        obj = content(ident, record["sha256"], sizes[row["path"]], **{
            "uco-core:name": record["artifact_id"], "adfir:artifactID": record["artifact_id"],
            "adfir:packagePath": row["path"], "adfir:recordHash": row["record_hash"],
            "adfir:ledgerSequence": event["sequence"], "adfir:ledgerEntryHash": event["entry_hash"],
        })
        # Classification and media labels remain recorded assertions. No file
        # extension, filesystem location, acquisition time, or actor is inferred.
        if record["classification"] is not None:
            obj["adfir:recordedClassification"] = record["classification"]
        if record["media_type"] is not None:
            obj["adfir:recordedMediaType"] = record["media_type"]
        members.append(_ref(ident))
    for row in bundle["relationships"]:
        record, event = row["record"], bound[row["record_hash"]]
        ident = node_id("relationship", row["record_hash"])
        relation = {
            "@id": ident, "@type": "uco-core:Relationship",
            "uco-core:source": [_ref(artifact_ids[record["child_artifact_id"]])],
            "uco-core:target": _ref(artifact_ids[record["parent_artifact_id"]]),
            "uco-core:isDirectional": True,
            "uco-core:kindOfRelationship": "AI-DFIR recorded lineage",
            "adfir:recordedRelationshipType": record["relationship_type"],
            "adfir:recordHash": row["record_hash"], "adfir:ledgerSequence": event["sequence"],
            "adfir:ledgerEntryHash": event["entry_hash"], "adfir:executionVerified": False,
            "adfir:recordedMetadataHash": sha256_object(record["metadata"]),
        }
        for field, predicate in (("transformation", "adfir:recordedTransformation"),
                                 ("transformation_version", "adfir:recordedTransformationVersion")):
            if record[field] is not None:
                relation[predicate] = record[field]
        secondary_inputs = {
            "v17_log_analytics_context.normalize": ("context_artifact_id", "adfir:contextArtifact"),
            "v17_gcp_logging_context.normalize": ("context_artifact_id", "adfir:contextArtifact"),
            "v17_evidence_validation.assess": ("rules_artifact_id", "adfir:rulesArtifact"),
            "v17_schema_drift.compare": ("baseline_artifact_id", "adfir:baselineArtifact"),
        }
        if record["transformation_version"] == "1.7" and record["transformation"] in secondary_inputs:
            field, predicate = secondary_inputs[record["transformation"]]
            relation[predicate] = _ref(artifact_ids[record["metadata"][field]])
        nodes.append(relation)
        members.append(_ref(ident))
    investigation = {
        "@id": node_id("investigation", expected_case), "@type": "case-investigation:Investigation",
        "uco-core:name": expected_case, "uco-core:object": sorted(members, key=lambda x: x["@id"]),
        "uco-core:description": "Selected verified inventory and recorded lineage. The graph is unsigned; verify the original signed case. No source truth, custody, execution, authority, completeness, or closure is established.",
        "adfir:profile": PROFILE, "adfir:caseOntologyVersion": ONTOLOGY_VERSION,
        "adfir:ucoOntologyVersion": ONTOLOGY_VERSION, "adfir:tenantID": expected_tenant,
        "adfir:caseID": expected_case, "adfir:sourceArchive": _ref(archive_id),
        "adfir:checkpointHash": report["checkpoint_hash"], "adfir:verificationReportHash": sha256_object(report),
        "adfir:checkpointTrustSource": report["signer_trust_source"],
        "adfir:checkpointKeyPolicyStatus": report["checkpoint_key_policy"]["status"],
        "adfir:checkpointTimestampStatus": report["checkpoint_timestamp"]["status"],
        "adfir:keyTrustHistoryStatus": report["checkpoint_key_trust_history"]["status"],
        "adfir:artifactCount": len(bundle["artifacts"]), "adfir:relationshipCount": len(bundle["relationships"]),
        "adfir:verifiedPackageFileCount": report["file_count"],
        "adfir:unmappedPackageFileCount": report["file_count"] - len(bundle["artifacts"]),
        "adfir:recordCount": reconstruction["record_count"],
        "adfir:omittedRecordCount": reconstruction["record_count"] - len(bundle["artifacts"]) - len(bundle["relationships"]),
        "adfir:unboundEventCount": reconstruction["unbound_event_count"],
        "adfir:sourceCaseIntegrityVerified": True, "adfir:sourceAuthenticityVerified": False,
        "adfir:executionVerified": False, "adfir:completeInvestigationExport": False,
        "adfir:collectionCompleteness": "unknown", "adfir:qualityRatingChanged": False,
        "adfir:closureAuthorized": False, "adfir:networkRequired": False,
        "adfir:graphSignaturePresent": False, "adfir:runtimeSHACLValidationPerformed": False,
    }
    nodes.append(investigation)
    if len(nodes) > MAX_GRAPH_NODES:
        raise ProvenanceError("case exchange graph exceeds node limit")
    if len({node["@id"] for node in nodes}) != len(nodes):
        raise ProvenanceError("case exchange instance identifier collision")
    graph = {"@context": dict(CONTEXT), "@graph": sorted(nodes, key=lambda x: x["@id"])}
    encoded = canonical_json_bytes(graph)
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise ProvenanceError("case exchange graph exceeds byte limit")
    _document(encoded, MAX_OUTPUT_BYTES)  # Enforce the comparison reader's global tree budget too.
    return graph


def compare_exchange(raw, recorded_raw, export_public_key, **options):
    """Compare the complete pinned-profile JSON graph; never resolve JSON-LD.

    JSON object key order and whitespace may vary. RDF-equivalent rewrites,
    floating-point substitutions for integers, array reordering, changed
    literals, contexts, or identifiers do not pass.
    """
    recorded = _document(recorded_raw, MAX_OUTPUT_BYTES)
    expected = export_exchange(raw, export_public_key, **options)
    # JCS alone equates 1.0 and 1; RDF consumers can assign distinct literal
    # datatypes. This fixed profile emits only native integer numeric values.
    pending, integer_types = [recorded], True
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, float):
            integer_types = False
    matched = integer_types and canonical_json_bytes(recorded) == canonical_json_bytes(expected)
    return {"schema": PROFILE, "status": "PASS" if matched else "FAIL",
            "comparison_basis": "RFC8785-JSON-with-integer-types", "source_sha256": sha256_bytes(raw),
            "expected_graph_sha256": sha256_object(expected), "network_required": False,
            "source_authenticity_verified": False, "closure_authorized": False}
