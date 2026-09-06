"""Reconstruct verified records and replay an explicit set of pure transforms."""
from __future__ import annotations

import json
from typing import Any, Callable

from v17_integrity import InvestigationLedger, canonical_json_bytes, sha256_object
from v17_provenance import ProvenanceError


def strict_json(raw: bytes) -> Any:
    """Reject duplicate keys and non-JSON numbers instead of choosing a meaning."""
    def pairs(items):
        obj = {}
        for key, value in items:
            if key in obj:
                raise ProvenanceError("duplicate JSON key")
            obj[key] = value
        return obj

    def constant(_):
        raise ProvenanceError("non-finite JSON number")

    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)


def reconstruct(
    bundle: dict[str, Any], index: dict[str, dict[str, Any]], ledger: InvestigationLedger,
    *, read_artifact: Callable[[str], bytes], replay_transforms: bool = False,
) -> dict[str, Any]:
    """Consume records validated within the same open, verified archive handle.

    Ordering is ledger sequence, not a guessed causal order from timestamps.
    Unsupported transformations are reported without loading or executing code.
    """
    timeline = []
    sequence_index = {row["ledger_sequence"]: (ident, row) for ident, row in index.items()}
    for event in ledger.events:
        entry = {
            "sequence": event.sequence, "timestamp": event.timestamp,
            "event_type": event.event_type, "actor": event.actor,
            "entry_hash": event.entry_hash, "record_id": None,
        }
        if event.sequence in sequence_index:
            ident, row = sequence_index[event.sequence]
            entry.update(record_id=ident, record_type=row["kind"], record_hash=row["record_hash"], record=row["record"])
            if row["kind"] == "ai_records":
                entry["output_sha256"] = row["output_sha256"]
        timeline.append(entry)

    comparisons = []
    for pair in bundle["comparisons"]:
        first, second = index[pair["original"]], index[pair["comparison"]]
        a, b = first["record"], second["record"]
        # Compare content digests: independently acquired artifacts may have
        # different record IDs while preserving the same observed bytes.
        def inputs(rec):
            return {kind: [index[ref]["record"]["sha256"] for ref in rec[kind]]
                    for kind in ("evidence_refs", "retrieval_refs")}
        comparisons.append({
            **pair, "mode": "recorded-comparison",
            "same_model_configuration": all(a[k] == b[k] for k in ("provider", "model", "model_version", "policy_config_id")),
            "same_referenced_inputs": inputs(a) == inputs(b),
            "same_recorded_output": first["output_sha256"] == second["output_sha256"] if first["output_sha256"] is not None and second["output_sha256"] is not None else None,
            "deterministic_reproduction_proven": False,
        })

    transforms = []
    if replay_transforms:
        for row in index.values():
            if row["kind"] != "relationships":
                continue
            rec = row["record"]
            result = {"relationship_hash": row["record_hash"], "transformation": rec["transformation"], "status": "UNSUPPORTED"}
            supported = (rec["transformation"], rec["transformation_version"]) in {
                ("RFC8785", "1"), ("provider_normalizer.normalize", "1.4"),
                ("evidence_quality.evaluate_gates", "1.7"),
            }
            if supported:
                try:
                    original_raw = read_artifact(index[rec["parent_artifact_id"]]["path"])
                    if rec["transformation"] == "evidence_quality.evaluate_gates":
                        from v17_pack_replay import MAX_INPUT_BYTES
                        if len(original_raw) > MAX_INPUT_BYTES:
                            raise ProvenanceError("Evidence Pack replay snapshot exceeds byte limit")
                    original = strict_json(original_raw)
                    preserved = read_artifact(index[rec["child_artifact_id"]]["path"])
                    if rec["transformation"] == "RFC8785":
                        matched = canonical_json_bytes(original) == preserved
                        result["comparison_basis"] = "exact-bytes"
                    elif rec["transformation"] == "provider_normalizer.normalize":
                        from provider_normalizer import PROVIDERS, normalize
                        meta = rec["metadata"]
                        if set(meta) != {"provider"} or meta["provider"] not in PROVIDERS:
                            raise ProvenanceError("unsupported normalization configuration")
                        if not isinstance(original, list) or not all(isinstance(x, dict) for x in original):
                            raise ProvenanceError("normalizer input must be an array of objects")
                        # Content inclusion is deliberately disabled. This is a
                        # fixed local adapter, not an evidence-selected import.
                        replayed = normalize(meta["provider"], original, include_content=False)
                        matched = sha256_object(replayed) == sha256_object(strict_json(preserved))
                        result["comparison_basis"] = "RFC8785-JSON"
                    else:
                        from v17_pack_replay import compare_pack_replay
                        meta = rec["metadata"]
                        if set(meta) != {"pack_sha256"}:
                            raise ProvenanceError("unsupported Evidence Pack replay configuration")
                        compared = compare_pack_replay(original, strict_json(preserved), case_id=ledger.case_id,
                                                       expected_pack_sha256=meta["pack_sha256"])
                        result.update(compared)
                        matched = compared["status"] == "PASS"
                    result["status"] = "PASS" if matched else "FAIL"
                except (ValueError, TypeError, KeyError, OSError, RecursionError):
                    result.update(status="FAIL", error="preserved transformation input/output is invalid or exceeds replay limits")
            transforms.append(result)

    statuses = {row["status"] for row in transforms}
    replay_status = "NOT_REQUESTED"
    if replay_transforms:
        replay_status = "FAIL" if "FAIL" in statuses else "INCOMPLETE" if "UNSUPPORTED" in statuses else "PASS" if transforms else "NOT_APPLICABLE"
    return {
        "schema": "ai-dfir/investigation-reconstruction/v1.7",
        "case_id": ledger.case_id, "mode": "recorded", "network_required": False,
        "model_invoked": False, "tools_executed": False,
        "content_policy": bundle["content_policy"], "timeline": timeline,
        "record_count": len(index), "comparisons": comparisons,
        "unbound_event_count": len(ledger.events) - len(index),
        "deterministic_replay": {"status": replay_status, "transforms": transforms},
        "interpretation": "Recorded activity and explicit lineage; neither source truth nor unrecorded causality is established.",
    }
