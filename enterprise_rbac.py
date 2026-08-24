#!/usr/bin/env python3
"""Enterprise RBAC policy for AI-DFIR v1.0."""
from __future__ import annotations
import argparse, json

ROLE_PERMISSIONS = {
    "viewer": {
        "case.read","evidence.metadata.read","report.read"
    },
    "analyst": {
        "case.read","case.create","case.update","evidence.metadata.read","evidence.read",
        "evidence.ingest","annotation.create","report.read","report.generate","search.execute"
    },
    "senior_analyst": {
        "case.read","case.create","case.update","case.transition","evidence.metadata.read",
        "evidence.read","evidence.ingest","annotation.create","report.read","report.generate",
        "search.execute","containment.plan","evidence.export"
    },
    "incident_commander": {
        "case.read","case.create","case.update","case.transition","case.assign",
        "evidence.metadata.read","evidence.read","evidence.ingest","annotation.create",
        "report.read","report.generate","search.execute","containment.plan",
        "containment.approve","recovery.approve","evidence.export","legal_hold.request"
    },
    "evidence_custodian": {
        "case.read","evidence.metadata.read","evidence.read","evidence.ingest",
        "evidence.export","evidence.verify","legal_hold.create","legal_hold.release",
        "retention.plan","repository.verify"
    },
    "auditor": {
        "case.read","evidence.metadata.read","audit.read","report.read",
        "repository.verify","legal_hold.read"
    },
    "admin": {"*"},
}

CLASSIFICATION_LEVEL = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "restricted": 3,
    "secret": 4,
}
ROLE_CLEARANCE = {
    "viewer": 1,
    "analyst": 2,
    "senior_analyst": 3,
    "incident_commander": 4,
    "evidence_custodian": 4,
    "auditor": 3,
    "admin": 4,
}

def authorize(role: str, permission: str):
    perms=ROLE_PERMISSIONS.get(role,set())
    return "*" in perms or permission in perms

def can_read_classification(role: str, classification: str):
    return ROLE_CLEARANCE.get(role,-1) >= CLASSIFICATION_LEVEL.get(classification,999)

def require(role: str, permission: str):
    if not authorize(role,permission):
        raise PermissionError(f"role={role} lacks permission={permission}")

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--role",required=True)
    ap.add_argument("--permission",required=True)
    ap.add_argument("--classification")
    a=ap.parse_args()
    result={"authorized":authorize(a.role,a.permission)}
    if a.classification:
        result["classification_authorized"]=can_read_classification(a.role,a.classification)
    print(json.dumps(result,indent=2,sort_keys=True))
    if not result["authorized"]:
        raise SystemExit(2)

if __name__=="__main__":main()
