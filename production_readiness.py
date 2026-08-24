#!/usr/bin/env python3
"""Fail-closed production-readiness validator for AI-DFIR deployments."""
from __future__ import annotations
import argparse,json
from pathlib import Path
REQ={
 'database':{'allowed':['postgresql_ha','managed_postgresql_ha']},
 'identity':{'allowed':['oidc','saml_oidc_gateway']},
 'service_identity':{'allowed':['mtls','spiffe_mtls']},
 'key_management':{'allowed':['kms','hsm','kms_hsm']},
 'evidence_storage':{'allowed':['object_lock','worm','immutable_replica']},
 'tenant_isolation':{'allowed':['row_level_security','separate_databases','separate_clusters']},
 'backup_dr':{'allowed':['tested_cross_region','tested_offline_restore']},
 'analyst_audit':{'allowed':['signed_hash_chain','external_audit_sink']},
 'peer_review':{'allowed':['required_for_critical']},
 'secrets_redaction':{'allowed':['enabled']},
}
def assess(cfg):
    findings=[];checks=[]
    for k,v in REQ.items():
        actual=cfg.get(k);ok=actual in v['allowed'];checks.append({'control':k,'actual':actual,'allowed':v['allowed'],'pass':ok})
        if not ok:findings.append({'type':'production_control_missing_or_weak','severity':'critical','control':k,'actual':actual,'allowed':v['allowed']})
    if cfg.get('workbench_bind') not in ('127.0.0.1','localhost','behind_authenticated_gateway'):
        findings.append({'type':'workbench_network_exposure_without_approved_gateway','severity':'critical','actual':cfg.get('workbench_bind')})
    return {'schema':'ai-dfir/production-readiness/v1.4','production_ready':not findings,'checks':checks,'findings':findings,
            'rule':'The reference implementation cannot self-certify production readiness; deployment controls must be explicitly validated.'}
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--config',required=True);ap.add_argument('--out');a=ap.parse_args();o=assess(json.loads(Path(a.config).read_text()));s=json.dumps(o,indent=2,sort_keys=True);Path(a.out).write_text(s) if a.out else print(s);raise SystemExit(0 if o['production_ready'] else 2)
if __name__=='__main__':main()
