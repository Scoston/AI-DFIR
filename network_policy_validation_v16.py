#!/usr/bin/env python3
"""Static validation of AI-DFIR Kubernetes production security boundaries."""
from __future__ import annotations
import argparse,json,re
from pathlib import Path
REQUIRED=['kind: NetworkPolicy','policyTypes:','Ingress','Egress','runAsNonRoot: true','readOnlyRootFilesystem: true','allowPrivilegeEscalation: false','seccompProfile:','RuntimeDefault','kind: PodDisruptionBudget']
def analyze(paths):
    text='\n'.join(Path(p).read_text(encoding='utf-8',errors='replace') for p in paths);findings=[]
    for r in REQUIRED:
        if r not in text:findings.append({'type':'kubernetes_hardening_control_missing','severity':'critical','control':r})
    if re.search(r'image:\s*[^\s]+:(?:latest|main)\b',text,re.I):findings.append({'type':'mutable_container_tag','severity':'critical'})
    if '0.0.0.0/0' in text and 'except:' not in text:findings.append({'type':'unrestricted_network_cidr','severity':'high'})
    return {'schema':'ai-dfir/network-policy-validation/v1.6','valid':not any(x['severity']=='critical' for x in findings),'files':[str(x) for x in paths],'findings':findings}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('files',nargs='+');ap.add_argument('--out');a=ap.parse_args();o=analyze(a.files);s=json.dumps(o,indent=2,sort_keys=True);Path(a.out).write_text(s) if a.out else print(s);raise SystemExit(0 if o['valid'] else 2)
if __name__=='__main__':main()
