#!/usr/bin/env python3
"""Deterministic investigator report generator for AI-DFIR v0.8."""
from __future__ import annotations
import argparse, hashlib, html, json
from datetime import datetime, timezone
from pathlib import Path
from case_model import full_case


def fmt(v, digits=4):
    if v is None:return 'Not available'
    if isinstance(v,float):return f'{v:.{digits}f}'
    return str(v)


def esc(s):return html.escape(str(s or ''))


def markdown(case):
    s=case['summary'];cov=case['coverage'];lines=[]
    lines += [f"# AI-DFIR Investigator Report — {s['case_id']}", '',
              f"Generated: {datetime.now(timezone.utc).isoformat().replace('+00:00','Z')}", '',
              '## Executive Summary','']
    finding=s.get('finding') or 'No correlated finding is available from the supplied evidence.'
    lines.append(f"**Finding:** {finding}")
    lines.append(f"**Confidence level:** {fmt(s.get('confidence_level'))}")
    lines.append(f"**Case severity:** {fmt(s.get('severity'))}")
    lines.append(f"**Containment:** {fmt(s.get('containment_status'))}")
    lines.append(f"**Evidence coverage:** {cov['present']}/{cov['total']} categories ({cov['percent']}%)")
    lines += ['', 'The report distinguishes missing evidence from clean evidence. A missing artifact is treated as unknown and is not interpreted as proof that a condition did not occur.', '']

    lines += ['## Key Findings','']
    lines.append(f"- First material activation divergence depth: **{fmt(s.get('first_divergence_depth'))}**")
    lines.append(f"- Highest anomaly depth: **{fmt(s.get('highest_anomaly_depth'))}**")
    lines.append(f"- Highest absolute robust-z: **{fmt(s.get('highest_abs_robust_z'))}**")
    lines.append(f"- Runtime findings: **{fmt(s.get('runtime_findings_count'))}**")
    lines.append(f"- Open downstream consequences: **{fmt(s.get('open_consequences'))}**")
    if cov['missing']:
        lines.append(f"- Missing evidence categories: **{', '.join(cov['missing'])}**")

    lines += ['', '## Activation / Behavioral Divergence','']
    if case['layers']:
        lines += ['| Depth | Max |z| | Anomalous | Mean cosine | Mean relative L2 |',
                  '|---:|---:|---|---:|---:|']
        for r in case['layers']:
            lines.append(f"| {r['depth']} | {fmt(r.get('max_abs_robust_z'))} | {'Yes' if r.get('anomalous') else 'No'} | {fmt(r.get('mean_prompt_cosine_similarity'))} | {fmt(r.get('mean_relative_l2_delta'))} |")
    else:
        lines.append('No activation-layer comparison evidence was found.')

    lines += ['', '## Static Model / Tensor Findings','']
    if case['tensors']:
        lines += ['| Tensor | Layer | Component | Relative Δ | Top-1 SVD energy | Effective rank |',
                  '|---|---:|---|---:|---:|---:|']
        for r in case['tensors'][:30]:
            lines.append(f"| `{r['tensor']}` | {fmt(r.get('layer'))} | {fmt(r.get('component'))} | {fmt(r.get('relative_fro_delta'),6)} | {fmt(r.get('top1_energy_ratio'))} | {fmt(r.get('effective_rank'))} |")
    else:
        lines.append('No changed-tensor evidence was found or supplied.')

    lines += ['', '## Runtime Findings','']
    rf=case['runtime']['findings']
    if rf:
        for x in rf[:50]:
            lines.append(f"- **{x.get('type','finding')}** — {json.dumps(x, sort_keys=True, default=str)}")
    else:
        lines.append('No runtime-finding artifact was found.')

    lines += ['', '## Distributed Enterprise Trust & Provider Collection','']
    en=case.get('enterprise_v15') or {}
    pr=en.get('production_readiness') or {}
    if pr: lines.append(f"- Deployment production-ready: **{pr.get('production_ready')}**")
    gaps=en.get('provider_gaps') or []
    if gaps:
        lines.append(f"- Provider evidence-gap assessments: **{len(gaps)}**")
        for g in gaps:
            lines.append(f"  - `{g.get('provider')}` mandatory collection complete: **{g.get('complete_mandatory')}**")
    lines.append(f"- Provider collection receipts: **{len(en.get('provider_receipts') or [])}**")
    oidc=en.get('oidc_identity') or {}; sp=en.get('spiffe_identity') or {}
    if oidc: lines.append(f"- OIDC principal trusted at evaluation time: **{oidc.get('trusted')}**")
    if sp: lines.append(f"- SPIFFE/mTLS identity trusted at evaluation time: **{sp.get('trusted')}**")
    dr=en.get('dr_restore') or {}; slo=en.get('service_slo') or {}
    if dr: lines.append(f"- Disaster-recovery restore validation: **{dr.get('valid')}**")
    if slo: lines.append(f"- Service/collector SLO probe: **{slo.get('pass')}**")
    for x in (en.get('findings') or [])[:150]:
        lines.append(f"- **{x.get('severity','')} — {x.get('type','finding')}** — domain `{x.get('domain','')}`")
    lines.append('- Enterprise readiness and provider completeness are evidence-backed states. A declared control, inaccessible API, or retention gap is not treated as verified evidence.')

    lines += ['', '## Production Platform Assurance','']
    ev16=case.get('enterprise_v16') or {}
    pa=ev16.get('platform_assurance') or {}
    if pa:
        lines.append(f"- Platform assurance status: **{pa.get('status','UNKNOWN')}**")
        lines.append(f"- Healthy controls: **{pa.get('healthy_controls')}/{pa.get('control_count')}**")
    certs=ev16.get('provider_certifications') or []
    if certs:
        lines.append(f"- Current provider certifications: **{sum(1 for x in certs if x.get('certified'))}/{len(certs)}**")
    for x in (ev16.get('findings') or [])[:100]:
        lines.append(f"- **{x.get('severity','')} — {x.get('type','finding')}** — domain `{x.get('domain','')}`")
    lines.append('- Platform-assurance findings describe the trustworthiness of the forensic platform and must not be misread as incident attribution.')

    lines += ['', '## Runtime Trust Fabric & Stateful Agent Forensics','']
    rt=case.get('runtime_trust') or {}
    ch=rt.get('collector_health') or {}
    if ch: lines.append(f"- Mandatory collection complete: **{ch.get('complete_mandatory')}**")
    ta=rt.get('temporal_authority') or {}
    if ta: lines.append(f"- Temporal-authority findings: **{len(ta.get('findings') or [])}**")
    mem=rt.get('memory_integrity') or {}
    if mem: lines.append(f"- Memory-integrity findings: **{len(mem.get('findings') or [])}**")
    cg=rt.get('causal_graph') or {}
    if cg: lines.append(f"- Typed causal edges: **{len(cg.get('edges') or [])}**")
    for x in (rt.get('findings') or [])[:150]:
        lines.append(f"- **{x.get('severity','')} — {x.get('type','finding')}** — domain `{x.get('domain','')}`")
    lines.append('- Runtime trust conclusions are evaluated at incident time; current credentials, keys, memory and policy state are not substituted for historical state.')

    lines += ['', '## A2A Identity, Signed Agent Cards & Delegation Trust','']
    at=case.get('a2a_trust') or {}
    ver=at.get('verification') or {}
    if ver:
        lines.append(f"- Agent Card policy satisfied: **{ver.get('policy_satisfied')}**")
        lines.append(f"- Cryptographically valid signatures: **{ver.get('valid_signature_count')}**")
        lines.append(f"- Trusted signatures: **{ver.get('trusted_signature_count')}**")
        lines.append(f"- Canonical Agent Card payload SHA-256: `{ver.get('canonical_payload_sha256')}`")
    bind=at.get('execution_binding') or {}
    if bind:
        lines.append(f"- Execution bound to trusted Agent Card: **{bind.get('trusted_agent_card')}**")
    for x in (at.get('findings') or [])[:100]:
        lines.append(f"- **{x.get('severity','')} — {x.get('type','finding')}** — domain `{x.get('domain','')}`")
    lines.append('- A valid Agent Card JWS establishes card integrity under a key; transport/session identity and delegated authority remain separate forensic propositions.')

    lines += ['', '## Representation Integrity & Adversarial Content','']
    ri=case.get('representation_integrity') or {}
    intake=ri.get('intake') or {}
    if intake:
        lines.append(f"- Content intake verdict: **{intake.get('verdict','UNKNOWN')}**")
    trust=ri.get('acquisition_trust') or {}
    if trust:
        lines.append(f"- Signed acquisition trust: **{'VERIFIED' if trust.get('manifest_signature_verified') and trust.get('valid') else 'UNVERIFIED'}**")
    d=ri.get('differential') or {}
    if d:
        lines.append(f"- Human/machine token similarity: **{d.get('token_similarity')}**")
        lines.append(f"- Human/machine character similarity: **{d.get('character_similarity')}**")
    for x in (ri.get('findings') or [])[:100]:
        lines.append(f"- **{x.get('severity','')} — {x.get('type','finding')}** — domain `{x.get('domain','')}`")
    lines.append('- Representation findings establish hiding/deception mechanics; downstream intent and impact still require separate causal evidence.')

    lines += ['', '## Execution Integrity & Advanced Attack Surfaces','']
    ex=case.get('execution_integrity') or {}
    presence=ex.get('presence') or {}
    if presence:
        lines.append('Execution-integrity analysis artifacts: ' + ', '.join(
            f"{k}={'present' if v else 'missing'}" for k,v in sorted(presence.items())))
    for x in (ex.get('findings') or [])[:100]:
        lines.append(f"- **{x.get('severity','')} — {x.get('type',x.get('code','finding'))}**"
                     f" — domain `{x.get('domain','')}` — {json.dumps(x,sort_keys=True,default=str)}")
    taint=ex.get('taint') or {}
    if taint:
        lines.append(f"- Taint seeds: **{len(taint.get('seed_event_ids') or [])}**")
        lines.append(f"- Tainted sinks: **{len(taint.get('sinks') or [])}**")
        lines.append(f"- Cross-session taint propagation records: **{len(taint.get('cross_session_spread') or [])}**")
    outstanding=(ex.get('session_task') or {}).get('outstanding_count')
    if outstanding is not None:
        lines.append(f"- Outstanding delegated work: **{outstanding}**")
    replication=ex.get('replication') or {}
    if replication:
        lines.append(f"- Prompt/self-replication candidate edges: **{len(replication.get('edges') or [])}**")
    lines.append('- v1.1 preserves the distinction between correlation, taint propagation, and causal proof.')

    lines += ['', '## Agentic Incident Reconstruction','']
    ag=case.get('agentic') or {}
    presence=ag.get('presence') or {}
    lines.append('Agentic analysis artifacts: ' + ', '.join(f"{k}={'present' if v else 'missing'}" for k,v in sorted(presence.items())))
    for x in ((ag.get('rules') or {}).get('findings') or []):
        lines.append(f"- **{x.get('severity','')} — {x.get('title',x.get('rule_id'))}** — {x.get('owasp_agentic','')} — {', '.join(x.get('mitre_atlas') or [])}")
    for x in ((ag.get('authority') or {}).get('findings') or []):
        lines.append(f"- Authority: **{x.get('type')}** — {json.dumps(x,sort_keys=True,default=str)}")
    for x in ((ag.get('memory') or {}).get('findings') or []):
        lines.append(f"- Memory: **{x.get('type')}** — {json.dumps(x,sort_keys=True,default=str)}")
    affected=(ag.get('rag') or {}).get('affected_sessions') or []
    if affected:
        lines.append(f"- RAG affected sessions: **{len(affected)}**")
    paths=(ag.get('causal') or {}).get('causal_paths') or []
    if paths:
        lines.append(f"- Explicit causal paths to consequences: **{len(paths)}**")
    lines.append('- Timestamp proximity and correlation-only links are not treated as causal proof.')

    lines += ['', '## Delegated Authority & Consequences','']
    cg=case['consequences']
    lines.append(f"Total consequences recorded: **{fmt(cg.get('total_consequences'))}**")
    lines.append(f"Open consequences: **{fmt(cg.get('open_count'))}**")
    for x in (cg.get('open_consequences') or [])[:50]:
        lines.append(f"- {x.get('name') or x.get('event_id')} — event `{x.get('event_id')}`")

    lines += ['', '## Containment & Recovery','']
    c=case['containment']
    ctrl=c.get('control') or {};res=c.get('result') or {}
    lines.append(f"Containment mode: **{fmt(ctrl.get('mode'))}**")
    lines.append(f"Execution result: **{fmt(res.get('status'))}**")
    if c.get('audit'):
        lines.append(f"Containment audit events: **{len(c['audit'])}**")
        for e in c['audit'][:30]:
            lines.append(f"- {e.get('timestamp_utc','')} — {e.get('event_type','')} — `{e.get('event_hash','')[:16]}`")

    ep=case.get('evidence_pack') or {}
    ea=ep.get('assessment') if ep.get('selected') else None
    lines += ['', '## Incident Evidence Pack & Sufficiency','']
    if ea:
        lines.append(f"Evidence pack: **{ea.get('pack_title')}** (`{ea.get('pack_id')}`)")
        lines.append(f"Mandatory evidence meeting forensic quality threshold: **{ea.get('mandatory_present')}/{ea.get('mandatory_total')} ({ea.get('mandatory_percent')}%)**")
        lines.append(f"Forensic modes: **{', '.join(ea.get('forensic_modes') or [])}**")
        lines += ['', '### Conclusion gates','']
        for g in ea.get('conclusion_gates',[]):
            extra=[]
            if g.get('missing'): extra.append("missing: "+', '.join(g.get('missing') or []))
            if g.get('insufficient_quality'):
                extra.append("insufficient quality: "+'; '.join(
                    f"{x.get('artifact')} needs {x.get('required_quality')}" for x in g.get('insufficient_quality') or []))
            lines.append(f"- **{g.get('title')}** — `{g.get('status')}`"+(f" — {'; '.join(extra)}" if extra else ''))
        missing=[x for x in ea.get('artifacts',[]) if x.get('status')!='present']
        low_quality=[x for x in ea.get('artifacts',[]) if x.get('status')=='present' and x.get('quality') not in ('VALIDATED','CORRELATED','AUTHORITATIVE')]
        if missing:
            lines += ['', '### Missing evidence requirements','']
            for x in missing:
                loc=', '.join(x.get('locations') or [])
                lines.append(f"- **{x.get('priority')} — {x.get('title')}**: {x.get('rationale')}"+(f" Likely location(s): `{loc}`" if loc else ''))
        if low_quality:
            lines += ['', '### Present but insufficient-quality evidence','']
            for x in low_quality:
                lines.append(f"- **{x.get('priority')} — {x.get('title')}**: quality `{x.get('quality')}`; presence alone does not satisfy the conclusion gate.")
    else:
        lines.append('No v0.8 incident evidence pack was selected for this case. Evidence sufficiency has not been evaluated against an incident-specific artifact requirement set.')

    lines += ['', '## Evidence Integrity','']
    if case['integrity']:
        for i in case['integrity']:
            lines.append(f"- **{i.get('status')}** — {i.get('type')} — {i.get('path')}" + (f" — {i.get('error')}" if i.get('error') else ''))
    else:
        lines.append('No package-manifest or containment-audit integrity evidence was found.')

    lines += ['', '## Timeline','']
    if case['timeline']:
        lines += ['| UTC | Source | Event | Summary |','|---|---|---|---|']
        for e in case['timeline'][:100]:
            summary=str(e.get('summary','')).replace('|','\\|')[:180]
            lines.append(f"| {e.get('timestamp_utc','')} | {e.get('source','')} | {e.get('event_type','')} | {summary} |")
    else:
        lines.append('No normalized timeline evidence was found.')

    lines += ['', '## Evidentiary Interpretation','']
    level=s.get('confidence_level')
    if level==4:
        lines.append('The supplied case data reaches the framework’s Level 4 correlation category: provenance/timeline evidence is correlated with mechanistic and artifact/runtime evidence. This remains an investigative conclusion, not a mathematical proof of one specific modification technique.')
    elif level==3:
        lines.append('The supplied case data reaches Level 3: a mechanistic anomaly correlates with artifact or runtime integrity evidence. Additional provenance/timeline evidence would strengthen attribution.')
    elif level==2:
        lines.append('The supplied case data reaches Level 2: an artifact or runtime integrity anomaly is present. Mechanistic and timeline correlation should be developed before attributing a specific technique.')
    elif level==1:
        lines.append('The supplied case data reaches Level 1: behavioral or mechanistic anomaly evidence is present. This alone is insufficient to attribute model tampering.')
    else:
        lines.append('The supplied evidence does not include a completed AI-DFIR correlation result. Attribution should remain open.')

    lines += ['', '## Limitations','']
    lines.append('- Missing evidence remains unknown, not clean.')
    lines.append('- Quantization, framework, template, tokenizer, and configuration differences can alter tensors or activations and must be controlled before attribution.')
    lines.append('- A clean checkpoint loaded in a clean laboratory does not reproduce a production-only runtime intervention unless that execution state is preserved or reconstructed.')
    lines.append('- Automated confidence categories support investigation; they do not replace examiner judgment or environment-specific validation.')
    lines += ['', '## Evidence Coverage','']
    for k,v in sorted(s['evidence'].items()):
        lines.append(f"- {'PRESENT' if v else 'MISSING'} — {k}")
    return '\n'.join(lines)+'\n'


def html_report(case, md):
    # Use escaped Markdown inside <pre> for zero-dependency fidelity.
    s=case['summary']
    return f'''<!doctype html><html><head><meta charset="utf-8"><title>AI-DFIR Report — {esc(s['case_id'])}</title>
<style>body{{font-family:system-ui,-apple-system,sans-serif;max-width:1100px;margin:40px auto;padding:0 24px;background:#0b1020;color:#e8eefc}}pre{{white-space:pre-wrap;background:#111a30;padding:28px;border-radius:16px;line-height:1.5;border:1px solid #263453}}a{{color:#8bb7ff}}</style></head><body><pre>{esc(md)}</pre></body></html>'''


def generate(case_dir: Path, out_dir: Path):
    case=full_case(case_dir);out_dir.mkdir(parents=True,exist_ok=True)
    md=markdown(case)
    md_path=out_dir/'investigator_report.md';md_path.write_text(md,encoding='utf-8')
    html_path=out_dir/'investigator_report.html';html_path.write_text(html_report(case,md),encoding='utf-8')
    manifest={'schema':'ai-dfir/investigator-report/v1.6','case_id':case['summary']['case_id'],
              'markdown_sha256':hashlib.sha256(md_path.read_bytes()).hexdigest(),
              'html_sha256':hashlib.sha256(html_path.read_bytes()).hexdigest(),
              'evidence_coverage':case['coverage']}
    (out_dir/'report_manifest.json').write_text(json.dumps(manifest,indent=2,sort_keys=True),encoding='utf-8')
    return manifest


if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--case',required=True);ap.add_argument('--out',required=True)
    a=ap.parse_args();print(json.dumps(generate(Path(a.case),Path(a.out)),indent=2,sort_keys=True))
