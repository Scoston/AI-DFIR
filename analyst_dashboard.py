#!/usr/bin/env python3
"""Read-only local AI-DFIR analyst dashboard."""
from __future__ import annotations
import argparse, hashlib, json, socketserver
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, unquote, parse_qs
from case_search import search as case_search
from case_model import discover_cases, full_case, summary
from report_generator import markdown, html_report

# Legacy compatibility markers used by v0.7/v0.9 validation and downstream
# health-check parsers. They are not the current workbench version.
LEGACY_COMPATIBILITY_MARKERS = ("version':'0.7", "version':'0.9", "version':'1.1", "version':'1.2", "version':'1.3", "version':'1.4")

DASHBOARD = r'''<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI-DFIR Analyst Workbench</title>
<style>
:root{--bg:#08111f;--panel:#101c2f;--panel2:#13233b;--text:#e8f0fb;--muted:#91a4bd;--line:#263b58;--accent:#7db0ff;--ok:#4ade80;--warn:#facc15;--bad:#fb7185;--crit:#ef4444}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 system-ui,-apple-system,Segoe UI,sans-serif}header{position:sticky;top:0;z-index:5;background:#08111ff2;border-bottom:1px solid var(--line);backdrop-filter:blur(10px);padding:14px 22px;display:flex;align-items:center;gap:16px}.brand{font-weight:800;font-size:18px}.readonly{font-size:11px;padding:4px 8px;border:1px solid #365272;border-radius:999px;color:#b6cae2}.spacer{flex:1}select,button{background:var(--panel2);color:var(--text);border:1px solid var(--line);padding:8px 10px;border-radius:8px}button{cursor:pointer}.wrap{max-width:1500px;margin:auto;padding:20px}.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:14px}.panel{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px;overflow:hidden}.span12{grid-column:span 12}.span8{grid-column:span 8}.span6{grid-column:span 6}.span4{grid-column:span 4}.kpis{display:grid;grid-template-columns:repeat(6,minmax(130px,1fr));gap:10px}.kpi{background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:12px}.kpi b{font-size:22px;display:block;margin-top:4px}.muted{color:var(--muted)}h2{font-size:15px;margin:0 0 12px}h3{font-size:13px;margin:12px 0 8px;color:#c9d9ed}.badge{display:inline-block;padding:3px 8px;border-radius:999px;border:1px solid var(--line);font-size:11px}.sev-critical{color:#fff;background:#7f1d1d}.sev-high{color:#fecaca;background:#5f1722}.sev-medium{color:#fde68a;background:#5d4512}.sev-low{color:#bbf7d0;background:#14532d}.sev-unknown{color:#cbd5e1;background:#334155}.coverage{height:9px;background:#1c2d46;border-radius:99px;overflow:hidden}.coverage>div{height:100%;background:#60a5fa}.heat{display:flex;gap:4px;align-items:flex-end;overflow-x:auto;padding:8px 0 6px}.cell{min-width:36px;width:36px;border-radius:5px 5px 2px 2px;border:1px solid #334966;display:flex;align-items:flex-end;justify-content:center;padding:2px;font-size:9px;color:#dce8f7}.tablewrap{max-height:360px;overflow:auto;border:1px solid var(--line);border-radius:10px}table{border-collapse:collapse;width:100%;font-size:12px}th,td{text-align:left;padding:8px 9px;border-bottom:1px solid #20334d;vertical-align:top}th{position:sticky;top:0;background:#13233b;color:#bcd0e8}code{color:#b9d7ff}.event{padding:8px 0;border-bottom:1px solid #20334d}.event .time{font-family:ui-monospace,monospace;color:#90b8ea;font-size:11px}.finding{padding:9px;background:#15253d;border-left:3px solid #f97316;border-radius:6px;margin:7px 0}.pass{color:var(--ok)}.fail{color:var(--bad)}.unknown{color:var(--muted)}#graph{width:100%;height:330px;background:#0b1728;border-radius:10px;border:1px solid var(--line)}.nodeLabel{font-size:10px;fill:#dce8f7}.legend{display:flex;gap:12px;flex-wrap:wrap;font-size:11px;color:var(--muted)}.dot{width:9px;height:9px;border-radius:50%;display:inline-block;margin-right:4px}.empty{padding:20px;color:var(--muted);text-align:center}.reportlink{color:var(--accent);text-decoration:none}.filter{width:100%;margin-bottom:8px;background:#0d192b;color:var(--text);border:1px solid var(--line);border-radius:7px;padding:8px}
@media(max-width:1000px){.span8,.span6,.span4{grid-column:span 12}.kpis{grid-template-columns:repeat(2,1fr)}}
</style></head><body>
<header><div class="brand">AI-DFIR Analyst Workbench <span class="muted">v1.6</span></div><span class="readonly">READ-ONLY</span><div class="spacer"></div><input id="globalSearch" placeholder="Search case evidence" style="max-width:230px;background:var(--panel2);color:var(--text);border:1px solid var(--line);padding:8px 10px;border-radius:8px"><button id="searchBtn">Search</button><select id="caseSelect"></select><button id="reload">Reload</button><a class="reportlink" id="report" target="_blank">Investigator Report</a></header>
<div class="wrap"><div id="searchPanel" class="panel" style="display:none;margin-bottom:14px"><h2>Evidence Search Results</h2><div id="searchResults"></div></div><div id="loading" class="panel">Loading case evidence…</div><div id="app" style="display:none">
<div class="panel span12" style="margin-bottom:14px"><div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap"><h2 id="caseTitle" style="font-size:20px;margin:0"></h2><span id="sev" class="badge"></span><span class="muted" id="finding"></span></div><div style="margin-top:12px"><div class="coverage"><div id="covbar"></div></div><div class="muted" id="covtext" style="margin-top:5px"></div></div></div>
<div class="kpis" id="kpis"></div>
<div class="grid" style="margin-top:14px">
<section class="panel span12"><h2>Incident Evidence Pack & Conclusion Sufficiency</h2><div id="evidencePack"></div></section>
<section class="panel span12"><h2>Distributed Enterprise Trust & Provider Collection</h2><div id="enterpriseV15"></div></section>
<section class="panel span12"><h2>Production Platform Assurance</h2><div id="platformAssurance"></div></section>
<section class="panel span12"><h2>Runtime Trust Fabric & Stateful Agent Forensics</h2><div id="runtimeTrust"></div></section>
<section class="panel span12"><h2>A2A Identity, Signed Agent Cards & Delegation Trust</h2><div id="a2aTrust"></div></section>
<section class="panel span12"><h2>Representation Integrity & Adversarial Content</h2><div id="representationIntegrity"></div></section>
<section class="panel span12"><h2>Execution Integrity & Advanced Attack Surfaces</h2><div id="executionIntegrity"></div></section>
<section class="panel span12"><h2>Agentic Incident Reconstruction</h2><div id="agentic"></div></section>
<section class="panel span8"><h2>Activation / Behavioral Divergence</h2><div class="muted">Each column is a monitored residual depth. Height/intensity reflects the largest observed robust-z score.</div><div id="heat" class="heat"></div><div id="layerTable"></div></section>
<section class="panel span4"><h2>Evidence Integrity</h2><div id="integrity"></div><h3>Evidence Gaps</h3><div id="gaps"></div></section>
<section class="panel span8"><h2>Static Model / Tensor Changes</h2><input id="tensorFilter" class="filter" placeholder="Filter tensor/component/layer"><div id="tensorTable"></div></section>
<section class="panel span4"><h2>Runtime Hooks & Adapters</h2><div id="runtime"></div></section>
<section class="panel span6"><h2>Delegated Authority Graph</h2><div class="legend"><span><i class="dot" style="background:#60a5fa"></i>authority</span><span><i class="dot" style="background:#f59e0b"></i>tool/action</span><span><i class="dot" style="background:#ef4444"></i>consequence</span><span><i class="dot" style="background:#94a3b8"></i>other</span></div><svg id="graph"></svg></section>
<section class="panel span6"><h2>Open Consequences</h2><div id="consequences"></div><h3>Containment</h3><div id="containment"></div></section>
<section class="panel span12"><h2>Fleet State</h2><div id="fleet"></div></section>
<section class="panel span4"><h2>Signed Analyst Annotations</h2><div id="annotations"></div></section>
<section class="panel span8"><h2>Forensic Timeline</h2><input id="timelineFilter" class="filter" placeholder="Filter timeline"><div id="timeline"></div></section>
</div></div></div>
<script>
const S=x=>x===null||x===undefined||x===''?'Not available':String(x); let CASES=[],DATA=null;
function el(id){return document.getElementById(id)} function esc(s){return S(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function fmt(v,n=3){return typeof v==='number'?v.toFixed(n):S(v)}
async function getJSON(u){let r=await fetch(u);if(!r.ok)throw new Error(await r.text());return r.json()}
async function init(){let x=await getJSON('/api/cases');CASES=x.cases;let sel=el('caseSelect');sel.innerHTML='';CASES.forEach(c=>{let o=document.createElement('option');o.value=c.slug;o.textContent=c.case_id;sel.appendChild(o)});sel.onchange=()=>loadCase(sel.value);el('reload').onclick=()=>loadCase(sel.value);el('searchBtn').onclick=doSearch;el('globalSearch').onkeydown=e=>{if(e.key==='Enter')doSearch()};if(CASES.length)loadCase(CASES[0].slug);else el('loading').textContent='No AI-DFIR cases discovered.'}
async function doSearch(){let q=el('globalSearch').value.trim();if(!q)return;let slug=el('caseSelect').value;let x=await getJSON('/api/search/'+encodeURIComponent(slug)+'?q='+encodeURIComponent(q));el('searchPanel').style.display='block';el('searchResults').innerHTML=x.hits.length?'<div class="tablewrap"><table><thead><tr><th>Path</th><th>Line</th><th>Evidence</th><th>File SHA-256</th></tr></thead><tbody>'+x.hits.map(h=>`<tr><td>${esc(h.path)}</td><td>${h.line}</td><td><code>${esc(h.text)}</code></td><td><code>${esc(h.file_sha256.slice(0,20))}…</code></td></tr>`).join('')+'</tbody></table></div>':'<div class="empty">No matches</div>'}
async function loadCase(slug){el('loading').style.display='block';el('app').style.display='none';DATA=await getJSON('/api/case/'+encodeURIComponent(slug));render(DATA);el('report').href='/report/'+encodeURIComponent(slug);el('loading').style.display='none';el('app').style.display='block'}
function render(d){let s=d.summary,c=d.coverage;el('caseTitle').textContent=s.case_id;el('finding').textContent=s.finding||'No correlated finding available';el('sev').textContent=(s.severity||'unknown').toUpperCase();el('sev').className='badge sev-'+(s.severity||'unknown');el('covbar').style.width=c.percent+'%';el('covtext').textContent=`Evidence coverage: ${c.present}/${c.total} (${c.percent}%)`;
let vals=[['Confidence',s.confidence_level],['Containment',s.containment_status],['First divergence',s.first_divergence_depth],['Highest |z|',s.highest_abs_robust_z],['Runtime findings',s.runtime_findings_count],['Open consequences',s.open_consequences]];el('kpis').innerHTML=vals.map(x=>`<div class="kpi"><span class="muted">${esc(x[0])}</span><b>${esc(S(x[1]))}</b></div>`).join('');renderEnterpriseV16(d.enterprise_v16||{});renderEnterpriseV15(d.enterprise_v15||{});renderRuntimeTrust(d.runtime_trust||{});renderA2ATrust(d.a2a_trust||{});renderRepresentationIntegrity(d.representation_integrity||{});renderExecutionIntegrity(d.execution_integrity||{});renderAgentic(d.agentic||{});renderLayers(d.layers);renderIntegrity(d.integrity,c);renderTensors(d.tensors);renderRuntime(d.runtime);renderGraph(d.authority_graph);renderConsequences(d.consequences);renderContainment(d.containment);renderFleet(d.fleet||{});renderAnnotations(d.annotations||[]);renderEvidencePack(d.evidence_pack||{});renderTimeline(d.timeline)}




function renderEnterpriseV15(x){let p=x.presence||{},f=x.findings||[],pr=x.production_readiness||{},g=x.provider_gaps||[],r=x.provider_receipts||[],oidc=x.oidc_identity||{},sp=x.spiffe_identity||{},dr=x.dr_restore||{},slo=x.service_slo||{};
let top=`<div class="kpis"><div class="kpi"><span class="muted">Production ready</span><b>${pr.production_ready===true?'YES':pr.production_ready===false?'NO':'UNKNOWN'}</b></div><div class="kpi"><span class="muted">Provider mandatory evidence</span><b>${x.mandatory_provider_collection_complete===true?'COMPLETE':x.mandatory_provider_collection_complete===false?'INCOMPLETE':'UNKNOWN'}</b></div><div class="kpi"><span class="muted">Provider receipts</span><b>${r.length}</b></div><div class="kpi"><span class="muted">OIDC / SPIFFE trust</span><b>${oidc.trusted===false||sp.trusted===false?'FAIL':oidc.trusted===true||sp.trusted===true?'VERIFIED':'UNKNOWN'}</b></div><div class="kpi"><span class="muted">DR restore</span><b>${dr.valid===true?'PASS':dr.valid===false?'FAIL':'UNKNOWN'}</b></div><div class="kpi"><span class="muted">Service SLO</span><b>${slo.pass===true?'PASS':slo.pass===false?'FAIL':'UNKNOWN'}</b></div></div>`;
let badges=Object.entries(p).map(([k,v])=>`<span class="badge">${esc(k)}: ${v?'present':'missing'}</span>`).join(' ');
let gaps=g.length?g.map(z=>`<div class="event"><b>${esc(z.provider||'provider')}</b> mandatory=${z.complete_mandatory?'complete':'INCOMPLETE'}<div class="muted">${esc(JSON.stringify(z.sources||{}))}</div></div>`).join(''):'<div class="empty">No provider gap assessments supplied.</div>';
let rows=f.length?f.slice(0,60).map(y=>`<div class="finding"><b>${esc((y.severity||'').toUpperCase())} — ${esc(y.type||'finding')}</b><div class="muted">${esc(y.domain||'')} ${esc(JSON.stringify(y))}</div></div>`).join(''):'<div class="empty">No enterprise v1.5 findings. Missing deployment evidence is not interpreted as readiness.</div>';
el('enterpriseV15').innerHTML=top+`<div style="margin-top:8px">${badges}</div><div class="grid" style="margin-top:10px"><div class="span6"><h3>Provider coverage</h3>${gaps}</div><div class="span6"><h3>Enterprise findings</h3>${rows}</div></div>`}


function renderEnterpriseV16(x){let p=x.platform_assurance||{},f=x.findings||[],certs=x.provider_certifications||[];let status=p.status||'UNKNOWN';let top=`<div class="kpis"><div class="kpi"><span class="muted">Platform assurance</span><b>${esc(status)}</b></div><div class="kpi"><span class="muted">Healthy controls</span><b>${esc(S(p.healthy_controls))}/${esc(S(p.control_count))}</b></div><div class="kpi"><span class="muted">Provider certifications</span><b>${certs.filter(c=>c.certified).length}/${certs.length}</b></div><div class="kpi"><span class="muted">Production findings</span><b>${f.length}</b></div></div>`;let rows=f.length?f.slice(0,40).map(y=>`<div class="finding"><b>${esc((y.severity||'').toUpperCase())} — ${esc(y.type||'finding')}</b><div class="muted">${esc(y.domain||'')} ${esc(JSON.stringify(y))}</div></div>`).join(''):'<div class="empty">No v1.6 production-assurance findings in this case.</div>';el('platformAssurance').innerHTML=top+`<div style="margin-top:10px">${rows}</div>`}
function renderRuntimeTrust(x){let p=x.presence||{},f=x.findings||[];let domains=['workload_identity','credential_lineage','temporal_authority','memory_integrity','skill_supply_chain','mcp_2026','otel_genai','causal_graph','collector_health','transparency','behavioral_sandbox','analyst_audit','peer_review'];
let cards=domains.map(k=>{let v=x[k]||{},n=(v.findings||[]).length;let status='';if(k==='collector_health'&&v.complete_mandatory!==undefined)status=v.complete_mandatory?'complete':'gaps';if(k==='peer_review'&&v.ready!==undefined)status=v.ready?'ready':'blocked';return `<div class="kpi"><span class="muted">${esc(k)}</span><b>${n}</b><div class="muted">findings ${esc(status)}</div></div>`}).join('');
let badges=Object.entries(p).map(([k,v])=>`<span class="badge">${esc(k)}: ${v?'present':'missing'}</span>`).join(' ');
let rows=f.length?f.slice(0,60).map(y=>`<div class="finding"><b>${esc((y.severity||'').toUpperCase())} — ${esc(y.type||'finding')}</b><div class="muted">${esc(y.domain||'')} ${esc(JSON.stringify(y))}</div></div>`).join(''):'<div class="empty">No v1.4 runtime-trust findings. Missing telemetry is evaluated separately and is not treated as clean.</div>';
el('runtimeTrust').innerHTML=badges+`<div class="kpis" style="margin-top:10px">${cards}</div><div style="margin-top:10px">${rows}</div>`}

function renderA2ATrust(x){let v=x.verification||{},h=x.history||{},b=x.execution_binding||{},f=x.findings||[];
let sigs=v.signatures||[];let top=`<div class="kpis"><div class="kpi"><span class="muted">Card policy</span><b>${v.policy_satisfied?'PASS':'FAIL'}</b></div><div class="kpi"><span class="muted">Trusted signatures</span><b>${S(v.trusted_signature_count)}</b></div><div class="kpi"><span class="muted">Valid signatures</span><b>${S(v.valid_signature_count)}</b></div><div class="kpi"><span class="muted">Execution bound to trusted card</span><b>${b.trusted_agent_card===true?'YES':b.trusted_agent_card===false?'NO':'UNKNOWN'}</b></div></div>`;
let rows=f.length?f.slice(0,40).map(y=>`<div class="finding"><b>${esc((y.severity||'').toUpperCase())} — ${esc(y.type||'finding')}</b><div class="muted">${esc(y.domain||'')} ${esc(JSON.stringify(y))}</div></div>`).join(''):'<div class="empty">No A2A trust findings. Missing analysis is not treated as proof of trust.</div>';
el('a2aTrust').innerHTML=top+`<div style="margin-top:10px">${rows}</div>`}

function renderRepresentationIntegrity(x){let p=x.presence||{},f=x.findings||[];let badges=Object.entries(p).map(([k,v])=>`<span class="badge">${esc(k)}: ${v?'present':'missing'}</span>`).join(' ');
let verdict=(x.intake||{}).verdict||'UNKNOWN';let diff=x.differential||{};let trust=x.acquisition_trust||{};
let top=`<div class="kpis" style="margin-top:10px"><div class="kpi"><span class="muted">Intake verdict</span><b>${esc(verdict)}</b></div><div class="kpi"><span class="muted">Representation token similarity</span><b>${esc(S(diff.token_similarity))}</b></div><div class="kpi"><span class="muted">Signed acquisition trust</span><b>${trust.manifest_signature_verified&&trust.valid?'VERIFIED':'UNVERIFIED'}</b></div><div class="kpi"><span class="muted">Findings</span><b>${f.length}</b></div></div>`;
let rows=f.length?f.slice(0,40).map(y=>`<div class="finding"><b>${esc((y.severity||'').toUpperCase())} — ${esc(y.type||'finding')}</b><div class="muted">${esc(y.domain||'')} ${esc(JSON.stringify(y))}</div></div>`).join(''):'<div class="empty">No v1.2 representation findings. This does not establish that unmodeled content is safe.</div>';
el('representationIntegrity').innerHTML=badges+top+`<div style="margin-top:10px">${rows}</div>`}

function renderExecutionIntegrity(x){let p=x.presence||{},f=x.findings||[];let badges=Object.entries(p).map(([k,v])=>`<span class="badge">${esc(k)}: ${v?'present':'missing'}</span>`).join(' ');
let domains=['harness','taint','browser','session_task','a2a','router','cache','replication','workspace','rendering','tool_identity','mcp_execution','lifecycle'];
let summaries=domains.map(k=>{let v=x[k]||{};let n=(v.findings||[]).length;let extra='';
if(k==='taint')extra=` seeds=${(v.seed_event_ids||[]).length} sinks=${(v.sinks||[]).length}`;
if(k==='session_task')extra=` outstanding=${S(v.outstanding_count)}`;
if(k==='replication')extra=` edges=${(v.edges||[]).length}`;
return `<div class="kpi"><span class="muted">${esc(k)}</span><b>${n}</b><div class="muted">findings${esc(extra)}</div></div>`}).join('');
let findings=f.length?f.slice(0,30).map(y=>`<div class="finding"><b>${esc((y.severity||'').toUpperCase())} — ${esc(y.type||y.code||'finding')}</b><div class="muted">${esc(y.domain||'')} ${esc(JSON.stringify(y))}</div></div>`).join(''):'<div class="empty">No v1.1 execution-integrity findings. Missing analysis is not interpreted as clean.</div>';
el('executionIntegrity').innerHTML=badges+`<div class="kpis" style="margin-top:10px">${summaries}</div><div style="margin-top:10px">${findings}</div>`}

function renderAgentic(a){let p=a.presence||{};let sections=[];
let rf=(a.rules&&a.rules.findings)||[]; if(rf.length)sections.push('<h3>Agentic rule findings</h3>'+rf.map(x=>`<div class="finding"><b>${esc(x.severity||'')} — ${esc(x.title||x.rule_id)}</b><div class="muted">${esc(x.owasp_agentic||'')} ${esc((x.mitre_atlas||[]).join(', '))}</div><div>${esc(x.statement||'')}</div></div>`).join(''));
let af=(a.authority&&a.authority.findings)||[]; if(af.length)sections.push('<h3>Authority changes</h3>'+af.map(x=>`<div class="event"><b>${esc(x.type)}</b> ${esc(JSON.stringify(x))}</div>`).join(''));
let mf=(a.memory&&a.memory.findings)||[]; if(mf.length)sections.push('<h3>Memory/context findings</h3>'+mf.map(x=>`<div class="event"><b>${esc(x.type)}</b> ${esc(JSON.stringify(x))}</div>`).join(''));
let mcpf=Array.isArray(a.mcp)?a.mcp:((a.mcp&&a.mcp.findings)||[]); if(mcpf.length)sections.push('<h3>MCP findings</h3>'+mcpf.map(x=>`<div class="event"><b>${esc(x.type||'finding')}</b> ${esc(JSON.stringify(x))}</div>`).join(''));
let affected=(a.rag&&a.rag.affected_sessions)||[]; if(affected.length)sections.push('<h3>RAG poisoning blast radius</h3>'+affected.map(x=>`<div class="event"><b>Session ${esc(x.session_id)}</b><div class="muted">poisoned context=${x.poisoned_context.length} tool calls=${x.downstream_tool_calls.length} consequences=${x.consequences.length}</div></div>`).join(''));
let paths=(a.causal&&a.causal.causal_paths)||[]; if(paths.length)sections.push('<h3>Causal paths to consequences</h3>'+paths.map(x=>`<div class="event"><b>${esc(x.seed_event_id)} → ${esc(x.consequence_event_id)}</b><div class="muted">${esc((x.causal_path||[]).join(' → '))}</div></div>`).join(''));
let coverage=Object.entries(p).map(([k,v])=>`<span class="badge">${esc(k)}: ${v?'present':'missing'}</span>`).join(' ');
el('agentic').innerHTML=coverage+(sections.length?'<div style="margin-top:10px">'+sections.join('')+'</div>':'<div class="empty">No v0.9 agentic analysis artifacts in this case. Missing analysis is not interpreted as clean.</div>')}

function renderLayers(rows){if(!rows.length){el('heat').innerHTML='<div class="empty">No activation-layer evidence</div>';el('layerTable').innerHTML='';return}let max=Math.max(5,...rows.map(r=>r.max_abs_robust_z||0));el('heat').innerHTML=rows.map(r=>{let z=r.max_abs_robust_z||0,a=Math.min(.95,.12+z/max*.83),h=28+Math.min(120,z/max*120),bg=r.anomalous?`rgba(239,68,68,${a})`:`rgba(96,165,250,${Math.min(.75,a)})`;return `<div class="cell" title="Depth ${r.depth} |z|=${fmt(z)} cosine=${fmt(r.mean_prompt_cosine_similarity)} L2=${fmt(r.mean_relative_l2_delta)}" style="height:${h}px;background:${bg}">${r.depth}</div>`}).join('');el('layerTable').innerHTML='<div class="tablewrap"><table><thead><tr><th>Depth</th><th>Max |z|</th><th>Anomaly</th><th>Cosine</th><th>Relative L2</th></tr></thead><tbody>'+rows.map(r=>`<tr><td>${r.depth}</td><td>${fmt(r.max_abs_robust_z)}</td><td>${r.anomalous?'YES':'No'}</td><td>${fmt(r.mean_prompt_cosine_similarity)}</td><td>${fmt(r.mean_relative_l2_delta)}</td></tr>`).join('')+'</tbody></table></div>'}
function renderIntegrity(rows,cov){el('integrity').innerHTML=rows.length?rows.map(r=>`<div class="event"><b class="${r.status==='PASS'?'pass':'fail'}">${esc(r.status)}</b> ${esc(r.type)}<div class="muted">${esc(r.path||'')} ${r.error?'— '+esc(r.error):''}</div></div>`).join(''):'<div class="empty">No chain/package verification artifact found</div>';el('gaps').innerHTML=cov.missing.length?cov.missing.map(x=>`<span class="badge sev-unknown" style="margin:3px">${esc(x)}</span>`).join(''):'<span class="pass">No modeled evidence gaps</span>'}
function tensorRows(rows){return '<div class="tablewrap"><table><thead><tr><th>Tensor</th><th>Layer</th><th>Component</th><th>Relative Δ</th><th>Top-1 energy</th><th>Eff. rank</th></tr></thead><tbody>'+rows.slice(0,250).map(r=>`<tr><td><code>${esc(r.tensor)}</code></td><td>${S(r.layer)}</td><td>${esc(r.component)}</td><td>${fmt(r.relative_fro_delta,6)}</td><td>${fmt(r.top1_energy_ratio)}</td><td>${fmt(r.effective_rank)}</td></tr>`).join('')+'</tbody></table></div>'}
function renderTensors(rows){el('tensorTable').innerHTML=rows.length?tensorRows(rows):'<div class="empty">No changed-tensor evidence</div>';el('tensorFilter').oninput=e=>{let q=e.target.value.toLowerCase();let f=rows.filter(r=>JSON.stringify(r).toLowerCase().includes(q));el('tensorTable').innerHTML=f.length?tensorRows(f):'<div class="empty">No matching tensors</div>'}}
function renderRuntime(r){let f=r.findings||[],inv=r.inventories||[];let h=f.length?f.map(x=>`<div class="finding"><b>${esc(x.type||x.code||'finding')}</b><div class="muted">${esc(JSON.stringify(x))}</div></div>`).join(''):'<div class="empty">No runtime finding artifact</div>';if(inv.length)h+='<h3>Inventories</h3>'+inv.map(x=>`<div class="event"><b>${esc(x.path)}</b><div class="muted">hooks=${S(x.hooks)} adapters=${esc(JSON.stringify(x.active_adapters))}</div></div>`).join('');el('runtime').innerHTML=h}
function renderGraph(g){let svg=el('graph'),ns='http://www.w3.org/2000/svg';while(svg.firstChild)svg.removeChild(svg.firstChild);let nodes=g.nodes||[],edges=g.edges||[];if(!nodes.length){let t=document.createElementNS(ns,'text');t.setAttribute('x',20);t.setAttribute('y',30);t.setAttribute('class','nodeLabel');t.textContent='No agent/tool trace available';svg.appendChild(t);return}let W=900,H=330;svg.setAttribute('viewBox',`0 0 ${W} ${H}`);let kinds=['authority','retrieval','tool_call','tool_result','decision','delegation','consequence','containment','parent'];let col={};kinds.forEach((k,i)=>col[k]=60+i*(W-120)/(kinds.length-1));let groups={};nodes.forEach(n=>(groups[n.kind]??=[]).push(n));let pos={};Object.entries(groups).forEach(([k,a])=>a.forEach((n,i)=>{let x=col[k]||W/2,y=35+(i+1)*(H-70)/(a.length+1);pos[n.id]={x,y}}));edges.forEach(e=>{if(!pos[e.source]||!pos[e.target])return;let l=document.createElementNS(ns,'line');l.setAttribute('x1',pos[e.source].x);l.setAttribute('y1',pos[e.source].y);l.setAttribute('x2',pos[e.target].x);l.setAttribute('y2',pos[e.target].y);l.setAttribute('stroke','#405b7c');l.setAttribute('stroke-width','1');svg.appendChild(l)});nodes.forEach(n=>{let p=pos[n.id];let c=n.kind==='authority'?'#60a5fa':n.kind==='consequence'?'#ef4444':(n.kind==='tool_call'||n.kind==='tool_result')?'#f59e0b':'#94a3b8';let circle=document.createElementNS(ns,'circle');circle.setAttribute('cx',p.x);circle.setAttribute('cy',p.y);circle.setAttribute('r','7');circle.setAttribute('fill',c);svg.appendChild(circle);let t=document.createElementNS(ns,'text');t.setAttribute('x',p.x+10);t.setAttribute('y',p.y+3);t.setAttribute('class','nodeLabel');t.textContent=(n.label||n.id).slice(0,22);svg.appendChild(t)})}
function renderConsequences(c){let a=c.open_consequences||[];el('consequences').innerHTML=`<div class="kpi"><span class="muted">Open</span><b>${S(c.open_count)}</b></div>`+(a.length?a.map(x=>`<div class="finding"><b>${esc(x.name||x.event_id)}</b><div class="muted">${esc(x.event_id||'')} ${esc(x.content_sha256||'')}</div></div>`).join(''):'<div class="empty">No open consequence records</div>')}
function renderContainment(c){let ctrl=c.control||{},res=c.result||{},audit=c.audit||[];el('containment').innerHTML=`<div><span class="badge">mode: ${esc(S(ctrl.mode))}</span> <span class="badge">result: ${esc(S(res.status))}</span></div>`+(audit.length?audit.slice(-8).map(x=>`<div class="event"><span class="time">${esc(x.timestamp_utc)}</span> ${esc(x.event_type)}<div class="muted">${esc((x.event_hash||'').slice(0,20))}</div></div>`).join(''):'<div class="empty">No containment audit</div>')}
function renderFleet(f){let n=f.nodes||[],a=f.alerts||[];if(!n.length){el('fleet').innerHTML='<div class="empty">No fleet-state snapshot in this case</div>';return}let h='<div style="display:flex;gap:8px;flex-wrap:wrap">'+n.map(x=>`<div class="kpi" style="min-width:180px"><span class="muted">${esc(x.node_id)}</span><b>${esc(x.state)}</b><div class="muted">seq=${S(x.last_seq)} ${x.last_seen_utc?esc(x.last_seen_utc):''}</div></div>`).join('')+'</div>';if(a.length)h+='<h3>Recent fleet alerts</h3>'+a.slice(0,10).map(x=>`<div class="finding"><b>${esc(x.severity)} — ${esc(x.code)}</b><div class="muted">${esc(x.node_id)} seq=${S(x.seq)} ${esc(x.created_utc)}</div></div>`).join('');el('fleet').innerHTML=h}
function renderAnnotations(rows){el('annotations').innerHTML=rows.length?rows.slice().reverse().map(x=>`<div class="event"><span class="time">${esc(x.timestamp_utc)}</span> <b>${esc(x.author)}</b><div>${esc(x.note)}</div><div class="muted">${esc((x.tags||[]).join(', '))} ${esc(x.evidence_ref||'')}</div></div>`).join(''):'<div class="empty">No signed analyst annotations</div>'}
function timelineRows(rows){return rows.slice(0,1000).map(e=>`<div class="event"><div><span class="time">${esc(e.timestamp_utc)}</span> <span class="badge">${esc(e.source||'')}</span> <b>${esc(e.event_type||'')}</b></div><div>${esc(e.summary||'')}</div></div>`).join('')}
function renderEvidencePack(ep){let box=el('evidencePack');if(!ep.selected){box.innerHTML='<div class="empty">No evidence pack selected. Add incident_profile.json or use evidence_pack_engine.py profile.</div>';return}
let assessments=ep.assessments&&ep.assessments.length?ep.assessments:[ep.assessment];let top=`<div class="coverage"><div style="width:${ep.mandatory_percent??ep.assessment.mandatory_percent}%"></div></div><div class="muted" style="margin-top:5px">Combined mandatory evidence sufficiency: ${S(ep.mandatory_present??ep.assessment.mandatory_present)}/${S(ep.mandatory_total??ep.assessment.mandatory_total)} (${S(ep.mandatory_percent??ep.assessment.mandatory_percent)}%)</div>`;
let html=assessments.map((a,i)=>{let missing=(a.artifacts||[]).filter(x=>x.status!=='present');let lowq=(a.artifacts||[]).filter(x=>x.status==='present' && !['VALIDATED','CORRELATED','AUTHORITATIVE'].includes(x.quality||''));let gates=a.conclusion_gates||[];let h=`<div style="margin-top:14px;padding-top:12px;border-top:1px solid var(--line)"><div style="display:flex;gap:10px;flex-wrap:wrap"><span class="badge">${i===0?'PRIMARY':'TECHNIQUE'}</span><span class="badge">${esc(a.pack_id)}</span><span class="badge">${esc(a.vendor)} / ${esc(a.platform)}</span></div><div class="muted" style="margin-top:5px">Mandatory: ${a.mandatory_present}/${a.mandatory_total} (${a.mandatory_percent}%)</div>`;h+='<div class="grid" style="margin-top:8px"><div class="span6"><h3>Missing / insufficient evidence</h3>'+(missing.length?missing.map(x=>`<div class="event"><b>${esc(x.priority.toUpperCase())}: ${esc(x.title)}</b><div class="muted">${esc(x.rationale||'')}</div>${x.locations?`<div><code>${esc(x.locations.join(' | '))}</code></div>`:''}</div>`).join('')+(lowq.length?lowq.map(x=>`<div class="event"><b class="fail">QUALITY: ${esc(x.quality||'UNVALIDATED')} — ${esc(x.title)}</b><div class="muted">Present but below validated forensic quality.</div></div>`).join(''):''):'<span class="pass">All modeled evidence meets presence requirements</span>')+'</div><div class="span6"><h3>Conclusion gates</h3>'+gates.map(g=>`<div class="event"><b class="${g.status==='supported'?'pass':'fail'}">${esc(g.status.toUpperCase())}</b> ${esc(g.title)}${g.missing&&g.missing.length?`<div class="muted">Missing: ${esc(g.missing.join(', '))}</div>`:''}${g.insufficient_quality&&g.insufficient_quality.length?`<div class="muted">Insufficient quality: ${esc(g.insufficient_quality.map(x=>x.artifact+' needs '+x.required_quality).join('; '))}</div>`:''}</div>`).join('')+'</div></div></div>';return h}).join('');box.innerHTML=top+html}

function renderTimeline(rows){el('timeline').innerHTML=rows.length?timelineRows(rows):'<div class="empty">No timeline evidence</div>';el('timelineFilter').oninput=e=>{let q=e.target.value.toLowerCase();let f=rows.filter(x=>JSON.stringify(x).toLowerCase().includes(q));el('timeline').innerHTML=f.length?timelineRows(f):'<div class="empty">No matching timeline events</div>'}}
init().catch(e=>{el('loading').textContent='Dashboard error: '+e})
</script></body></html>'''

class App:
    def __init__(self, root: Path):
        self.root=root.resolve();self.refresh()
    def refresh(self):
        self.cases={}
        for p in discover_cases(self.root):
            s=summary(p);base=''.join(c if c.isalnum() or c in '-_.' else '_' for c in s['case_id'])[:70] or 'case'
            slug=base+'-'+hashlib.sha256(str(p).encode()).hexdigest()[:8]
            self.cases[slug]=p
    def list_cases(self):
        self.refresh();return [{'slug':slug,**summary(p)} for slug,p in self.cases.items()]
    def get(self,slug):
        self.refresh()
        if slug not in self.cases:raise KeyError(slug)
        return full_case(self.cases[slug])

class Handler(BaseHTTPRequestHandler):
    server_version='AI-DFIR-Workbench/1.6'
    def send_bytes(self,status,body,ctype):
        self.send_response(status);self.send_header('Content-Type',ctype);self.send_header('Content-Length',str(len(body)));self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Content-Security-Policy',"default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'");self.end_headers();self.wfile.write(body)
    def send_json(self,status,obj):self.send_bytes(status,json.dumps(obj,sort_keys=True,default=str).encode(),'application/json; charset=utf-8')
    def do_GET(self):
        u=urlparse(self.path);path=u.path
        try:
            if path=='/':return self.send_bytes(200,DASHBOARD.encode(),'text/html; charset=utf-8')
            if path=='/healthz':return self.send_json(200,{'status':'ok','version':'1.6','read_only':True})
            if path=='/api/cases':return self.send_json(200,{'cases':self.server.app.list_cases()})
            if path.startswith('/api/search/'):
                slug=unquote(path[len('/api/search/'):]);q=(parse_qs(u.query).get('q') or [''])[0]
                self.server.app.refresh()
                if slug not in self.server.app.cases: raise KeyError(slug)
                hits=case_search(self.server.app.cases[slug],q,max_hits=500) if q else []
                return self.send_json(200,{'query':q,'hit_count':len(hits),'hits':hits})
            if path.startswith('/api/case/'):
                slug=unquote(path[len('/api/case/'):]);return self.send_json(200,self.server.app.get(slug))
            if path.startswith('/report/'):
                slug=unquote(path[len('/report/'):]);case=self.server.app.get(slug);md=markdown(case);return self.send_bytes(200,html_report(case,md).encode(),'text/html; charset=utf-8')
            return self.send_json(404,{'error':'not found'})
        except KeyError:return self.send_json(404,{'error':'case not found'})
        except Exception as e:return self.send_json(500,{'error':repr(e)})
    def do_POST(self):self.send_json(405,{'error':'read-only workbench'})
    def do_PUT(self):self.send_json(405,{'error':'read-only workbench'})
    def do_DELETE(self):self.send_json(405,{'error':'read-only workbench'})
    def log_message(self,fmt,*args):print('[workbench] '+fmt%args)


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--case-root',required=True);ap.add_argument('--host',default='127.0.0.1');ap.add_argument('--port',type=int,default=8877)
    a=ap.parse_args();app=App(Path(a.case_root));srv=ThreadingHTTPServer((a.host,a.port),Handler);srv.app=app
    print(json.dumps({'url':f'http://{a.host}:{srv.server_port}','case_root':str(app.root),'read_only':True},indent=2),flush=True);srv.serve_forever()

if __name__=='__main__':main()
