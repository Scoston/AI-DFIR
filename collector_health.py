#!/usr/bin/env python3
"""Collector/source health and evidence-availability analysis."""
from __future__ import annotations
import argparse,json
from datetime import datetime
from pathlib import Path

def dt(s):return datetime.fromisoformat(str(s).replace('Z','+00:00')) if s else None

def analyze(expectations,observations,incident_window=None):
    obs={x.get('source_id'):x for x in observations};findings=[];sources=[]
    iw=incident_window or {};start=dt(iw.get('start_utc'));end=dt(iw.get('end_utc'))
    for e in expectations:
        sid=e['source_id'];o=obs.get(sid);critical=bool(e.get('mandatory',False));status='AVAILABLE';reasons=[]
        if not o:status='MISSING';reasons.append('no collector observation')
        else:
            if o.get('enabled') is False:status='DISABLED';reasons.append('logging/collector disabled')
            if o.get('last_error'):status='DEGRADED';reasons.append(str(o['last_error']))
            expected=e.get('expected_events');collected=o.get('collected_events')
            if expected is not None and collected is not None and expected>0 and collected/expected<float(e.get('min_event_ratio',.95)):
                status='INCOMPLETE';reasons.append(f'event coverage {collected}/{expected}')
            cs=dt(o.get('coverage_start_utc'));ce=dt(o.get('coverage_end_utc'))
            if start and (not cs or cs>start):status='INCOMPLETE';reasons.append('coverage starts after incident window')
            if end and (not ce or ce<end):status='INCOMPLETE';reasons.append('coverage ends before incident window')
            if o.get('retention_gap_seconds',0)>0:status='INCOMPLETE';reasons.append(f"retention gap {o.get('retention_gap_seconds')}s")
            if float(o.get('clock_uncertainty_ms') or 0)>float(e.get('max_clock_uncertainty_ms') or 60000):status='DEGRADED';reasons.append('clock uncertainty exceeds policy')
        if status!='AVAILABLE':findings.append({'type':'mandatory_evidence_source_unavailable' if critical else 'evidence_source_degraded','severity':'critical' if critical else 'high','source_id':sid,'status':status,'reasons':reasons})
        sources.append({'source_id':sid,'mandatory':critical,'status':status,'reasons':reasons,'expectation':e,'observation':o})
    unknown=sorted(set(obs)-{e['source_id'] for e in expectations})
    return {'schema':'ai-dfir/collector-health/v1.4','sources':sources,'unknown_sources':unknown,'findings':findings,
            'complete_mandatory':all(x['status']=='AVAILABLE' for x in sources if x['mandatory']),
            'rule':'Unavailable evidence is represented explicitly and never interpreted as evidence of absence.'}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--expectations',required=True);ap.add_argument('--observations',required=True);ap.add_argument('--incident-window');ap.add_argument('--out')
    a=ap.parse_args();e=json.loads(Path(a.expectations).read_text());e=e.get('sources',e);o=json.loads(Path(a.observations).read_text());o=o.get('sources',o);w=json.loads(Path(a.incident_window).read_text()) if a.incident_window else None
    r=analyze(e,o,w);s=json.dumps(r,indent=2,sort_keys=True);Path(a.out).write_text(s) if a.out else print(s)
if __name__=='__main__':main()
