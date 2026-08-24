#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,shutil,subprocess,sys,tempfile
from datetime import datetime,timezone
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from evidence_pack_engine import load_packs
from environment_separation_v16 import analyze as env_analyze
from provider_certification_v16 import certify
from chaos_validation_v16 import assess as chaos_assess
from network_policy_validation_v16 import analyze as network_analyze
from security_assurance_v16 import assess as security_assess
from upgrade_assurance_v16 import assess as upgrade_assess
from platform_assurance_v16 import evaluate as platform_evaluate,REQUIRED
from release_integrity_v16 import verify as release_verify
from production_readiness_v16 import assess as readiness_assess
from case_model import full_case

def writej(p,o):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(o,indent=2,sort_keys=True))
def now():return datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
def main():
 import argparse
 ap=argparse.ArgumentParser();ap.add_argument('--out',required=True);a=ap.parse_args();out=Path(a.out).resolve();shutil.rmtree(out,ignore_errors=True);out.mkdir(parents=True);r={}
 packs=load_packs();ids={x['id'] for x in packs};assert len(packs)>=111
 for pid in ('production.platform_assurance_failure','production.provider_certification_gap','production.release_provenance_failure','production.environment_separation_failure'):assert pid in ids
 r['production_evidence_pack_catalog']='PASS'
 env=env_analyze(json.loads((HERE/'config/environments.json').read_text()));assert env['valid'];r['environment_separation']='PASS'
 profile={'provider':'openai','adapter':'openai_org','api_version':'2026-08','max_certification_age_days':90,'known_limitations':['aggregate usage is not request history']}
 receipts=[{'test':t,'pass':True,'validated_utc':now(),'api_version':'2026-08'} for t in ['authentication','pagination','rate_limit_recovery','time_window','schema_normalization','evidence_gap_reporting','negative_permission_case']]
 cert=certify(profile,receipts);assert cert['certified'];r['provider_certification']='PASS'
 policy=json.loads((HERE/'config/chaos_policy.json').read_text());cr=[{'scenario':s,'pass':True,'recovery_seconds':30,'data_loss_events':0} for s in policy['scenarios']];chaos=chaos_assess(cr,policy);assert chaos['valid'];r['chaos_validation']='PASS'
 net=network_analyze([HERE/'deploy/kubernetes/policies/hardening.yaml']);assert net['valid'];r['network_policy_validation']='PASS'
 report={'independent_assessor':'External Security Lab','completed_utc':now(),'unresolved_findings':{'critical':0,'high':0},'scope':['tenant_isolation','authentication','authorization','evidence_integrity','collector_impersonation','parser_fuzzing','ssrf','supply_chain','closure_bypass']}
 sec=security_assess(report,json.loads((HERE/'config/security_assurance_policy.json').read_text()));assert sec['valid'];r['security_assurance']='PASS'
 up=upgrade_assess({'from_version':'1.5.0','to_version':'1.6.0','pre_upgrade_backup_verified':True,'migration_applied':True,'post_upgrade_integrity_verified':True,'rollback_tested':True,'rollback_integrity_verified':True});assert up['valid'];r['upgrade_rollback_assurance']='PASS'
 # migration idempotency
 db=out/'migrate.db';cp=subprocess.run([sys.executable,str(HERE/'schema_migration_v16.py'),'--migrations',str(HERE/'migrations/sqlite'),'--sqlite',str(db),'--out',str(out/'migration.json')],capture_output=True,text=True);assert cp.returncode==0,(cp.stdout,cp.stderr)
 cp=subprocess.run([sys.executable,str(HERE/'schema_migration_v16.py'),'--migrations',str(HERE/'migrations/sqlite'),'--sqlite',str(db)],capture_output=True,text=True);assert cp.returncode==0
 r['transactional_schema_migration']='PASS'
 # release integrity
 rel=out/'release';rel.mkdir();(rel/'a.bin').write_bytes(b'abc');digest=hashlib.sha256(b'abc').hexdigest();(rel/'SHA256SUMS').write_text(f'{digest}  a.bin\n');ri=release_verify(rel,rel/'SHA256SUMS');assert ri['valid'];r['release_integrity']='PASS'
 # platform assurance with current validated control artifacts
 controls={}
 for name in REQUIRED:
  p=out/f'{name}.json';writej(p,{'schema':f'ai-dfir/{name}/selftest','valid':True,'validated_utc':now()});controls[name]={'evidence':str(p),'max_age_hours':24}
 pa=platform_evaluate({'controls':controls});assert pa['status']=='HEALTHY';writej(out/'platform_assurance.json',pa);r['platform_assurance']='PASS'
 # production readiness v1.6 aggregation
 artifacts={'v15':{'schema':'ai-dfir/production-readiness/v1.5','production_ready':True,'validated_utc':now()},'env':{**env,'validated_utc':now()},'chaos':{**chaos,'validated_utc':now()},'release':{**ri,'validated_utc':now()},'security':{**sec,'validated_utc':now()},'upgrade':{**up,'validated_utc':now()},'network':{**net,'validated_utc':now()},'cert':cert,'slo':{'schema':'ai-dfir/service-slo/v1.5','pass':True,'validated_utc':now()},'bench':{'schema':'ai-dfir/scale-benchmark/v1.5','backend':'postgres','deployment_benchmark':True,'validated_utc':now()}}
 paths={}
 for k,v in artifacts.items():p=out/f'{k}.json';writej(p,v);paths[k]=str(p)
 cfg={'platform_assurance':str(out/'platform_assurance.json'),'environment_separation':paths['env'],'chaos_validation':paths['chaos'],'release_integrity':paths['release'],'security_assurance':paths['security'],'upgrade_assurance':paths['upgrade'],'network_policy_validation':paths['network'],'provider_certifications':[paths['cert']],'service_slo':paths['slo'],'scale_benchmark':paths['bench']}
 ready=readiness_assess(cfg,artifacts['v15']);assert ready['production_ready'];r['production_readiness_v16']='PASS'
 # orchestrator + case/workbench
 case=out/'case';case.mkdir();writej(case/'case.json',{'case_id':'V16-1','tool_version':'1.6'});bad_env={'schema':'ai-dfir/environment-separation/v1.6','valid':False,'findings':[{'type':'environment_control_reused','severity':'critical'}]};bad=out/'bad_env.json';writej(bad,bad_env)
 cp=subprocess.run([sys.executable,str(HERE/'enterprise_v16_analyze.py'),'--case',str(case),'--environment-separation',str(bad)],capture_output=True,text=True);assert cp.returncode==0,(cp.stdout,cp.stderr)
 prof=json.loads((case/'incident_profile.json').read_text());assert 'production.environment_separation_failure' in prof.get('additional_evidence_pack_ids',[])
 fc=full_case(case);assert fc['enterprise_v16']['presence']['environment_separation'];dash=(HERE/'analyst_dashboard.py').read_text();assert "version':'1.6" in dash and 'Production Platform Assurance' in dash
 r['case_workbench_and_pack_attachment']='PASS'
 # github/release/deployment repo checks
 cp=subprocess.run([sys.executable,str(HERE/'scripts/github_repo_check_v16.py')],capture_output=True,text=True);assert cp.returncode==0,(cp.stdout,cp.stderr);r['github_repository_surface']='PASS'
 assert (HERE/'deploy/kubernetes/helm/ai-dfir/Chart.yaml').exists() and (HERE/'deploy/production/Dockerfile').exists();r['production_deployment_assets']='PASS'
 final={'schema':'ai-dfir/selftest/v1.6','status':'PASS','evidence_pack_count':len(packs),'components':r};writej(out/'V1.6_SELFTEST.json',final);print(json.dumps(final,indent=2,sort_keys=True))
if __name__=='__main__':main()
