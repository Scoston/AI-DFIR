#!/usr/bin/env python3
"""Provider-native, read-only evidence collectors for AI-DFIR v1.5.

All network collectors use fixed HTTPS provider hosts and bounded pagination.
Secrets are read from environment variables or caller parameters and are never
written into collection artifacts or receipts. A receipt records whether the
source was exhausted or only partially collected.
"""
from __future__ import annotations
import argparse,hashlib,json,os,re
from pathlib import Path
from urllib.parse import urlparse
import requests

UA='AI-DFIR-v1.5-Forensic-Collector'
DEFAULT_MAX_PAGES=100

def sha_bytes(b):return hashlib.sha256(b).hexdigest()
def write_artifact(out,obj,source,request_meta,limitations=None):
    out=Path(out);out.parent.mkdir(parents=True,exist_ok=True)
    raw=json.dumps(obj,indent=2,sort_keys=True,default=str).encode();out.write_bytes(raw)
    rec={'schema':'ai-dfir/provider-collection-receipt/v1.5','source':source,'artifact_path':str(out),
         'sha256':sha_bytes(raw),'size_bytes':len(raw),'request':request_meta,
         'collection_complete':bool(request_meta.get('collection_complete',False)),
         'page_count':request_meta.get('page_count',1),'limitations':limitations or []}
    out.with_suffix(out.suffix+'.receipt.json').write_text(json.dumps(rec,indent=2,sort_keys=True))
    return rec

def req(method,url,headers=None,params=None,json_body=None,allowed_hosts=()):
    u=urlparse(url)
    if u.scheme!='https' or u.hostname not in allowed_hosts:raise ValueError('provider endpoint not allowlisted')
    h={'User-Agent':UA,**(headers or {})}
    r=requests.request(method,url,headers=h,params=params,json=json_body,timeout=45)
    r.raise_for_status()
    meta={'method':method,'url':u.scheme+'://'+u.netloc+u.path,'status':r.status_code,
          'request_id':r.headers.get('x-request-id') or r.headers.get('request-id') or r.headers.get('x-ms-request-id'),
          'link':r.headers.get('Link')}
    return r.json(),meta

def _merge_pages(pages):
    # Preserve page boundaries for evidentiary fidelity while providing a flat
    # common view for ordinary list responses.
    return {'schema':'ai-dfir/provider-paginated-export/v1.5','page_count':len(pages),'pages':pages}

def _next_link(link):
    if not link:return None
    for part in link.split(','):
        m=re.search(r'<([^>]+)>\s*;\s*rel="?next"?',part,re.I)
        if m:return m.group(1)
    return None

def openai_org(kind,start_time=None,end_time=None,token=None,max_pages=DEFAULT_MAX_PAGES):
    token=token or os.environ['OPENAI_ADMIN_KEY'];base='https://api.openai.com';headers={'Authorization':'Bearer '+token}
    if kind=='usage':path='/v1/organization/usage/completions';params={'start_time':start_time,'bucket_width':'1h','group_by':['project_id','user_id','api_key_id','model']}
    elif kind=='costs':path='/v1/organization/costs';params={'start_time':start_time}
    elif kind=='projects':path='/v1/organization/projects';params={'limit':100,'include_archived':'true'}
    elif kind=='api_keys':path='/v1/organization/admin_api_keys';params={'limit':100}
    elif kind=='certificates':path='/v1/organization/certificates';params={'limit':100}
    else:raise ValueError(kind)
    if end_time is not None and kind in ('usage','costs'):params['end_time']=end_time
    pages=[];complete=False;last_meta={}
    for _ in range(int(max_pages)):
        obj,last_meta=req('GET',base+path,headers=headers,params=params,allowed_hosts=('api.openai.com',));pages.append(obj)
        if not isinstance(obj,dict) or not obj.get('has_more'):
            complete=True;break
        cursor=obj.get('next_page') or obj.get('last_id')
        if not cursor:break
        if kind in ('usage','costs'):params['page']=cursor
        else:params['after']=cursor
    last_meta.update({'page_count':len(pages),'collection_complete':complete,'kind':kind})
    lim=[]
    if kind in ('usage','costs'):lim.append('Organization usage/cost APIs are aggregate telemetry, not a request-by-request audit trail.')
    lim.append('Provider-side abuse monitoring/support logs are not assumed available to this collector.')
    if not complete:lim.append('Pagination did not reach a terminal page within the configured max_pages bound.')
    return _merge_pages(pages),last_meta,lim

def anthropic_compliance(start_iso=None,end_iso=None,token=None,limit=1000,max_pages=DEFAULT_MAX_PAGES):
    token=token or os.environ.get('ANTHROPIC_COMPLIANCE_ACCESS_KEY') or os.environ['ANTHROPIC_ADMIN_KEY']
    headers={'x-api-key':token,'anthropic-version':'2023-06-01'};params={'limit':min(int(limit),5000)}
    if start_iso:params['created_at.gte']=start_iso
    if end_iso:params['created_at.lt']=end_iso
    pages=[];complete=False;last_meta={}
    for _ in range(int(max_pages)):
        obj,last_meta=req('GET','https://api.anthropic.com/v1/compliance/activities',headers=headers,params=params,allowed_hosts=('api.anthropic.com',));pages.append(obj)
        if not isinstance(obj,dict) or not obj.get('has_more'):
            complete=True;break
        cursor=obj.get('last_id') or obj.get('after_id')
        if not cursor:break
        params['after_id']=cursor
    last_meta.update({'page_count':len(pages),'collection_complete':complete})
    lim=['Compliance content endpoints require additional permissions and are not fetched automatically.']
    if not complete:lim.append('Activity Feed pagination did not reach a terminal page within max_pages.')
    return _merge_pages(pages),last_meta,lim

def anthropic_usage(start_iso,end_iso=None,token=None,max_pages=DEFAULT_MAX_PAGES):
    token=token or os.environ['ANTHROPIC_ADMIN_KEY'];headers={'x-api-key':token,'anthropic-version':'2023-06-01'}
    params={'starting_at':start_iso,'bucket_width':'1h'}
    if end_iso:params['ending_at']=end_iso
    pages=[];complete=False;last_meta={}
    for _ in range(int(max_pages)):
        obj,last_meta=req('GET','https://api.anthropic.com/v1/organizations/usage_report/messages',headers=headers,params=params,allowed_hosts=('api.anthropic.com',));pages.append(obj)
        if not isinstance(obj,dict) or not obj.get('has_more'):
            complete=True;break
        cursor=obj.get('next_page') or obj.get('last_id')
        if not cursor:break
        params['page']=cursor
    last_meta.update({'page_count':len(pages),'collection_complete':complete})
    lim=['Usage reports are aggregate telemetry and do not substitute for Compliance Activity Feed/session evidence.']
    if not complete:lim.append('Usage pagination did not reach a terminal page within max_pages.')
    return _merge_pages(pages),last_meta,lim

def microsoft_graph_security(token=None,filter_expr=None,incidents=False,max_pages=DEFAULT_MAX_PAGES):
    token=token or os.environ['MS_GRAPH_TOKEN'];url='https://graph.microsoft.com'+('/v1.0/security/incidents' if incidents else '/v1.0/security/alerts_v2')
    params={'$top':100}
    if filter_expr:params['$filter']=filter_expr
    pages=[];complete=False;last_meta={}
    for i in range(int(max_pages)):
        obj,last_meta=req('GET',url,headers={'Authorization':'Bearer '+token},params=params if i==0 else None,allowed_hosts=('graph.microsoft.com',));pages.append(obj)
        nxt=obj.get('@odata.nextLink') if isinstance(obj,dict) else None
        if not nxt:complete=True;break
        url=nxt;params=None
    last_meta.update({'page_count':len(pages),'collection_complete':complete,'resource':'incidents' if incidents else 'alerts_v2'})
    lim=['Results remain bounded by tenant/provider retention and Graph permissions.']
    if not complete:lim.append('Graph pagination did not reach a terminal page within max_pages.')
    return _merge_pages(pages),last_meta,lim

def azure_foundry_logs(workspace_id,kql,token=None):
    token=token or os.environ['AZURE_LOG_ANALYTICS_TOKEN'];url=f'https://api.loganalytics.io/v1/workspaces/{workspace_id}/query'
    obj,meta=req('POST',url,headers={'Authorization':'Bearer '+token},json_body={'query':kql},allowed_hosts=('api.loganalytics.io',))
    meta.update({'page_count':1,'collection_complete':True})
    return obj,meta,['Foundry diagnostic/request-response evidence only exists for periods where relevant diagnostic/tracing categories were enabled and retained.','The supplied KQL defines the evidence window; preserve the query text and workspace ID with the artifact.']

def google_cloud_logs(project_id,filter_expr,start_iso=None,end_iso=None,token=None,page_size=1000,max_pages=DEFAULT_MAX_PAGES):
    token=token or os.environ['GOOGLE_OAUTH_ACCESS_TOKEN'];f=filter_expr
    if start_iso:f+=f' AND timestamp >= "{start_iso}"'
    if end_iso:f+=f' AND timestamp < "{end_iso}"'
    body={'resourceNames':[f'projects/{project_id}'],'filter':f,'pageSize':min(int(page_size),1000),'orderBy':'timestamp desc'}
    pages=[];complete=False;last_meta={}
    for _ in range(int(max_pages)):
        obj,last_meta=req('POST','https://logging.googleapis.com/v2/entries:list',headers={'Authorization':'Bearer '+token},json_body=body,allowed_hosts=('logging.googleapis.com',));pages.append(obj)
        nxt=obj.get('nextPageToken') if isinstance(obj,dict) else None
        if not nxt:complete=True;break
        body['pageToken']=nxt
    last_meta.update({'page_count':len(pages),'collection_complete':complete})
    lim=['Cloud Audit Logs/Data Access availability depends on project logging configuration and retention.']
    if not complete:lim.append('Cloud Logging pagination did not reach a terminal page within max_pages.')
    return _merge_pages(pages),last_meta,lim

def github_copilot(enterprise,token=None,phrase='actor:Copilot',after=None,max_pages=DEFAULT_MAX_PAGES):
    token=token or os.environ['GITHUB_AUDIT_TOKEN'];url=f'https://api.github.com/enterprises/{enterprise}/audit-log'
    params={'phrase':phrase,'include':'web','per_page':100}
    if after:params['after']=after
    pages=[];complete=False;last_meta={}
    for i in range(int(max_pages)):
        obj,last_meta=req('GET',url,headers={'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2026-03-10'},params=params if i==0 else None,allowed_hosts=('api.github.com',));pages.append(obj)
        nxt=_next_link(last_meta.get('link'))
        if not nxt:complete=True;break
        url=nxt;params=None
    last_meta.update({'page_count':len(pages),'collection_complete':complete})
    lim=['Enterprise audit log retention is finite; stream to a SIEM for longer history.','Local Copilot client prompts are not present in the ordinary enterprise audit log; client OTel/custom hooks are separate evidence sources.']
    if not complete:lim.append('GitHub audit pagination did not reach a terminal page within max_pages.')
    return _merge_pages(pages),last_meta,lim

def aws_bedrock(region,start_iso=None,end_iso=None,cloudwatch_log_group=None,max_pages=DEFAULT_MAX_PAGES):
    import boto3,datetime
    ct=boto3.client('cloudtrail',region_name=region);events=[];errors=[]
    start=datetime.datetime.fromisoformat(start_iso.replace('Z','+00:00')) if start_iso else None
    end=datetime.datetime.fromisoformat(end_iso.replace('Z','+00:00')) if end_iso else None
    for name in ('InvokeModel','InvokeModelWithResponseStream','Converse','ConverseStream','InvokeAgent','InvokeInlineAgent','Retrieve','RetrieveAndGenerate'):
        token=None
        for _ in range(int(max_pages)):
            try:
                kw={'LookupAttributes':[{'AttributeKey':'EventName','AttributeValue':name}],'MaxResults':50}
                if start:kw['StartTime']=start
                if end:kw['EndTime']=end
                if token:kw['NextToken']=token
                page=ct.lookup_events(**kw);events+=page.get('Events',[]);token=page.get('NextToken')
                if not token:break
            except Exception as e:errors.append({'CollectorError':repr(e),'EventName':name});break
    out={'cloudtrail_events':events,'collector_errors':errors};cw_complete=True;cw_pages=0
    if cloudwatch_log_group:
        logs=boto3.client('logs',region_name=region);token=None;cw=[]
        for _ in range(int(max_pages)):
            kw={'logGroupName':cloudwatch_log_group,'limit':10000}
            if start:kw['startTime']=int(start.timestamp()*1000)
            if end:kw['endTime']=int(end.timestamp()*1000)
            if token:kw['nextToken']=token
            page=logs.filter_log_events(**kw);cw+=page.get('events',[]);cw_pages+=1
            nxt=page.get('nextToken')
            if not nxt or nxt==token:break
            token=nxt
        else:cw_complete=False
        out['invocation_log_events']=cw
    meta={'method':'boto3-readonly','region':region,'page_count':None,'collection_complete':not errors and cw_complete}
    lim=['Bedrock model invocation logging is disabled by default and covers only configured endpoints/modalities.','Some Bedrock operations are CloudTrail data events and require explicit advanced event selectors.']
    if errors:lim.append('One or more CloudTrail event-name queries failed; receipt is partial.')
    return out,meta,lim

COLLECTORS={'openai_org','anthropic_compliance','anthropic_usage','microsoft_graph_security','azure_foundry_logs','google_cloud_logs','github_copilot','aws_bedrock'}
def main():
    ap=argparse.ArgumentParser();ap.add_argument('collector',choices=sorted(COLLECTORS));ap.add_argument('--params-json',default='{}');ap.add_argument('--out',required=True)
    a=ap.parse_args();p=json.loads(a.params_json);fn=globals()[a.collector];obj,meta,limitations=fn(**p);rec=write_artifact(a.out,obj,a.collector,meta,limitations);print(json.dumps(rec,indent=2,sort_keys=True));raise SystemExit(0 if rec['collection_complete'] else 2)
if __name__=='__main__':main()
