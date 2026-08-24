#!/usr/bin/env python3
"""AI-DFIR v1.5 durable metadata store.

SQLite is supported for reference/single-node deployments. PostgreSQL is the
production backend and is loaded lazily through psycopg when installed.
All public case/evidence/task methods require an explicit tenant_id.
"""
from __future__ import annotations
import contextlib, json, sqlite3, time, uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

SCHEMA_VERSION=15

def utc(): return datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
def _jd(o): return json.dumps(o,sort_keys=True,separators=(',',':')) if o is not None else None
def _jl(s): return json.loads(s) if s else None

DDL_SQLITE='''
CREATE TABLE IF NOT EXISTS schema_meta(version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS tenants(tenant_id TEXT PRIMARY KEY, name TEXT, created_utc TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS cases(
  tenant_id TEXT NOT NULL, case_id TEXT NOT NULL, title TEXT, severity TEXT, status TEXT NOT NULL,
  created_utc TEXT NOT NULL, updated_utc TEXT NOT NULL, metadata_json TEXT,
  PRIMARY KEY(tenant_id,case_id));
CREATE TABLE IF NOT EXISTS evidence_meta(
  tenant_id TEXT NOT NULL, evidence_id TEXT NOT NULL, case_id TEXT NOT NULL, sha256 TEXT NOT NULL,
  size_bytes INTEGER NOT NULL, media_type TEXT, classification TEXT, object_uri TEXT NOT NULL,
  acquisition_receipt_sha256 TEXT, created_utc TEXT NOT NULL, metadata_json TEXT,
  PRIMARY KEY(tenant_id,evidence_id));
CREATE INDEX IF NOT EXISTS evidence_case_idx ON evidence_meta(tenant_id,case_id);
CREATE INDEX IF NOT EXISTS evidence_sha_idx ON evidence_meta(tenant_id,sha256);
CREATE TABLE IF NOT EXISTS acquisition_tasks(
  tenant_id TEXT NOT NULL, task_id TEXT NOT NULL, case_id TEXT NOT NULL, collector_type TEXT NOT NULL,
  state TEXT NOT NULL, lease_owner TEXT, lease_until_utc TEXT, attempt INTEGER NOT NULL DEFAULT 0,
  request_json TEXT NOT NULL, receipt_json TEXT, created_utc TEXT NOT NULL, updated_utc TEXT NOT NULL,
  PRIMARY KEY(tenant_id,task_id));
CREATE INDEX IF NOT EXISTS task_state_idx ON acquisition_tasks(tenant_id,state);
CREATE TABLE IF NOT EXISTS collector_nodes(
  tenant_id TEXT NOT NULL, collector_id TEXT NOT NULL, public_key_fingerprint TEXT, capabilities_json TEXT,
  enabled INTEGER NOT NULL DEFAULT 1, last_seen_utc TEXT, metadata_json TEXT,
  PRIMARY KEY(tenant_id,collector_id));
CREATE TABLE IF NOT EXISTS legal_holds(
  tenant_id TEXT NOT NULL, hold_id TEXT NOT NULL, case_id TEXT NOT NULL, status TEXT NOT NULL,
  reason TEXT NOT NULL, created_by TEXT NOT NULL, created_utc TEXT NOT NULL, released_by TEXT,
  released_utc TEXT, metadata_json TEXT, PRIMARY KEY(tenant_id,hold_id));
CREATE TABLE IF NOT EXISTS audit_events(
  seq INTEGER PRIMARY KEY AUTOINCREMENT, tenant_id TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
  object_type TEXT, object_id TEXT, created_utc TEXT NOT NULL, details_json TEXT);
'''

class MetadataStore:
    def __init__(self,dsn:str):
        self.dsn=dsn
        self.kind='postgres' if dsn.startswith(('postgresql://','postgres://')) else 'sqlite'
        if self.kind=='sqlite':
            raw=dsn[len('sqlite:///'):] if dsn.startswith('sqlite:///') else dsn
            self.path=Path(raw).resolve(); self.path.parent.mkdir(parents=True,exist_ok=True)
        self.migrate()
    def _connect(self):
        if self.kind=='sqlite':
            c=sqlite3.connect(self.path);c.row_factory=sqlite3.Row;c.execute('PRAGMA foreign_keys=ON');return c
        try: import psycopg
        except Exception as e: raise RuntimeError('PostgreSQL backend requires psycopg>=3') from e
        return psycopg.connect(self.dsn)
    @contextlib.contextmanager
    def tx(self,tenant_id=None):
        c=self._connect()
        try:
            if self.kind=='postgres' and tenant_id:
                with c.cursor() as cur:
                    cur.execute("SELECT set_config('app.tenant_id', %s, true)",(tenant_id,))
            yield c;c.commit()
        except Exception:
            c.rollback();raise
        finally:c.close()
    def migrate(self):
        if self.kind=='sqlite':
            with self.tx() as c:
                c.executescript(DDL_SQLITE)
                row=c.execute('SELECT version FROM schema_meta LIMIT 1').fetchone()
                if row is None:c.execute('INSERT INTO schema_meta(version) VALUES(?)',(SCHEMA_VERSION,))
                elif int(row[0])!=SCHEMA_VERSION:raise RuntimeError(f'unsupported metadata schema {row[0]} expected {SCHEMA_VERSION}')
        else:
            sql=(Path(__file__).with_name('postgres_schema_v15.sql')).read_text()
            with self.tx() as c:
                with c.cursor() as cur:cur.execute(sql)
    def ensure_tenant(self,tenant_id,name=None):
        if not tenant_id:raise ValueError('tenant_id required')
        with self.tx(tenant_id) as c:
            if self.kind=='sqlite':c.execute('INSERT OR IGNORE INTO tenants VALUES(?,?,?)',(tenant_id,name,utc()))
            else:
                with c.cursor() as cur:cur.execute('INSERT INTO tenants(tenant_id,name,created_utc) VALUES(%s,%s,%s) ON CONFLICT(tenant_id) DO NOTHING',(tenant_id,name,utc()))
    def create_case(self,tenant_id,case_id,title=None,severity='medium',metadata=None):
        self.ensure_tenant(tenant_id);now=utc()
        with self.tx(tenant_id) as c:
            if self.kind=='sqlite':
                c.execute('INSERT INTO cases VALUES(?,?,?,?,?,?,?,?)',(tenant_id,case_id,title,severity,'OPEN',now,now,_jd(metadata)))
            else:
                with c.cursor() as cur:cur.execute('INSERT INTO cases(tenant_id,case_id,title,severity,status,created_utc,updated_utc,metadata_json) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)',(tenant_id,case_id,title,severity,'OPEN',now,now,_jd(metadata)))
        return self.get_case(tenant_id,case_id)
    def get_case(self,tenant_id,case_id):
        with self.tx(tenant_id) as c:
            if self.kind=='sqlite':r=c.execute('SELECT * FROM cases WHERE tenant_id=? AND case_id=?',(tenant_id,case_id)).fetchone()
            else:
                with c.cursor() as cur:cur.execute('SELECT tenant_id,case_id,title,severity,status,created_utc,updated_utc,metadata_json FROM cases WHERE tenant_id=%s AND case_id=%s',(tenant_id,case_id));r=cur.fetchone()
        if not r:return None
        keys=['tenant_id','case_id','title','severity','status','created_utc','updated_utc','metadata_json']
        d=dict(r) if hasattr(r,'keys') else dict(zip(keys,r));d['metadata']=_jl(d.pop('metadata_json',None));return d
    def put_evidence(self,tenant_id,case_id,sha256,size_bytes,object_uri,media_type=None,classification='internal',receipt_sha256=None,metadata=None,evidence_id=None):
        if not self.get_case(tenant_id,case_id):raise KeyError('case not found in tenant')
        evidence_id=evidence_id or 'EVID-'+uuid.uuid4().hex;now=utc()
        vals=(tenant_id,evidence_id,case_id,sha256,int(size_bytes),media_type,classification,object_uri,receipt_sha256,now,_jd(metadata))
        with self.tx(tenant_id) as c:
            if self.kind=='sqlite':c.execute('INSERT INTO evidence_meta VALUES(?,?,?,?,?,?,?,?,?,?,?)',vals)
            else:
                with c.cursor() as cur:cur.execute('INSERT INTO evidence_meta(tenant_id,evidence_id,case_id,sha256,size_bytes,media_type,classification,object_uri,acquisition_receipt_sha256,created_utc,metadata_json) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',vals)
        return evidence_id
    def list_evidence(self,tenant_id,case_id):
        with self.tx(tenant_id) as c:
            if self.kind=='sqlite':rows=c.execute('SELECT * FROM evidence_meta WHERE tenant_id=? AND case_id=? ORDER BY created_utc',(tenant_id,case_id)).fetchall()
            else:
                with c.cursor() as cur:cur.execute('SELECT tenant_id,evidence_id,case_id,sha256,size_bytes,media_type,classification,object_uri,acquisition_receipt_sha256,created_utc,metadata_json FROM evidence_meta WHERE tenant_id=%s AND case_id=%s ORDER BY created_utc',(tenant_id,case_id));rows=cur.fetchall()
        out=[]
        for r in rows:
            d=dict(r) if hasattr(r,'keys') else dict(zip(['tenant_id','evidence_id','case_id','sha256','size_bytes','media_type','classification','object_uri','acquisition_receipt_sha256','created_utc','metadata_json'],r));d['metadata']=_jl(d.pop('metadata_json',None));out.append(d)
        return out
    def register_collector(self,tenant_id,collector_id,fingerprint,capabilities,metadata=None):
        self.ensure_tenant(tenant_id);now=utc();vals=(tenant_id,collector_id,fingerprint,_jd(capabilities),1,now,_jd(metadata))
        with self.tx(tenant_id) as c:
            if self.kind=='sqlite':c.execute('INSERT OR REPLACE INTO collector_nodes VALUES(?,?,?,?,?,?,?)',vals)
            else:
                with c.cursor() as cur:cur.execute('''INSERT INTO collector_nodes(tenant_id,collector_id,public_key_fingerprint,capabilities_json,enabled,last_seen_utc,metadata_json) VALUES(%s,%s,%s,%s,%s,%s,%s) ON CONFLICT(tenant_id,collector_id) DO UPDATE SET public_key_fingerprint=EXCLUDED.public_key_fingerprint,capabilities_json=EXCLUDED.capabilities_json,enabled=EXCLUDED.enabled,last_seen_utc=EXCLUDED.last_seen_utc,metadata_json=EXCLUDED.metadata_json''',vals)
    def get_collector(self,tenant_id,collector_id):
        with self.tx(tenant_id) as c:
            if self.kind=='sqlite':r=c.execute('SELECT tenant_id,collector_id,public_key_fingerprint,capabilities_json,enabled,last_seen_utc,metadata_json FROM collector_nodes WHERE tenant_id=? AND collector_id=?',(tenant_id,collector_id)).fetchone()
            else:
                with c.cursor() as cur:cur.execute('SELECT tenant_id,collector_id,public_key_fingerprint,capabilities_json,enabled,last_seen_utc,metadata_json FROM collector_nodes WHERE tenant_id=%s AND collector_id=%s',(tenant_id,collector_id));r=cur.fetchone()
        if not r:return None
        keys=['tenant_id','collector_id','public_key_fingerprint','capabilities_json','enabled','last_seen_utc','metadata_json'];d=dict(r) if hasattr(r,'keys') else dict(zip(keys,r));d['capabilities']=_jl(d.pop('capabilities_json',None)) or [];d['metadata']=_jl(d.pop('metadata_json',None)) or {};d['enabled']=bool(d['enabled']);return d
    def put_legal_hold(self,tenant_id,case_id,hold_id,reason,created_by,metadata=None):
        if not self.get_case(tenant_id,case_id):raise KeyError('case not found')
        vals=(tenant_id,hold_id,case_id,'ACTIVE',reason,created_by,utc(),None,None,_jd(metadata))
        with self.tx(tenant_id) as c:
            if self.kind=='sqlite':c.execute('INSERT INTO legal_holds VALUES(?,?,?,?,?,?,?,?,?,?)',vals)
            else:
                with c.cursor() as cur:cur.execute('INSERT INTO legal_holds(tenant_id,hold_id,case_id,status,reason,created_by,created_utc,released_by,released_utc,metadata_json) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',vals)
    def release_legal_hold(self,tenant_id,hold_id,released_by):
        with self.tx(tenant_id) as c:
            if self.kind=='sqlite':c.execute("UPDATE legal_holds SET status='RELEASED',released_by=?,released_utc=? WHERE tenant_id=? AND hold_id=? AND status='ACTIVE'",(released_by,utc(),tenant_id,hold_id));n=c.total_changes
            else:
                with c.cursor() as cur:cur.execute("UPDATE legal_holds SET status='RELEASED',released_by=%s,released_utc=%s WHERE tenant_id=%s AND hold_id=%s AND status='ACTIVE'",(released_by,utc(),tenant_id,hold_id));n=cur.rowcount
        if not n:raise KeyError('active hold not found')
    def active_holds(self,tenant_id,case_id):
        with self.tx(tenant_id) as c:
            if self.kind=='sqlite':rows=c.execute("SELECT hold_id,reason,created_by,created_utc FROM legal_holds WHERE tenant_id=? AND case_id=? AND status='ACTIVE'",(tenant_id,case_id)).fetchall()
            else:
                with c.cursor() as cur:cur.execute("SELECT hold_id,reason,created_by,created_utc FROM legal_holds WHERE tenant_id=%s AND case_id=%s AND status='ACTIVE'",(tenant_id,case_id));rows=cur.fetchall()
        return [dict(r) if hasattr(r,'keys') else dict(zip(['hold_id','reason','created_by','created_utc'],r)) for r in rows]
    def put_task(self,tenant_id,case_id,collector_type,request,task_id=None):
        if not self.get_case(tenant_id,case_id):raise KeyError('case not found')
        task_id=task_id or 'TASK-'+uuid.uuid4().hex;now=utc();vals=(tenant_id,task_id,case_id,collector_type,'QUEUED',None,None,0,_jd(request),None,now,now)
        with self.tx(tenant_id) as c:
            if self.kind=='sqlite':c.execute('INSERT INTO acquisition_tasks VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',vals)
            else:
                with c.cursor() as cur:cur.execute('INSERT INTO acquisition_tasks(tenant_id,task_id,case_id,collector_type,state,lease_owner,lease_until_utc,attempt,request_json,receipt_json,created_utc,updated_utc) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',vals)
        return task_id
    def claim_task(self,tenant_id,collector_id,capabilities,lease_seconds=300):
        reg=self.get_collector(tenant_id,collector_id)
        if not reg or not reg.get('enabled'):raise PermissionError('collector is not enrolled/enabled for tenant')
        registered=set(reg.get('capabilities') or []);requested=set(capabilities or [])
        capabilities=sorted(registered & requested) if requested else sorted(registered)
        if not capabilities:return None
        now=datetime.now(timezone.utc);until=(now+timedelta(seconds=lease_seconds)).isoformat().replace('+00:00','Z')
        with self.tx(tenant_id) as c:
            if self.kind=='sqlite':
                rows=c.execute("SELECT task_id,collector_type,request_json,attempt FROM acquisition_tasks WHERE tenant_id=? AND (state='QUEUED' OR (state='LEASED' AND lease_until_utc<?)) ORDER BY created_utc",(tenant_id,now.isoformat().replace('+00:00','Z'))).fetchall()
                pick=next((r for r in rows if r['collector_type'] in capabilities),None)
                if not pick:return None
                c.execute("UPDATE acquisition_tasks SET state='LEASED',lease_owner=?,lease_until_utc=?,attempt=attempt+1,updated_utc=? WHERE tenant_id=? AND task_id=?",(collector_id,until,utc(),tenant_id,pick['task_id']))
                return {'task_id':pick['task_id'],'collector_type':pick['collector_type'],'request':_jl(pick['request_json']),'lease_until_utc':until,'attempt':int(pick['attempt'])+1}
            # PostgreSQL uses SKIP LOCKED for concurrent workers.
            with c.cursor() as cur:
                cur.execute("SELECT task_id,collector_type,request_json,attempt FROM acquisition_tasks WHERE tenant_id=%s AND (state='QUEUED' OR (state='LEASED' AND lease_until_utc<%s)) ORDER BY created_utc FOR UPDATE SKIP LOCKED",(tenant_id,now.isoformat().replace('+00:00','Z')))
                rows=cur.fetchall();pick=next((r for r in rows if r[1] in capabilities),None)
                if not pick:return None
                cur.execute("UPDATE acquisition_tasks SET state='LEASED',lease_owner=%s,lease_until_utc=%s,attempt=attempt+1,updated_utc=%s WHERE tenant_id=%s AND task_id=%s",(collector_id,until,utc(),tenant_id,pick[0]))
                return {'task_id':pick[0],'collector_type':pick[1],'request':_jl(pick[2]),'lease_until_utc':until,'attempt':int(pick[3])+1}
    def complete_task(self,tenant_id,task_id,collector_id,receipt,state='COMPLETE'):
        if state not in ('COMPLETE','PARTIAL','FAILED'):raise ValueError(state)
        with self.tx(tenant_id) as c:
            if self.kind=='sqlite':
                r=c.execute('SELECT lease_owner FROM acquisition_tasks WHERE tenant_id=? AND task_id=?',(tenant_id,task_id)).fetchone()
                if not r or r[0]!=collector_id:raise PermissionError('collector does not own lease')
                c.execute('UPDATE acquisition_tasks SET state=?,receipt_json=?,lease_owner=NULL,lease_until_utc=NULL,updated_utc=? WHERE tenant_id=? AND task_id=?',(state,_jd(receipt),utc(),tenant_id,task_id))
            else:
                with c.cursor() as cur:
                    cur.execute('SELECT lease_owner FROM acquisition_tasks WHERE tenant_id=%s AND task_id=%s FOR UPDATE',(tenant_id,task_id));r=cur.fetchone()
                    if not r or r[0]!=collector_id:raise PermissionError('collector does not own lease')
                    cur.execute('UPDATE acquisition_tasks SET state=%s,receipt_json=%s,lease_owner=NULL,lease_until_utc=NULL,updated_utc=%s WHERE tenant_id=%s AND task_id=%s',(state,_jd(receipt),utc(),tenant_id,task_id))
    def audit(self,tenant_id,actor,action,object_type=None,object_id=None,details=None):
        with self.tx(tenant_id) as c:
            vals=(tenant_id,actor,action,object_type,object_id,utc(),_jd(details))
            if self.kind=='sqlite':c.execute('INSERT INTO audit_events(tenant_id,actor,action,object_type,object_id,created_utc,details_json) VALUES(?,?,?,?,?,?,?)',vals)
            else:
                with c.cursor() as cur:cur.execute('INSERT INTO audit_events(tenant_id,actor,action,object_type,object_id,created_utc,details_json) VALUES(%s,%s,%s,%s,%s,%s,%s)',vals)

if __name__=='__main__':
    import argparse
    ap=argparse.ArgumentParser();ap.add_argument('--dsn',required=True);ap.add_argument('--selftest',action='store_true');a=ap.parse_args()
    s=MetadataStore(a.dsn)
    if a.selftest:
        s.ensure_tenant('T1','Tenant One');s.create_case('T1','C1','Test')
        print(json.dumps({'schema':'ai-dfir/metadata-store/v1.5','status':'PASS','backend':s.kind},indent=2))
