#!/usr/bin/env python3
"""
AI-DFIR v1.1 content-addressed enterprise evidence repository.

v1.1 changes:
- streamed chunked AES-256-GCM format (AIDFIR2) for large artifacts
- backward-compatible reading of v1.0 AIDFIR1 objects
- strongest-classification tracking for deduplicated content
- no whole-file plaintext/ciphertext buffering for new encrypted objects
"""
from __future__ import annotations
import argparse, hashlib, json, os, shutil, sqlite3, struct, tempfile, uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VALID_CLASSIFICATIONS={"public","internal","confidential","restricted","secret"}
CLASS_RANK={"public":0,"internal":1,"confidential":2,"restricted":3,"secret":4}
MAGIC_V1=b"AIDFIR1"
MAGIC_V2=b"AIDFIR2"
DEFAULT_CHUNK=4*1024*1024

def utc():return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
def sha256_file(path,chunk=8*1024*1024):
    h=hashlib.sha256()
    with open(path,"rb") as f:
        for b in iter(lambda:f.read(chunk),b""):h.update(b)
    return h.hexdigest()
def canon(o):return json.dumps(o,sort_keys=True,separators=(",",":"),default=str).encode()

class Repository:
    def __init__(self,root,master_key=None):
        self.root=Path(root).resolve();self.root.mkdir(parents=True,exist_ok=True)
        self.objects=self.root/"objects"/"sha256";self.objects.mkdir(parents=True,exist_ok=True)
        self.db_path=self.root/"repository.db"
        self.audit_path=self.root/"repository_audit.jsonl"
        self.master_key=master_key
        if master_key is not None and len(master_key)!=32:
            raise ValueError("master key must be 32 bytes for AES-256-GCM")
        self._init()

    def conn(self):
        c=sqlite3.connect(self.db_path);c.row_factory=sqlite3.Row;return c

    def _init(self):
        with self.conn() as c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS objects(
              sha256 TEXT PRIMARY KEY,size INTEGER NOT NULL,stored_path TEXT NOT NULL,
              encrypted INTEGER NOT NULL,created_utc TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS evidence(
              evidence_id TEXT PRIMARY KEY,case_id TEXT NOT NULL,sha256 TEXT NOT NULL,
              logical_name TEXT NOT NULL,source TEXT,classification TEXT NOT NULL,
              acquired_utc TEXT NOT NULL,retention_until TEXT,metadata_json TEXT NOT NULL,
              FOREIGN KEY(sha256) REFERENCES objects(sha256)
            );
            CREATE INDEX IF NOT EXISTS idx_evidence_case ON evidence(case_id);
            CREATE TABLE IF NOT EXISTS legal_holds(
              hold_id TEXT PRIMARY KEY,case_id TEXT NOT NULL,evidence_id TEXT,
              reason TEXT NOT NULL,created_utc TEXT NOT NULL,created_by TEXT NOT NULL,
              released_utc TEXT,released_by TEXT
            );
            CREATE TABLE IF NOT EXISTS repo_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            """)
            cols={r["name"] for r in c.execute("PRAGMA table_info(objects)")}
            if "storage_classification" not in cols:
                c.execute("ALTER TABLE objects ADD COLUMN storage_classification TEXT NOT NULL DEFAULT 'internal'")
            if "encryption_format" not in cols:
                c.execute("ALTER TABLE objects ADD COLUMN encryption_format TEXT NOT NULL DEFAULT 'legacy_or_plain'")

    def _audit(self,actor,action,**details):
        prev="0"*64
        if self.audit_path.exists():
            for line in self.audit_path.read_text(encoding="utf-8").splitlines():
                if line.strip():prev=json.loads(line)["event_hash"]
        core={"schema":"ai-dfir/repository-audit/v1.1","timestamp_utc":utc(),
              "actor":actor,"action":action,"details":details,"prev_event_hash":prev}
        eh=hashlib.sha256(canon(core)).hexdigest();obj={**core,"event_hash":eh}
        with self.audit_path.open("a",encoding="utf-8") as f:
            f.write(json.dumps(obj,sort_keys=True)+"\n");f.flush();os.fsync(f.fileno())
        return obj

    def _object_path(self,digest):
        d=self.objects/digest[:2];d.mkdir(parents=True,exist_ok=True)
        return d/digest

    def _encrypt_v2(self,src,tmp,digest,chunk_size=DEFAULT_CHUNK):
        aes=AESGCM(self.master_key);prefix=os.urandom(8);counter=0
        with open(src,"rb") as fin,open(tmp,"wb") as fout:
            fout.write(MAGIC_V2);fout.write(prefix);fout.write(struct.pack(">I",chunk_size))
            while True:
                plain=fin.read(chunk_size)
                if not plain:break
                if counter>=2**32:raise OverflowError("encrypted object exceeds nonce counter space")
                nonce=prefix+counter.to_bytes(4,"big")
                aad=f"{digest}:{counter}".encode()
                ct=aes.encrypt(nonce,plain,aad)
                fout.write(struct.pack(">I",len(ct)));fout.write(ct)
                counter+=1
            fout.flush();os.fsync(fout.fileno())

    def _decrypt_v2_to(self,src,out,digest):
        aes=AESGCM(self.master_key);h=hashlib.sha256()
        with open(src,"rb") as fin,open(out,"wb") as fout:
            if fin.read(7)!=MAGIC_V2:raise ValueError("AIDFIR2 header invalid")
            prefix=fin.read(8);chunk_size=struct.unpack(">I",fin.read(4))[0]
            counter=0
            while True:
                n=fin.read(4)
                if not n:break
                if len(n)!=4:raise ValueError("truncated encrypted chunk length")
                length=struct.unpack(">I",n)[0];ct=fin.read(length)
                if len(ct)!=length:raise ValueError("truncated encrypted chunk")
                nonce=prefix+counter.to_bytes(4,"big");aad=f"{digest}:{counter}".encode()
                plain=aes.decrypt(nonce,ct,aad)
                if len(plain)>chunk_size:raise ValueError("invalid encrypted chunk size")
                h.update(plain);fout.write(plain);counter+=1
            fout.flush();os.fsync(fout.fileno())
        if h.hexdigest()!=digest:raise ValueError("object plaintext digest mismatch")
        return h.hexdigest()

    def _verify_encrypted(self,path,digest):
        with open(path,"rb") as f:magic=f.read(7)
        if magic==MAGIC_V2:
            if not self.master_key:return None
            fd,tmp=tempfile.mkstemp(prefix="verify.",dir=self.root);os.close(fd)
            try:self._decrypt_v2_to(path,tmp,digest);return True
            finally:
                if os.path.exists(tmp):os.unlink(tmp)
        if magic==MAGIC_V1:
            if not self.master_key:return None
            raw=Path(path).read_bytes();nonce=raw[7:19];plain=AESGCM(self.master_key).decrypt(nonce,raw[19:],digest.encode())
            return hashlib.sha256(plain).hexdigest()==digest
        raise ValueError("unknown encrypted object format")

    def _upgrade_object_classification(self,digest,classification):
        with self.conn() as c:
            r=c.execute("SELECT storage_classification FROM objects WHERE sha256=?",(digest,)).fetchone()
            if r and CLASS_RANK[classification] > CLASS_RANK.get(r["storage_classification"],0):
                c.execute("UPDATE objects SET storage_classification=? WHERE sha256=?",(classification,digest))

    def add_file(self,case_id,path,logical_name,actor,source=None,classification="confidential",
                 retention_days=None,metadata=None,encrypt=None):
        if classification not in VALID_CLASSIFICATIONS:raise ValueError(classification)
        src=Path(path);digest=sha256_file(src);size=src.stat().st_size
        with self.conn() as c:row=c.execute("SELECT * FROM objects WHERE sha256=?",(digest,)).fetchone()
        if row is None:
            use_encrypt=bool(self.master_key) if encrypt is None else bool(encrypt)
            if use_encrypt and not self.master_key:raise ValueError("encryption requested but repository master key not supplied")
            target=self._object_path(digest);fd,tmp=tempfile.mkstemp(prefix=digest+".",dir=target.parent);os.close(fd)
            try:
                if use_encrypt:self._encrypt_v2(src,tmp,digest);fmt="AIDFIR2"
                else:
                    with open(src,"rb") as fin,open(tmp,"wb") as fout:
                        shutil.copyfileobj(fin,fout,length=8*1024*1024);fout.flush();os.fsync(fout.fileno())
                    fmt="plain"
                os.chmod(tmp,0o440);os.replace(tmp,target)
            finally:
                if os.path.exists(tmp):os.unlink(tmp)
            with self.conn() as c:
                c.execute("""INSERT INTO objects
                    (sha256,size,stored_path,encrypted,created_utc,storage_classification,encryption_format)
                    VALUES(?,?,?,?,?,?,?)""",
                    (digest,size,str(target.relative_to(self.root)),1 if use_encrypt else 0,utc(),classification,fmt))
        else:self._upgrade_object_classification(digest,classification)

        evid=f"EVID-{uuid.uuid4().hex}";retention=None
        if retention_days is not None:
            retention=(datetime.now(timezone.utc)+timedelta(days=int(retention_days))).isoformat().replace("+00:00","Z")
        with self.conn() as c:
            c.execute("INSERT INTO evidence VALUES(?,?,?,?,?,?,?,?,?)",
                      (evid,case_id,digest,logical_name,source,classification,utc(),retention,
                       json.dumps(metadata or {},sort_keys=True)))
        self._audit(actor,"evidence_ingested",case_id=case_id,evidence_id=evid,sha256=digest,
                    logical_name=logical_name,classification=classification,size=size)
        return self.get_metadata(evid)

    def get_metadata(self,evidence_id):
        with self.conn() as c:
            r=c.execute("""SELECT e.*,o.size,o.encrypted,o.stored_path,o.storage_classification,o.encryption_format
                           FROM evidence e JOIN objects o ON e.sha256=o.sha256 WHERE evidence_id=?""",(evidence_id,)).fetchone()
            if not r:return None
            d=dict(r);d["metadata"]=json.loads(d.pop("metadata_json"));d["encrypted"]=bool(d["encrypted"]);return d

    def list_case(self,case_id):
        with self.conn() as c:
            rows=c.execute("""SELECT e.*,o.size,o.encrypted,o.storage_classification,o.encryption_format
                              FROM evidence e JOIN objects o ON e.sha256=o.sha256
                              WHERE e.case_id=? ORDER BY e.acquired_utc""",(case_id,))
            out=[]
            for r in rows:
                d=dict(r);d["metadata"]=json.loads(d.pop("metadata_json"));d["encrypted"]=bool(d["encrypted"]);out.append(d)
            return out

    def extract(self,evidence_id,out_path,actor):
        m=self.get_metadata(evidence_id)
        if not m:raise KeyError(evidence_id)
        src=self.root/m["stored_path"];out=Path(out_path);out.parent.mkdir(parents=True,exist_ok=True)
        fd,tmp=tempfile.mkstemp(prefix=out.name+".",dir=out.parent);os.close(fd)
        try:
            if m["encrypted"]:
                if not self.master_key:raise PermissionError("encrypted object requires repository master key")
                with open(src,"rb") as f:magic=f.read(7)
                if magic==MAGIC_V2:self._decrypt_v2_to(src,tmp,m["sha256"])
                elif magic==MAGIC_V1:
                    raw=src.read_bytes();nonce=raw[7:19];plain=AESGCM(self.master_key).decrypt(nonce,raw[19:],m["sha256"].encode())
                    Path(tmp).write_bytes(plain)
                    if hashlib.sha256(plain).hexdigest()!=m["sha256"]:raise ValueError("object plaintext digest mismatch")
                else:raise ValueError("encrypted object format unknown")
            else:
                with open(src,"rb") as fin,open(tmp,"wb") as fout:
                    h=hashlib.sha256()
                    while True:
                        b=fin.read(8*1024*1024)
                        if not b:break
                        h.update(b);fout.write(b)
                    fout.flush();os.fsync(fout.fileno())
                if h.hexdigest()!=m["sha256"]:raise ValueError("object digest mismatch")
            os.replace(tmp,out)
        finally:
            if os.path.exists(tmp):os.unlink(tmp)
        self._audit(actor,"evidence_extracted",case_id=m["case_id"],evidence_id=evidence_id,
                    sha256=m["sha256"],destination=str(out))
        return out

    def create_hold(self,case_id,reason,actor,evidence_id=None):
        hid=f"HOLD-{uuid.uuid4().hex}"
        with self.conn() as c:c.execute("INSERT INTO legal_holds VALUES(?,?,?,?,?,?,?,?)",(hid,case_id,evidence_id,reason,utc(),actor,None,None))
        self._audit(actor,"legal_hold_created",hold_id=hid,case_id=case_id,evidence_id=evidence_id,reason=reason);return hid

    def release_hold(self,hold_id,actor):
        with self.conn() as c:
            r=c.execute("SELECT * FROM legal_holds WHERE hold_id=?",(hold_id,)).fetchone()
            if not r:raise KeyError(hold_id)
            if r["released_utc"]:return
            c.execute("UPDATE legal_holds SET released_utc=?,released_by=? WHERE hold_id=?",(utc(),actor,hold_id))
        self._audit(actor,"legal_hold_released",hold_id=hold_id)

    def active_holds(self,case_id=None):
        with self.conn() as c:
            q="SELECT * FROM legal_holds WHERE released_utc IS NULL";args=[]
            if case_id:q+=" AND case_id=?";args=[case_id]
            return [dict(x) for x in c.execute(q,args)]

    def disposition_plan(self,now=None):
        now=now or datetime.now(timezone.utc)
        with self.conn() as c:
            rows=[dict(x) for x in c.execute("SELECT * FROM evidence WHERE retention_until IS NOT NULL")]
            holds=[dict(x) for x in c.execute("SELECT * FROM legal_holds WHERE released_utc IS NULL")]
        case_holds={h["case_id"] for h in holds if h["evidence_id"] is None};evid_holds={h["evidence_id"] for h in holds if h["evidence_id"] is not None}
        eligible=[];blocked=[]
        for e in rows:
            expiry=datetime.fromisoformat(e["retention_until"].replace("Z","+00:00"))
            if expiry>now:continue
            reason="case legal hold" if e["case_id"] in case_holds else ("evidence legal hold" if e["evidence_id"] in evid_holds else None)
            item={"evidence_id":e["evidence_id"],"case_id":e["case_id"],"sha256":e["sha256"],"retention_until":e["retention_until"]}
            (blocked if reason else eligible).append({**item,**({"blocked_by":reason} if reason else {})})
        return {"schema":"ai-dfir/disposition-plan/v1.1","generated_utc":utc(),
                "eligible_for_review":eligible,"blocked_by_hold":blocked,
                "note":"v1.1 never auto-deletes evidence; disposition requires an external approved process."}

    def verify(self):
        findings=[];objects=0
        with self.conn() as c:rows=[dict(x) for x in c.execute("SELECT * FROM objects")]
        for o in rows:
            p=self.root/o["stored_path"];objects+=1
            if not p.exists():findings.append({"type":"missing_object","sha256":o["sha256"]});continue
            if not o["encrypted"]:
                got=sha256_file(p)
                if got!=o["sha256"]:findings.append({"type":"digest_mismatch","sha256":o["sha256"],"actual":got})
            elif self.master_key:
                try:
                    ok=self._verify_encrypted(p,o["sha256"])
                    if ok is False:findings.append({"type":"encrypted_plaintext_digest_mismatch","sha256":o["sha256"]})
                except Exception as ex:findings.append({"type":"encrypted_object_decrypt_failure","sha256":o["sha256"],"error":repr(ex)})
        prev="0"*64;audit_count=0
        if self.audit_path.exists():
            for i,line in enumerate(self.audit_path.read_text().splitlines(),1):
                if not line.strip():continue
                obj=json.loads(line);got=obj.pop("event_hash")
                if obj.get("prev_event_hash")!=prev:findings.append({"type":"audit_chain_prev_mismatch","line":i});break
                expected=hashlib.sha256(canon(obj)).hexdigest()
                if got!=expected:findings.append({"type":"audit_chain_hash_mismatch","line":i});break
                prev=got;audit_count+=1
        return {"valid":not findings,"objects":objects,"audit_events":audit_count,"findings":findings}

def main():
    ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest="cmd",required=True)
    p=sp.add_parser("init");p.add_argument("--root",required=True);p.add_argument("--key-hex")
    p=sp.add_parser("verify");p.add_argument("--root",required=True);p.add_argument("--key-hex")
    p=sp.add_parser("disposition-plan");p.add_argument("--root",required=True);p.add_argument("--key-hex")
    a=ap.parse_args();key=bytes.fromhex(a.key_hex) if getattr(a,"key_hex",None) else None;r=Repository(a.root,key)
    if a.cmd=="init":print(json.dumps({"root":str(r.root),"status":"initialized","version":"1.1"},indent=2))
    elif a.cmd=="verify":print(json.dumps(r.verify(),indent=2,sort_keys=True))
    else:print(json.dumps(r.disposition_plan(),indent=2,sort_keys=True))
if __name__=="__main__":main()
