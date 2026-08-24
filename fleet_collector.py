#!/usr/bin/env python3
"""AI-DFIR v0.5 central fleet attestation collector (stdlib HTTP + SQLite)."""
from __future__ import annotations
import argparse, base64, hashlib, json, sqlite3, threading, time, ssl
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
from cryptography.hazmat.primitives import serialization
from fleet_crypto import canonical, key_id, sign_payload
from fleet_policy import evaluate, aggregate_state


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")


def parse_utc(s):
    return datetime.fromisoformat(s.replace("Z","+00:00")).timestamp()


def load_registry(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def verify_pem_envelope(public_pem: str, envelope: dict):
    pub=serialization.load_pem_public_key(public_pem.encode())
    if envelope.get("algorithm")!="Ed25519": raise ValueError("unsupported algorithm")
    if envelope.get("key_id")!=key_id(pub): raise ValueError("key_id mismatch")
    body=canonical(envelope["payload"])
    if hashlib.sha256(body).hexdigest()!=envelope.get("payload_sha256"):
        raise ValueError("payload digest mismatch")
    sig=base64.b64decode(envelope["signature"])
    pub.verify(sig,body)
    return envelope["payload"]


class Store:
    def __init__(self,path):
        self.path=str(path)
        self.lock=threading.Lock()
        self._init()

    def conn(self):
        c=sqlite3.connect(self.path,timeout=20)
        c.row_factory=sqlite3.Row
        return c

    def _init(self):
        with self.conn() as c:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS heartbeats(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              node_id TEXT NOT NULL,
              seq INTEGER NOT NULL,
              received_utc TEXT NOT NULL,
              payload_timestamp_utc TEXT NOT NULL,
              payload_sha256 TEXT NOT NULL,
              prev_heartbeat_hash TEXT,
              state TEXT NOT NULL,
              findings_json TEXT NOT NULL,
              payload_json TEXT NOT NULL,
              envelope_json TEXT NOT NULL,
              UNIQUE(node_id,seq)
            );
            CREATE TABLE IF NOT EXISTS node_state(
              node_id TEXT PRIMARY KEY,
              last_seq INTEGER NOT NULL,
              last_payload_sha256 TEXT NOT NULL,
              last_seen_utc TEXT NOT NULL,
              state TEXT NOT NULL,
              recovery_streak INTEGER NOT NULL DEFAULT 0,
              findings_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS alerts(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              node_id TEXT NOT NULL,
              seq INTEGER NOT NULL,
              created_utc TEXT NOT NULL,
              severity TEXT NOT NULL,
              code TEXT NOT NULL,
              finding_json TEXT NOT NULL
            );
            """)

    def get_state(self,node_id):
        with self.conn() as c:
            r=c.execute("SELECT * FROM node_state WHERE node_id=?",(node_id,)).fetchone()
            return dict(r) if r else None

    def ingest(self,node_id,envelope,payload,findings,recovery_required):
        with self.lock, self.conn() as c:
            prior=c.execute("SELECT * FROM node_state WHERE node_id=?",(node_id,)).fetchone()
            last_seq=int(prior["last_seq"]) if prior else 0
            if int(payload["seq"]) <= last_seq:
                raise ValueError(f"replay/out-of-order sequence: got {payload['seq']} <= {last_seq}")
            expected_prev=prior["last_payload_sha256"] if prior else "0"*64
            got_prev=payload.get("prev_heartbeat_hash") or "0"*64
            if got_prev!=expected_prev:
                raise ValueError("heartbeat chain mismatch")

            prev_state=prior["state"] if prior else "NORMAL"
            recovery=int(prior["recovery_streak"]) if prior else 0
            state,recovery=aggregate_state(
                findings,previous_state=prev_state,recovery_streak=recovery,
                recovery_required=recovery_required
            )
            received=utc_now()
            cur=c.execute("""
              INSERT INTO heartbeats(
                node_id,seq,received_utc,payload_timestamp_utc,payload_sha256,
                prev_heartbeat_hash,state,findings_json,payload_json,envelope_json
              ) VALUES(?,?,?,?,?,?,?,?,?,?)
            """,(
                node_id,int(payload["seq"]),received,payload["timestamp_utc"],
                envelope["payload_sha256"],payload.get("prev_heartbeat_hash"),state,
                json.dumps(findings,sort_keys=True),json.dumps(payload,sort_keys=True),
                json.dumps(envelope,sort_keys=True)
            ))
            hb_id=cur.lastrowid
            c.execute("""
              INSERT INTO node_state(node_id,last_seq,last_payload_sha256,last_seen_utc,state,recovery_streak,findings_json)
              VALUES(?,?,?,?,?,?,?)
              ON CONFLICT(node_id) DO UPDATE SET
                last_seq=excluded.last_seq,last_payload_sha256=excluded.last_payload_sha256,
                last_seen_utc=excluded.last_seen_utc,state=excluded.state,
                recovery_streak=excluded.recovery_streak,findings_json=excluded.findings_json
            """,(node_id,int(payload["seq"]),envelope["payload_sha256"],received,state,recovery,json.dumps(findings,sort_keys=True)))
            for f in findings:
                if f["severity"] in ("high","critical"):
                    c.execute("""
                      INSERT INTO alerts(node_id,seq,created_utc,severity,code,finding_json)
                      VALUES(?,?,?,?,?,?)
                    """,(node_id,int(payload["seq"]),received,f["severity"],f["code"],json.dumps(f,sort_keys=True)))
            return {"heartbeat_id":hb_id,"received_utc":received,"state":state,"recovery_streak":recovery}

    def fleet(self):
        with self.conn() as c:
            return [dict(r) for r in c.execute("SELECT * FROM node_state ORDER BY node_id")]

    def node_history(self,node_id,limit=50):
        with self.conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT id,node_id,seq,received_utc,payload_timestamp_utc,payload_sha256,state,findings_json "
                "FROM heartbeats WHERE node_id=? ORDER BY seq DESC LIMIT ?",(node_id,limit)
            )]

    def alerts(self,limit=100):
        with self.conn() as c:
            rows=[dict(r) for r in c.execute(
                "SELECT id,node_id,seq,created_utc,severity,code,finding_json "
                "FROM alerts ORDER BY id DESC LIMIT ?",(limit,)
            )]
            for r in rows:
                r["finding"]=json.loads(r.pop("finding_json"))
            return rows

    def alert_counts(self):
        with self.conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT severity,COUNT(*) AS count FROM alerts GROUP BY severity"
            )]


class App:
    def __init__(self,registry_path,db_path,max_clock_skew=300,collector_private_key=None):
        self.registry_path=Path(registry_path)
        self.store=Store(db_path)
        self.max_clock_skew=max_clock_skew
        self.collector_private_key=Path(collector_private_key) if collector_private_key else None

    def registry(self):
        return load_registry(self.registry_path)

    def accept(self,envelope):
        payload=envelope.get("payload") or {}
        node_id=payload.get("node_id")
        if not node_id: raise ValueError("missing node_id")
        reg=self.registry()
        node=reg.get("nodes",{}).get(node_id)
        if not node or not node.get("enabled",True):
            raise PermissionError("node not enrolled/enabled")
        verify_pem_envelope(node["public_key_pem"],envelope)

        if payload.get("schema")!="ai-dfir/fleet-heartbeat/v0.5":
            raise ValueError("unexpected heartbeat schema")
        ts=parse_utc(payload["timestamp_utc"])
        skew=abs(time.time()-ts)
        if skew>self.max_clock_skew:
            raise ValueError(f"heartbeat clock skew {skew:.1f}s exceeds {self.max_clock_skew}s")

        policy=node.get("policy",{})
        findings=evaluate(payload,policy)
        receipt=self.store.ingest(
            node_id,envelope,payload,findings,
            recovery_required=int(policy.get("recovery_heartbeats",3))
        )
        receipt.update({
            "schema":"ai-dfir/fleet-receipt/v0.5",
            "node_id":node_id,
            "seq":int(payload["seq"]),
            "heartbeat_payload_sha256":envelope["payload_sha256"],
            "findings":findings,
        })
        if self.collector_private_key:
            return {"signed_receipt":sign_payload(self.collector_private_key,receipt)}
        return {"receipt":receipt}

    def fleet_view(self):
        reg=self.registry()
        now=time.time()
        rows=[]
        by={x["node_id"]:x for x in self.store.fleet()}
        for node_id,node in sorted(reg.get("nodes",{}).items()):
            state=by.get(node_id)
            expected=float(node.get("policy",{}).get("expected_heartbeat_seconds",300))
            if not state:
                rows.append({"node_id":node_id,"state":"NEVER_SEEN","stale":True,"last_seen_utc":None})
                continue
            age=now-parse_utc(state["last_seen_utc"])
            stale=age>expected*2.5
            shown="STALE" if stale else state["state"]
            rows.append({
                "node_id":node_id,"state":shown,"underlying_state":state["state"],
                "stale":stale,"age_seconds":round(age,1),"last_seen_utc":state["last_seen_utc"],
                "last_seq":state["last_seq"],"findings":json.loads(state["findings_json"])
            })
        return rows


class Handler(BaseHTTPRequestHandler):
    server_version="AI-DFIR-Fleet/0.5"

    def _json(self,status,obj):
        data=json.dumps(obj,sort_keys=True).encode()
        self.send_response(status);self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(data)));self.end_headers();self.wfile.write(data)

    def do_POST(self):
        if self.path!="/v1/heartbeat":
            return self._json(404,{"error":"not found"})
        try:
            n=int(self.headers.get("Content-Length","0"))
            body=self.rfile.read(n)
            envelope=json.loads(body)
            result=self.server.app.accept(envelope)
            self._json(202,result)
        except PermissionError as e:self._json(403,{"error":str(e)})
        except Exception as e:self._json(400,{"error":str(e)})

    def do_GET(self):
        u=urlparse(self.path)
        if u.path=="/healthz":
            return self._json(200,{"status":"ok","version":"0.5"})
        if u.path=="/v1/fleet":
            return self._json(200,{"nodes":self.server.app.fleet_view()})
        if u.path=="/v1/alerts":
            return self._json(200,{"alerts":self.server.app.store.alerts()})
        if u.path.startswith("/v1/node/"):
            node_id=u.path.split("/",3)[3]
            return self._json(200,{"node_id":node_id,"history":self.server.app.store.node_history(node_id)})
        if u.path=="/metrics":
            rows=self.server.app.fleet_view()
            lines=["# HELP ai_dfir_fleet_node_state Node state (1 for current labelled state)",
                   "# TYPE ai_dfir_fleet_node_state gauge"]
            states=["NORMAL","RECOVERED","OBSERVE","ALERT","CRITICAL","STALE","NEVER_SEEN"]
            for r in rows:
                for s in states:
                    val=1 if r["state"]==s else 0
                    lines.append(f'ai_dfir_fleet_node_state{{node_id="{r["node_id"]}",state="{s}"}} {val}')
                if "age_seconds" in r:
                    lines.append(f'ai_dfir_fleet_heartbeat_age_seconds{{node_id="{r["node_id"]}"}} {r["age_seconds"]}')
            data=("\n".join(lines)+"\n").encode()
            self.send_response(200);self.send_header("Content-Type","text/plain; version=0.0.4")
            self.send_header("Content-Length",str(len(data)));self.end_headers();self.wfile.write(data)
            return
        self._json(404,{"error":"not found"})

    def log_message(self,fmt,*args):
        print(f"[collector] {self.address_string()} {fmt%args}")


def make_server(host,port,app,tls_cert=None,tls_key=None,client_ca=None):
    srv=ThreadingHTTPServer((host,port),Handler);srv.app=app
    scheme="http"
    if tls_cert or tls_key:
        if not (tls_cert and tls_key):
            raise ValueError("Both --tls-cert and --tls-key are required")
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version=ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(tls_cert,tls_key)
        if client_ca:
            ctx.load_verify_locations(cafile=client_ca)
            ctx.verify_mode=ssl.CERT_REQUIRED
        srv.socket=ctx.wrap_socket(srv.socket,server_side=True)
        scheme="https"
    srv.listen_scheme=scheme
    return srv


def serve(host,port,app,tls_cert=None,tls_key=None,client_ca=None):
    srv=make_server(host,port,app,tls_cert,tls_key,client_ca)
    print(json.dumps({"listen":f"{srv.listen_scheme}://{host}:{srv.server_port}","db":app.store.path,
                      "mtls_required":bool(client_ca)},indent=2),flush=True)
    srv.serve_forever()


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--registry",required=True)
    ap.add_argument("--db",required=True)
    ap.add_argument("--host",default="127.0.0.1")
    ap.add_argument("--port",type=int,default=8787)
    ap.add_argument("--max-clock-skew",type=int,default=300)
    ap.add_argument("--collector-private-key")
    ap.add_argument("--tls-cert")
    ap.add_argument("--tls-key")
    ap.add_argument("--client-ca",help="Optional CA used to require and verify client certificates (mTLS)")
    args=ap.parse_args()
    app=App(args.registry,args.db,args.max_clock_skew,args.collector_private_key)
    serve(args.host,args.port,app,args.tls_cert,args.tls_key,args.client_ca)

if __name__=="__main__":main()
