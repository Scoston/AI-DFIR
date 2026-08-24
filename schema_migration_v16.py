#!/usr/bin/env python3
"""Transactional schema migration runner for AI-DFIR enterprise metadata."""
from __future__ import annotations
import argparse,hashlib,json,sqlite3
from pathlib import Path

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def discover(directory):return sorted(Path(directory).glob('*.sql'))

def sqlite_apply(db,migrations,dry=False):
    c=sqlite3.connect(db);c.execute('CREATE TABLE IF NOT EXISTS schema_migrations(version TEXT PRIMARY KEY,sha256 TEXT NOT NULL,applied_utc TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)');applied={r[0]:r[1] for r in c.execute('SELECT version,sha256 FROM schema_migrations')};rows=[]
    try:
        for p in migrations:
            version=p.stem.split('_',1)[0];digest=sha(p)
            if version in applied:
                if applied[version]!=digest:raise RuntimeError(f'migration checksum changed: {version}')
                rows.append({'version':version,'status':'ALREADY_APPLIED'});continue
            if not dry:
                c.executescript(p.read_text());c.execute('INSERT INTO schema_migrations(version,sha256) VALUES(?,?)',(version,digest));c.commit()
            rows.append({'version':version,'status':'DRY_RUN' if dry else 'APPLIED','sha256':digest})
        return {'schema':'ai-dfir/schema-migration/v1.6','valid':True,'backend':'sqlite','migrations':rows}
    finally:c.close()

def postgres_apply(dsn,migrations,dry=False):
    import psycopg
    rows=[]
    with psycopg.connect(dsn) as c:
        with c.cursor() as cur:
            cur.execute('CREATE TABLE IF NOT EXISTS schema_migrations(version text PRIMARY KEY,sha256 text NOT NULL,applied_utc timestamptz NOT NULL DEFAULT now())')
            cur.execute('SELECT version,sha256 FROM schema_migrations');applied=dict(cur.fetchall())
            for p in migrations:
                version=p.stem.split('_',1)[0];digest=sha(p)
                if version in applied:
                    if applied[version]!=digest:raise RuntimeError(f'migration checksum changed: {version}')
                    rows.append({'version':version,'status':'ALREADY_APPLIED'});continue
                if not dry:
                    cur.execute(p.read_text());cur.execute('INSERT INTO schema_migrations(version,sha256) VALUES(%s,%s)',(version,digest))
                rows.append({'version':version,'status':'DRY_RUN' if dry else 'APPLIED','sha256':digest})
        if dry:c.rollback()
    return {'schema':'ai-dfir/schema-migration/v1.6','valid':True,'backend':'postgres','migrations':rows}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--migrations',required=True);g=ap.add_mutually_exclusive_group(required=True);g.add_argument('--sqlite');g.add_argument('--dsn');ap.add_argument('--dry-run',action='store_true');ap.add_argument('--out');a=ap.parse_args();ms=discover(a.migrations);o=sqlite_apply(a.sqlite,ms,a.dry_run) if a.sqlite else postgres_apply(a.dsn,ms,a.dry_run);s=json.dumps(o,indent=2,sort_keys=True);Path(a.out).write_text(s) if a.out else print(s)
if __name__=='__main__':main()
