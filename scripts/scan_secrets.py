#!/usr/bin/env python3
"""Pre-publish staged + reachable-history scan. Reports path/rule only, never matches."""
import argparse
import json
import re
import subprocess
from pathlib import Path

RULES={
    'github_token': re.compile(rb'(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})'),
    'private_key': re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'),
    'credential_url':re.compile(rb'https?://[^\s/@:]+:[^\s/@]+@'),
    'vault_material':re.compile(rb'"(?:code_pepper|encryption_key)"\s*:\s*"[A-Za-z0-9_+/=-]{32,}"'),
}


def git(*args):
    return subprocess.run(['git',*args],capture_output=True,check=True).stdout


def bad_path(name):
    p=Path(name)
    return (p.name in ['.env','vault.json','center.db','config.json','deployment.json'] or
            p.suffix.lower() in ['.pem','.key','.db','.sqlite','.sqlite3','.lcb','.lcb2','.log'] or
            'enrollment' in p.name.lower() or any(v in p.parts for v in ['state','backups','operator-exchange','business-state']))


def scan():
    findings=[];seen=set();count=0
    for line in git('ls-files','--stage','-z').split(b'\0'):
        if not line:continue
        attrs,name=line.split(b'\t',1);mode,oid,stage=attrs.split()
        path=name.decode('utf-8','replace')
        seen.add((oid,path))
    for line in git('rev-list','--objects','--all').splitlines():
        parts=line.split(b' ',1)
        if len(parts)!=2:continue
        oid,name=parts
        if git('cat-file','-t',oid.decode()).strip()!=b'blob':continue
        seen.add((oid,name.decode('utf-8','replace')))
    for oid,path in seen:
        count+=1
        if bad_path(path):findings.append({'path':path,'rule':'sensitive_filename'})
        raw=git('cat-file','blob',oid.decode())
        for rule,pattern in RULES.items():
            if pattern.search(raw):findings.append({'path':path,'rule':rule})
    return {'scanned_blobs_and_paths':count,'findings':findings,'scope':'Git index and all reachable history; pattern scan, not proof of absence'}


if __name__=='__main__':
    result=scan();print(json.dumps(result,ensure_ascii=False,indent=2))
    raise SystemExit(1 if result['findings'] else 0)
