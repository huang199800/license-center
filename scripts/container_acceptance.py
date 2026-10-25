#!/usr/bin/env python3
"""Real Docker integration drill for a disposable Linux CI runner, not a mock.

Run as root with application test dependencies installed. Never point at production.
"""
import base64
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

from center.security import totp
from sdk import LicenseClient
from scripts.ops import Deployment, commit_of, write_json


def main():
    if os.name=='nt' or os.geteuid()!=0:raise SystemExit('DISPOSABLE_LINUX_ROOT_RUNNER_REQUIRED')
    source=Path(__file__).resolve().parents[1]
    checks=[]
    with tempfile.TemporaryDirectory(prefix='lc-container-drill-') as temp:
        base=Path(temp);root=base/'original';target=base/'recovered'
        config=base/'install.json';secret_dir=base/'secrets'
        write_json(config,{'domain':'','secret_dir':str(secret_dir),'port':18081})
        def ops(command,*args):
            r=subprocess.run([sys.executable,str(source/'scripts/ops.py'),command,*map(str,args)],capture_output=True,text=True)
            if r.returncode:raise RuntimeError('INTEGRATION_OPERATION_FAILED_'+command)
            return r.stdout
        dep=Deployment(root)
        try:
            ops('install','--root',root,'--config',config,'--non-interactive');checks.append('clean_source_install')
            credentials=dep.config()
            enrollment=json.loads((root/'exchange/admin-enrollment.json').read_text())
            url='http://127.0.0.1:18081'
            password=Path(credentials['admin_password_file']).read_text().strip()
            otp=enrollment['totp_secret']
            login=httpx.post(url+'/v1/admin/login',json={'username':'admin','password':password,'otp':totp(otp,int(time.time())//30-1)})
            assert login.status_code==200
            headers={'Authorization':'Bearer '+login.json()['access_token']}
            assert httpx.post(url+'/v1/admin/reauth',json={'otp':totp(otp)},headers=headers).status_code==200
            codes=httpx.post(url+'/v1/admin/codes',json={'plan':'demo-month'},headers=headers)
            assert codes.status_code==200
            client=LicenseClient(url,'demo',credentials['issuer'],httpx.get(url+'/v1/public-keys').json()['keys'],base/'client.json',allow_http=True).initialize()
            assert client.activate(codes.json()['delivery_once'][0]['code'],'container-drill')['status']=='active'
            assert client.requireFeature('basic');checks.append('admin_mfa_redeem_activate_signature')
            old_key=(root/'state/keys/vault.json').read_bytes()
            ops('install','--root',root,'--config',config,'--non-interactive')
            assert old_key==(root/'state/keys/vault.json').read_bytes()
            assert client.refresh()['status']=='active';checks.append('repeat_install_preserves_identity_and_license')
            ops('restart','--root',root);assert client.refresh()['status']=='active'
            dep.dc('up','-d','--force-recreate');dep.wait();assert client.refresh()['status']=='active'
            checks.append('restart_and_container_recreation_persist')
            # Same pinned commit tests the real update state machine without inventing another release.
            ops('update','--root',root,'--ref',commit_of(),'--commit',commit_of())
            assert client.refresh()['status']=='active';checks.append('same_schema_pinned_redeploy_preserves_license')
            backup=base/'migration.lcb2'
            ops('stop','--root',root);ops('backup','--root',root,'--output',backup)
            restored_config=base/'restore.json'
            write_json(restored_config,{'domain':'','port':18082,'backup_password_file':credentials['backup_password_file'],
                                       'key_password_file':credentials['key_password_file']})
            ops('restore','--root',target,'--config',restored_config,'--bundle',backup,'--non-interactive','--accept-stale-state')
            client.close()
            client=LicenseClient('http://127.0.0.1:18082','demo',credentials['issuer'],httpx.get('http://127.0.0.1:18082/v1/public-keys').json()['keys'],base/'client.json',allow_http=True).initialize()
            assert client.refresh()['status']=='active';checks.append('fresh_root_restore_original_client_continues')
            output=ops('logs','--root',target)
            assert password not in output and otp not in output and client.data['activation_secret'] not in output
            checks.append('management_logs_secret_filter')
            client.close()
        finally:
            for deployment in [Deployment(root),Deployment(target)]:
                if deployment.compose_path.exists():deployment.dc('down',allow_failure=True)
    print(json.dumps({'passed':len(checks),'checks':checks,'scope':'real Docker; source install and second isolated root on same CI host, not two physical servers'}))


if __name__=='__main__':main()
