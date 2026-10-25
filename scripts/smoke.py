"""Real TCP deployment drill. Isolated temporary data; no secrets in output."""
import base64
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

from center.backup import restore, snapshot
from center.cli import add_admin, seed
from center.db import migrate
from center.security import Vault, totp
from sdk import LicenseClient, LicenseError


def main():
    checks=[]
    with tempfile.TemporaryDirectory(prefix='lc-drill-') as temp:
        root=Path(temp)/'original';root.mkdir()
        vault=Vault.create(root/'vault.json','urn:smoke:licenses')
        migrate(root/'center.db')
        secret=base64.b32encode(secrets.token_bytes(20)).decode()
        password=secrets.token_urlsafe(24)
        add_admin(root,'drill',password,secret)
        seed(root,'demo')
        processes=[]
        logs=[]
        def start(directory):
            with socket.socket() as sock:
                sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
            env={**os.environ,'LC_PORT':str(port),'LC_HOST':'127.0.0.1','PYTHONUNBUFFERED':'1'}
            logfile=open(Path(temp)/f'server-{port}.log','w',encoding='utf-8');logs.append(logfile)
            p=subprocess.Popen([sys.executable,'-m','center.cli','--data',str(directory),'serve'],env=env,stdout=logfile,stderr=logfile,
                               creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
            processes.append(p);url=f'http://127.0.0.1:{port}'
            for _ in range(100):
                try:
                    if httpx.get(url+'/health/ready',trust_env=False).status_code==200:return p,url
                except httpx.TransportError:pass
                time.sleep(.1)
            raise RuntimeError('startup failed; inspect local smoke log')
        def request(url,method,path,body=None,headers=None):
            r=httpx.request(method,url+path,json=body,headers=headers,trust_env=False)
            if r.status_code>=400:raise RuntimeError(f'{path}: HTTP {r.status_code}: {r.text}')
            return r.json()
        def login(url):
            # Previous valid TOTP window leaves current counter for explicit step-up.
            r=request(url,'POST','/v1/admin/login',{'username':'drill','password':password,'otp':totp(secret,int(time.time())//30-1)})
            return {'Authorization':'Bearer '+r['access_token']}
        last_counter=[-1]
        def step(url,headers):
            while int(time.time())//30<=last_counter[0]:time.sleep(.25)
            counter=int(time.time())//30
            request(url,'POST','/v1/admin/reauth',{'otp':totp(secret,counter)},headers)
            last_counter[0]=counter
        try:
            p,url=start(root);checks.append('Uvicorn真实进程启动及就绪检查')
            h=login(url);checks.append('真实HTTP管理员密码加TOTP登录')
            step(url,h)
            issued=request(url,'POST','/v1/admin/codes',{'plan':'demo-month','count':2},h)['delivery_once']
            code=issued[0]['code']
            checks.append('MFA再次验证与兑换码一次性交付')
            client=LicenseClient(url,'demo',vault.data['issuer'],vault.public(),Path(temp)/'client.json',allow_http=True).initialize()
            result=client.activate(code,'deployment-drill');assert result['status']=='active'
            assert client.requireFeature('basic');checks.append('SDK真实HTTP激活、签名验证及功能校验')
            node_config=Path(temp)/'node-config.json'
            node_config.write_text(json.dumps({'url':url,'product':'demo','issuer':vault.data['issuer'],'keys':vault.public(),
                                              'cache':str(Path(temp)/'node-cache.json'),'allowHttp':True,'code':issued[1]['code']}),encoding='utf-8')
            subprocess.run(['node','scripts/node-smoke.mjs',str(node_config)],check=True,capture_output=True)
            checks.append('Node.js SDK通过真实HTTP完成激活、刷新及功能校验')
            step(url,h)
            renew=request(url,'POST','/v1/admin/codes',{'plan':'demo-month','kind':'renew'},h)['delivery_once'][0]['code']
            before=client.getLicenseStatus()['expires_at']
            result=client.renew(renew,idempotency_key='real-smoke-renew-key-0001')
            assert result['expires_at']==before+30*86400
            again=client.renew(renew,idempotency_key='real-smoke-renew-key-0001');assert result==again
            checks.append('续费与同幂等键重试不重复加时')
            path=Path(temp)/'backup.lcb';backup_password=secrets.token_urlsafe(32)
            snapshot(root,path,backup_password);checks.append('在线一致性快照及加密备份')
            p.terminate();p.wait(timeout=10)
            recovered=Path(temp)/'recovered';restore(path,recovered,backup_password,True)
            p2,url2=start(recovered);checks.append('停写后新目录恢复并启动独立服务进程')
            # Existing cache and credentials continue to work at new physical endpoint.
            client.close()
            client=LicenseClient(url2,'demo',vault.data['issuer'],vault.public(),Path(temp)/'client.json',allow_http=True).initialize()
            assert client.refresh()['status']=='active';checks.append('迁移后原SDK缓存与实例身份继续刷新，无须重新激活')
            # Old admin sessions are intentionally invalidated; use a later TOTP for new login.
            while int(time.time())//30<=last_counter[0]+1:time.sleep(.25)
            h=login(url2);step(url2,h)
            revoked=request(url2,'POST','/v1/admin/licenses/'+client.data['license_id']+'/status',{'status':'revoked','reason':'部署演练撤销'},h)
            assert revoked['cached_credential_boundary']>int(time.time())
            try:client.refresh();raise AssertionError('revocation not enforced')
            except LicenseError as exc:assert exc.code=='LICENSE_REVOKED'
            checks.append('撤销拒绝刷新；返回旧凭证有效窗口')
            client.close()
        finally:
            for proc in processes:
                if proc.poll() is None:proc.terminate();proc.wait(timeout=10)
            for logfile in logs:logfile.close()
    report={'platform':sys.platform,'python':sys.version.split()[0],'checks':checks,'passed':len(checks),'failed':0,
            'scope':'本机真实TCP进程与隔离目录恢复；没有执行Docker、Linux或真实跨主机DNS切换'}
    if len(sys.argv)>1:
        Path(sys.argv[1]).write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(report,ensure_ascii=True,indent=2))


if __name__=='__main__':main()
