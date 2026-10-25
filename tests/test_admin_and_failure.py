import json
import secrets

import pytest

from center.db import connect, migrate
from sdk import LicenseClient, LicenseError


def test_pause_clock_expiry_and_explicit_restore(env):
    r=env.redeem().json()
    env.step()
    path='/v1/admin/licenses/'+r['license_id']+'/status'
    assert env.client.post(path,json={'status':'paused','reason':'暂停测试'},headers=env.headers).status_code==200
    with connect(env.root/'center.db') as c:expiry=c.execute('SELECT expires_at FROM licenses').fetchone()[0]
    body={'product':'demo','activation_id':r['activation_id']}
    headers={'Authorization':'Bearer '+r['activation_secret']}
    assert env.client.post('/v1/refresh',json=body,headers=headers).json()['error']['code']=='LICENSE_PAUSED'
    env.step()
    assert env.client.post(path,json={'status':'active','reason':'明确恢复'},headers=env.headers).status_code==200
    with connect(env.root/'center.db') as c:assert c.execute('SELECT expires_at FROM licenses').fetchone()[0]==expiry
    env.clock[0]=expiry
    assert env.client.post('/v1/refresh',json=body,headers=headers).json()['error']['code']=='LICENSE_EXPIRED'


def test_disabled_code_and_stepup_expires(env):
    code=env.batch()
    inv=env.client.get('/v1/admin/inventory',headers=env.headers).json()
    assert env.client.post('/v1/admin/codes/'+inv['codes'][0]['id']+'/disable',headers=env.headers,json={}).status_code==200
    assert env.redeem(code).json()['error']['code']=='CODE_INVALID'
    env.step();env.clock[0]+=121
    assert env.client.post('/v1/admin/codes',json={'plan':'demo-month'},headers=env.headers).json()['error']['code']=='REAUTH_REQUIRED'


def test_spoof_forwarded_ip_cannot_bypass_rate_limit(env):
    responses=[env.client.post('/v1/admin/login',json={'username':'x','password':'wrong','otp':'000000'},headers={'X-Forwarded-For':f'192.0.2.{i}'}) for i in range(35)]
    assert responses[-1].status_code==429
    assert responses[-1].headers['Retry-After']=='60'


def test_failed_initial_migration_is_atomic(tmp_path,monkeypatch):
    from pathlib import Path
    original=Path.read_text
    def faulty(path,*args,**kwargs):
        if path.name=='001.sql':return 'CREATE TABLE partial(id TEXT); INVALID SQL;'
        return original(path,*args,**kwargs)
    monkeypatch.setattr(Path,'read_text',faulty)
    db=tmp_path/'failure.db'
    with pytest.raises(Exception):migrate(db)
    with connect(db) as c:
        assert c.execute('PRAGMA user_version').fetchone()[0]==0
        assert not c.execute("SELECT 1 FROM sqlite_master WHERE name='partial'").fetchall()


def test_ui_assets_and_openapi(env):
    home=env.client.get('/')
    assert home.status_code==200
    assert "script-src 'self'" in home.headers['Content-Security-Policy']
    assert env.client.get('/admin.js').status_code==200
    assert env.client.get('/admin.css').status_code==200
    api=env.client.get('/openapi.json').json()
    assert '/v1/admin/offline' in api['paths']
    assert '/v1/redeem' in api['paths']
