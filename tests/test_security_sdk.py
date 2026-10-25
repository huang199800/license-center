import base64
import json
import time

import httpx
import pytest

from center.cli import add_admin, seed
from center.db import connect, transaction
from center.security import b64, totp
from sdk import LicenseClient, LicenseError, verify_token
from sdk.client import atomic_json


def claims(env,r,**kw):
    return verify_token(r['token'],keys=env.vault.public(),issuer=env.vault.data['issuer'],product='demo',instance='stable-instance-0001',now=env.clock[0],**kw)


@pytest.mark.parametrize('change,expected',[
    ({'aud':'other'},'TOKEN_AUDIENCE'),({'inst':'fake'},'TOKEN_INSTANCE'),({'iat':'1'},'TOKEN_INVALID'),
    ({'nbf':9999999999},'TOKEN_TIME_INVALID'),({'exp':1},'TOKEN_TIME_INVALID'),
    ({'perpetual':True},'TOKEN_INVALID'),({'features':'all'},'TOKEN_INVALID'),
    ({'quotas':{'users':-1}},'TOKEN_INVALID'),({'license_exp':1},'TOKEN_INVALID'),({'status':'revoked'},'TOKEN_INVALID')])
def test_signed_invalid_claims(env,change,expected):
    r=env.redeem().json();p=claims(env,r);p.update(change);r['token']=env.vault.sign(p)
    with pytest.raises(LicenseError,match=expected):claims(env,r)


@pytest.mark.parametrize('mutation',['signature','features','expiry','algorithm','unknown','url'])
def test_tamper_and_header(env,mutation):
    r=env.redeem().json();head,body,sig=r['token'].split('.')
    h=json.loads(base64.urlsafe_b64decode(head+'='*(-len(head)%4)));p=claims(env,r)
    if mutation=='signature':sig=('A' if sig[0]!='A' else 'B')+sig[1:]
    if mutation=='features':p['features']=['superadmin'];body=b64(json.dumps(p).encode())
    if mutation=='expiry':p['exp']+=86400;body=b64(json.dumps(p).encode())
    if mutation=='algorithm':h['alg']='none';head=b64(json.dumps(h).encode())
    if mutation=='unknown':h['kid']='unknown';head=b64(json.dumps(h).encode())
    if mutation=='url':h['jku']='https://attacker.invalid/keys';head=b64(json.dumps(h).encode())
    r['token']='.'.join([head,body,sig])
    with pytest.raises(LicenseError):claims(env,r)


def test_token_expiry_distinct_from_license(env):
    r=env.redeem().json();env.clock[0]=r['expires_at']
    with pytest.raises(LicenseError,match='TOKEN_EXPIRED'):claims(env,r)
    p=json.loads(base64.urlsafe_b64decode(r['token'].split('.')[1]+'=='))
    env.clock[0]=p['license_exp']
    with pytest.raises(LicenseError,match='LICENSE_EXPIRED'):claims(env,r)


def test_mfa_replay_and_stepup(env):
    repeated=env.client.post('/v1/admin/login',json={'username':'admin','password':env.password,'otp':totp(env.otp,env.clock[0]//30)})
    assert repeated.status_code==401
    assert env.client.post('/v1/admin/codes',headers=env.headers,json={'plan':'demo-month'}).status_code==401
    env.step()
    assert env.client.post('/v1/admin/codes',headers=env.headers,json={'plan':'demo-month'}).status_code==200
    assert env.client.post('/v1/admin/codes',headers=env.headers,json={'plan':'demo-month'}).status_code==401
    assert env.client.post('/v1/admin/login',json={'username':'no-user','password':'bad','otp':'000000'}).status_code==401


@pytest.mark.parametrize('role',['viewer','operator'])
def test_admin_scoping(env,role):
    seed(env.root,'other')
    otp=base64.b32encode(b'a'*20).decode()
    add_admin(env.root,role,'a-long-password-for-test',otp,role,['demo'])
    response=env.client.post('/v1/admin/login',json={'username':role,'password':'a-long-password-for-test','otp':totp(otp,env.clock[0]//30)})
    headers={'Authorization':'Bearer '+response.json()['access_token']}
    inventory=env.client.get('/v1/admin/inventory',headers=headers).json()
    assert all(p['product']=='demo' for p in inventory['plans'])
    assert env.client.get('/v1/admin/inventory?product=other',headers=headers).status_code==403
    assert env.client.post('/v1/admin/products',headers=headers,json={'id':'new','name':'new'}).status_code==403
    plan={'id':'other-month','product':'demo','name':'collision'}
    assert env.client.post('/v1/admin/plans',headers=headers,json=plan).status_code== (403 if role=='viewer' else 409)


def sdk_from_result(env,r,transport=None):
    client=LicenseClient('http://testserver','demo',env.vault.data['issuer'],env.vault.public(),env.tmp/'cache.json',allow_http=True,transport=transport).initialize('stable-instance-0001')
    client.data.update(r);client._save()
    return client


def test_sdk_fail_closed_network_cache_and_clock(env,monkeypatch):
    r=env.redeem().json()
    # Use server time so the deterministic fixture and real-time SDK agree.
    monkeypatch.setattr('sdk.client.time.time',lambda:env.clock[0])
    def offline(request):raise httpx.ConnectError('network down')
    client=sdk_from_result(env,r,httpx.MockTransport(offline))
    assert client.requireFeature('basic')
    with pytest.raises(LicenseError,match='FEATURE_DENIED'):client.requireFeature('missing')
    with pytest.raises(LicenseError,match='NETWORK_UNAVAILABLE'):client.refresh()
    assert client.requireFeature('basic')
    client.data['seen_time']=env.clock[0]+100
    with pytest.raises(LicenseError,match='CLOCK_ROLLBACK'):client.requireFeature('basic')
    client.data['seen_time']=env.clock[0]
    env.clock[0]=r['expires_at']+1
    with pytest.raises(LicenseError,match='TOKEN_EXPIRED'):client.requireFeature('basic')
    client.close()


def test_strict_online_never_falls_back(env,monkeypatch):
    r=env.redeem().json();p=claims(env,r);p['policy']='online';r['token']=env.vault.sign(p)
    monkeypatch.setattr('sdk.client.time.time',lambda:env.clock[0])
    def offline(request):raise httpx.ConnectError('network down')
    client=sdk_from_result(env,r,httpx.MockTransport(offline))
    with pytest.raises(LicenseError,match='NETWORK_UNAVAILABLE'):client.requireFeature('basic')
    client.close()


def test_corrupt_cache_denied(env):
    cache=env.tmp/'cache.json';cache.write_text('{bad')
    client=LicenseClient('http://testserver','demo',env.vault.data['issuer'],env.vault.public(),cache,allow_http=True)
    with pytest.raises(LicenseError,match='CACHE_INVALID'):client.initialize()
    client.close()


def test_quota_not_unlimited(env,monkeypatch):
    r=env.redeem().json();p=claims(env,r);p['quotas']={'users':2};r['token']=env.vault.sign(p)
    monkeypatch.setattr('sdk.client.time.time',lambda:env.clock[0])
    client=sdk_from_result(env,r)
    assert client.checkQuota('users',1,1)
    with pytest.raises(LicenseError,match='QUOTA_EXCEEDED'):client.checkQuota('users',2,1)
    with pytest.raises(LicenseError,match='QUOTA_EXCEEDED'):client.checkQuota('unknown',0)
    with pytest.raises(ValueError):client.checkQuota('users',-1)
    client.close()


def test_sdk_invalid_refresh_response_clears_token(env,monkeypatch):
    r=env.redeem().json()
    monkeypatch.setattr('sdk.client.time.time',lambda:env.clock[0])
    client=sdk_from_result(env,r)
    with pytest.raises(LicenseError,match='TOKEN_INVALID'):client._accept({'token':'bad'})
    assert client.getLicenseStatus()['status']=='not_activated'
    client.close()
