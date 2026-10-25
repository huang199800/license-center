import json

import pytest

from sdk import LicenseClient, LicenseError, verify_token


def test_offline_issuance_install_and_limits(env,monkeypatch):
    plan={'id':'demo-offline','product':'demo','name':'离线永久','days':None,'perpetual':True,
          'policy':'offline','token_ttl':900,'offline_max':86400}
    assert env.client.post('/v1/admin/plans',json=plan,headers=env.headers).status_code==200
    env.step()
    headers={**env.headers,'Idempotency-Key':'offline-issue-request-0001'}
    body={'plan':'demo-offline','customer':'offline-customer','instance':'stable-offline-instance-001','reason':'隔离网络部署'}
    response=env.client.post('/v1/admin/offline',json=body,headers=headers)
    assert response.status_code==200,response.text
    r=response.json()
    assert env.client.post('/v1/admin/offline',json=body,headers=headers).json()==r
    assert r['expires_at']==env.clock[0]+86400
    assert 'activation_secret' not in r
    path=env.tmp/'offline.json';path.write_text(json.dumps(r))
    monkeypatch.setattr('sdk.client.time.time',lambda:env.clock[0])
    client=LicenseClient('https://unused.invalid','demo',env.vault.data['issuer'],env.vault.public(),env.tmp/'offline-cache.json').initialize(body['instance'])
    assert client.installOffline(path)['perpetual']
    assert client.requireFeature('basic')
    client.start_background_refresh();assert client.thread is None
    env.step()
    revoke=env.client.post('/v1/admin/licenses/'+r['license_id']+'/status',json={'status':'revoked','reason':'离线撤销测试'},headers=env.headers)
    assert revoke.status_code==200
    assert client.requireFeature('basic') # documented offline revocation boundary
    env.clock[0]=r['expires_at']
    with pytest.raises(LicenseError,match='TOKEN_EXPIRED'):client.requireFeature('basic')
    client.close()
