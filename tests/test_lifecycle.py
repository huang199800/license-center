import json
import secrets
from concurrent.futures import ThreadPoolExecutor

import pytest

from center.db import connect, dump, transaction


def auth(secret):
    return {'Authorization': 'Bearer ' + secret}


def refresh(env, r, product='demo'):
    return env.client.post('/v1/refresh', headers=auth(r['activation_secret']), json={'product': product, 'activation_id': r['activation_id']})


@pytest.mark.parametrize('name,days', [('trial',3),('week',7),('month',30),('year',365),('perpetual',None)])
def test_card_rules(env,name,days):
    result=env.redeem(env.batch('demo-'+name))
    assert result.status_code==200,result.text
    r=result.json()
    with connect(env.root/'center.db') as c:
        lic=c.execute('SELECT * FROM licenses WHERE id=?',(r['license_id'],)).fetchone()
    assert lic['starts_at']==r['server_time']
    assert lic['expires_at']==(None if days is None else r['server_time']+days*86400)
    assert bool(lic['perpetual'])==(days is None)
    if days:
        assert r['expires_at']<=lic['expires_at']


@pytest.mark.parametrize('expired',[False,True])
def test_renew_idempotency_and_expiry(env,expired):
    r=env.redeem().json()
    with connect(env.root/'center.db') as c:
        old=c.execute('SELECT expires_at FROM licenses').fetchone()[0]
    code=env.batch(kind='renew')
    if expired: env.clock[0]=old+1
    body={'product':'demo','license_id':r['license_id'],'code':code}
    headers={**auth(r['license_secret']),'Idempotency-Key':'renew-request-000001'}
    a=env.client.post('/v1/renew',json=body,headers=headers)
    b=env.client.post('/v1/renew',json=body,headers=headers)
    assert a.status_code==200,a.text
    assert a.json()==b.json()
    assert a.json()['expires_at']==max(old,env.clock[0])+30*86400
    assert refresh(env,r).status_code==200


def test_concurrent_single_code(env):
    code=env.batch()
    with ThreadPoolExecutor(max_workers=8) as pool:
        responses=list(pool.map(lambda i:env.redeem(code,instance=f'instance-number-{i:04}'),range(12)))
    assert sum(r.status_code==200 for r in responses)==1
    assert all(r.status_code in [200,409] for r in responses)


def test_concurrent_idempotency(env):
    code=env.batch()
    with ThreadPoolExecutor(max_workers=6) as pool:
        responses=list(pool.map(lambda _:env.redeem(code,key='same-request-key-00001'),range(6)))
    assert all(r.status_code==200 for r in responses)
    assert all(r.json()==responses[0].json() for r in responses)
    conflict=env.redeem(code,key='same-request-key-00001',instance='different-instance-0001')
    assert conflict.status_code==409


def test_concurrent_activation_limit(env):
    r=env.redeem().json()
    def activate(i):
        return env.client.post('/v1/activate',headers={**auth(r['license_secret']),'Idempotency-Key':secrets.token_hex(16)},
                               json={'product':'demo','license_id':r['license_id'],'instance':f'other-instance-{i:04}'})
    with ThreadPoolExecutor(max_workers=6) as pool:
        responses=list(pool.map(activate,range(6)))
    assert all(x.status_code==409 and x.json()['error']['code']=='DEVICE_LIMIT' for x in responses)


def test_code_deadline_separate_from_usage(env):
    code=env.batch(redeem_before=env.clock[0]+1000)
    r=env.redeem(code).json()
    env.clock[0]+=1000
    assert refresh(env,r).status_code==200
    expired_code=env.batch(redeem_before=env.clock[0]-1)
    assert env.redeem(expired_code).json()['error']['code']=='CODE_REDEEM_EXPIRED'


def test_starts_at_explicit_and_expired_start_rolls_back(env):
    start=env.clock[0]-86400
    r=env.redeem(env.batch(starts_at=start)).json()
    with connect(env.root/'center.db') as c:
        assert c.execute('SELECT expires_at FROM licenses WHERE id=?',(r['license_id'],)).fetchone()[0]==start+30*86400
    code=env.batch(starts_at=env.clock[0]-40*86400)
    assert env.redeem(code).json()['error']['code']=='LICENSE_EXPIRED'
    with connect(env.root/'center.db') as c:
        assert c.execute('SELECT uses FROM codes WHERE digest=?',(env.vault.digest_code(code),)).fetchone()[0]==0


def test_snapshot_upgrade_and_revocation(env):
    r=env.redeem().json()
    inv=env.client.get('/v1/admin/inventory',headers=env.headers).json()
    plan=next(json.loads(p['spec']) for p in inv['plans'] if p['id']=='demo-month')
    plan['features']=['basic','export'];plan['quotas']={'users':10}
    assert env.client.post('/v1/admin/plans',headers=env.headers,json=plan).status_code==200
    with connect(env.root/'center.db') as c:
        assert json.loads(c.execute('SELECT snapshot FROM licenses').fetchone()[0])['features']==['basic']
    code=env.batch(kind='upgrade')
    u=env.client.post('/v1/renew',json={'product':'demo','license_id':r['license_id'],'code':code},headers={**auth(r['license_secret']),'Idempotency-Key':'upgrade-key-000001'})
    assert u.status_code==200,u.text
    env.step()
    rev=env.client.post('/v1/admin/licenses/'+r['license_id']+'/status',headers=env.headers,json={'status':'revoked','reason':'测试撤销'})
    assert rev.status_code==200
    assert rev.json()['cached_credential_boundary']>=env.clock[0]
    assert refresh(env,r).json()['error']['code']=='LICENSE_REVOKED'
    renewal=env.batch(kind='renew')
    assert env.client.post('/v1/renew',json={'product':'demo','license_id':r['license_id'],'code':renewal},headers={**auth(r['license_secret']),'Idempotency-Key':'revoked-renew-0001'}).json()['error']['code']=='LICENSE_REVOKED'


def test_cross_product_and_public_id_not_auth(env):
    r=env.redeem().json()
    assert refresh(env,r,'other').status_code==401
    assert env.client.post('/v1/refresh',json={'product':'demo','activation_id':r['activation_id']}).status_code==401
    assert env.client.post('/v1/activate',json={'product':'demo','license_id':r['license_id'],'instance':'new-instance-0001'},headers={'Idempotency-Key':secrets.token_hex(16)}).status_code==401


def test_rebinding_keeps_old_window(env):
    r=env.redeem().json()
    out=env.client.post('/v1/deactivate',headers=auth(r['activation_secret']),json={'product':'demo','activation_id':r['activation_id']})
    assert out.status_code==200
    assert out.json()['old_credential_valid_until']==r['expires_at']
    assert refresh(env,r).status_code==401
    body={'product':'demo','license_id':r['license_id'],'instance':'replacement-instance-001'}
    headers={**auth(r['license_secret']),'Idempotency-Key':secrets.token_hex(16)}
    assert env.client.post('/v1/activate',json=body,headers=headers).status_code==409
    env.clock[0]=out.json()['new_binding_not_before']+1
    assert env.client.post('/v1/activate',json=body,headers=headers).status_code==200


def test_crash_lease_expiry_and_partition(env):
    inv=env.client.get('/v1/admin/inventory',headers=env.headers).json()
    plan=next(json.loads(p['spec']) for p in inv['plans'] if p['id']=='demo-month')
    plan['max_devices']=2
    assert env.client.post('/v1/admin/plans',headers=env.headers,json=plan).status_code==200
    r=env.redeem().json()
    body={'product':'demo','license_id':r['license_id'],'instance':'second-instance-0001'}
    headers={**auth(r['license_secret']),'Idempotency-Key':secrets.token_hex(16)}
    assert env.client.post('/v1/activate',json=body,headers=headers).json()['error']['code']=='ONLINE_LIMIT'
    env.clock[0]=r['expires_at']+1
    second=env.client.post('/v1/activate',json=body,headers=headers)
    assert second.status_code==200,second.text
    assert refresh(env,r).json()['error']['code']=='ONLINE_LIMIT'
    with connect(env.root/'center.db') as c:
        assert c.execute('SELECT count(*) FROM instances').fetchone()[0]==2


def test_multiredeem_code_limit_and_no_plaintext(env):
    code=env.batch(max_uses=2)
    assert env.redeem(code,instance='customer-instance-0001').status_code==200
    assert env.redeem(code,instance='customer-instance-0002').status_code==200
    assert env.redeem(code,instance='customer-instance-0003').status_code==409
    with connect(env.root/'center.db') as c:
        raw=''.join(str(tuple(row)) for table in ['codes','audit','idempotency'] for row in c.execute('SELECT * FROM '+table))
    assert code not in raw
