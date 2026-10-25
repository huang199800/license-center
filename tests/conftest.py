import base64
import secrets
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from center.app import create_app
from center.cli import add_admin, seed
from center.db import migrate
from center.security import Vault, totp


@pytest.fixture
def env(tmp_path):
    root = tmp_path / 'data'
    root.mkdir()
    vault = Vault.create(root / 'vault.json', 'urn:test:licenses')
    migrate(root / 'center.db')
    otp = base64.b32encode(secrets.token_bytes(20)).decode()
    password = secrets.token_urlsafe(24)
    add_admin(root, 'admin', password, otp)
    seed(root, 'demo')
    clock = [int(time.time()) // 30 * 30 + 2]
    app = create_app(root, lambda: clock[0])
    client = TestClient(app)
    login = client.post('/v1/admin/login', json={'username': 'admin', 'password': password, 'otp': totp(otp, clock[0]//30)})
    assert login.status_code == 200, login.text
    headers = {'Authorization': 'Bearer ' + login.json()['access_token']}
    e = SimpleNamespace(root=root, vault=vault, clock=clock, app=app, client=client, otp=otp, password=password, headers=headers, tmp=tmp_path)
    def step():
        clock[0] += 30
        response = client.post('/v1/admin/reauth', headers=headers, json={'otp': totp(otp, clock[0]//30)})
        assert response.status_code == 200, response.text
    e.step = step
    def batch(plan='demo-month', kind='new', **kw):
        step()
        response = client.post('/v1/admin/codes', json={'plan': plan, 'kind': kind, **kw}, headers=headers)
        assert response.status_code == 200, response.text
        return response.json()['delivery_once'][0]['code']
    e.batch = batch
    def redeem(code=None, key=None, instance='stable-instance-0001', product='demo'):
        code = code or batch()
        return client.post('/v1/redeem', json={'product': product, 'code': code, 'customer': 'test-customer', 'instance': instance},
                           headers={'Idempotency-Key': key or secrets.token_hex(16)})
    e.redeem = redeem
    yield e
    client.close()
