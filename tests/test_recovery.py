import json
import sqlite3

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from center.app import create_app
from center.backup import inspect_backup, reconcile, restore, snapshot
from center.db import connect, migrate
from center.security import Vault, b64
from sdk import verify_token, LicenseError
from sdk.client import atomic_json


def test_backup_restore_keeps_client_identity_and_reconciles(env):
    r=env.redeem().json();path=env.tmp/'snapshot.lcb';password='separate-backup-password-long'
    manifest=snapshot(env.root,path,password)
    assert inspect_backup(path,password)[0]['manifest']==manifest
    # New writes after the snapshot are intentionally absent in old-state recovery.
    new=env.redeem().json()
    restored=env.tmp/'restored'
    restore(path,restored,password,True)
    app=create_app(restored,lambda:env.clock[0])
    with TestClient(app) as client:
        result=client.post('/v1/refresh',headers={'Authorization':'Bearer '+r['activation_secret']},json={'product':'demo','activation_id':r['activation_id']})
        assert result.status_code==200,result.text
        assert app.state.vault.public()==env.vault.public()
        assert client.get('/v1/admin/inventory',headers=env.headers).status_code==401
    diff=reconcile(env.root,restored)
    assert new['license_id'] in diff['licenses']['only_left']
    assert diff['redemptions']['only_left']
    with pytest.raises(ValueError,match='RESTORE_REQUIRES'):restore(path,env.root,password,True)
    with pytest.raises(ValueError):restore(path,env.tmp/'unsafe',password,False)


def test_backup_password_tamper_schema_checks(env):
    path=env.tmp/'snapshot.lcb';password='separate-backup-password-long';snapshot(env.root,path,password)
    with pytest.raises(InvalidTag):inspect_backup(path,'wrong-password-long-enough')
    envelope=json.loads(path.read_text());envelope['ciphertext']='A'+envelope['ciphertext'][1:];path.write_text(json.dumps(envelope))
    with pytest.raises(InvalidTag):inspect_backup(path,password)
    with connect(env.root/'center.db') as c:c.execute('PRAGMA user_version=999')
    with pytest.raises(RuntimeError,match='DATABASE_NEWER'):migrate(env.root/'center.db')
    with pytest.raises(RuntimeError,match='SCHEMA_MISMATCH'):create_app(env.root)


def test_rotation_compatibility_and_trust_removal(env):
    r=env.redeem().json();old_keys=env.vault.public();data=env.vault.data
    data['active']='new-key';data['keys']['new-key']=b64(Ed25519PrivateKey.generate().private_bytes_raw())
    atomic_json(env.root/'vault.json',data)
    vault=Vault(env.root/'vault.json');all_keys=vault.public()
    options={'issuer':data['issuer'],'product':'demo','instance':'stable-instance-0001','now':env.clock[0]}
    old=verify_token(r['token'],keys=all_keys,**options)
    new_token=vault.sign(old)
    assert verify_token(new_token,keys=all_keys,**options)['sub']==r['license_id']
    with pytest.raises(LicenseError,match='TOKEN_UNKNOWN_KEY'):verify_token(new_token,keys=old_keys,**options)
    with pytest.raises(LicenseError,match='TOKEN_UNKNOWN_KEY'):verify_token(r['token'],keys={'new-key':all_keys['new-key']},**options)


def test_migration_idempotency(env):
    migrate(env.root/'center.db');migrate(env.root/'center.db')
    with connect(env.root/'center.db') as c:
        assert c.execute('PRAGMA user_version').fetchone()[0]==1
        assert c.execute('SELECT count(*) FROM products').fetchone()[0]==1
