import json
import os
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from fastapi.testclient import TestClient

from center.app import create_app
from center.deployment import initialize, pack, selftest, unpack
from center.security import Vault
from scripts.ops import Deployment, OperationError, read_config, write_json


def test_deployment_selftest_is_real_and_isolated():
    result=selftest()
    assert result['selftest']=='passed'
    assert result['production_data_modified'] is False


def test_split_backup_restores_original_credentials(env,monkeypatch):
    result=env.redeem().json()
    target=env.tmp/'split.lcb2'
    password='independent-state-password';key_password='independent-key-password'
    metadata={'version':'1.1.0','commit':'a'*40}
    pack(env.root,target,{'domain':'license.example.com'},metadata,password,key_password)
    envelope=json.loads(target.read_text())
    assert 'vault' not in envelope
    assert result['activation_secret'] not in target.read_text()
    with pytest.raises(InvalidTag):unpack(target,env.tmp/'bad',env.tmp/'bad-config.json',password,'incorrect-key-password',True)
    dest=env.tmp/'recovered'
    unpack(target,dest,env.tmp/'recovered-config.json',password,key_password,True)
    app=create_app(dest,lambda:env.clock[0])
    with TestClient(app) as c:
        refresh=c.post('/v1/refresh',headers={'Authorization':'Bearer '+result['activation_secret']},json={'product':'demo','activation_id':result['activation_id']})
        assert refresh.status_code==200
    assert app.state.vault.public()==env.vault.public()
    with pytest.raises(ValueError):unpack(target,dest,env.tmp/'another.json',password,key_password,True)
    with pytest.raises(ValueError):pack(env.root,env.tmp/'same.lcb2',{},metadata,password,password)
    envelope['header']['commit']='b'*40;target.write_text(json.dumps(envelope))
    with pytest.raises(InvalidTag):unpack(target,env.tmp/'tampered',env.tmp/'tampered.json',password,key_password,True)


def test_initialize_separate_keys_and_repeat_refused(tmp_path,monkeypatch):
    state=tmp_path/'state';key_path=state/'keys/vault.json'
    password_file=tmp_path/'password';password_file.write_text('random-only-for-this-test-password')
    monkeypatch.setenv('LC_VAULT',str(key_path))
    initialize(state/'data',password_file,'urn:deployment:test','admin',tmp_path/'mfa.json')
    original=key_path.read_bytes()
    assert not (state/'data/vault.json').exists()
    with pytest.raises(ValueError,match='DATABASE_ALREADY_EXISTS'):
        initialize(state/'data',password_file,'urn:other','admin',tmp_path/'mfa2.json')
    assert key_path.read_bytes()==original
    assert create_app(state/'data').state.vault.data['issuer']=='urn:deployment:test'


def test_config_is_data_and_not_executable(tmp_path):
    config=tmp_path/'config.json'
    write_json(config,{'domain':'','issuer':'urn:test','auto_install_docker':False})
    assert read_config(config)['port']==18080
    write_json(config,{'domain':'$(touch /tmp/pwned)'})
    with pytest.raises(OperationError):read_config(config)
    write_json(config,{'token':'this-should-never-be-a-config-value'})
    with pytest.raises(OperationError):read_config(config)


def test_generated_compose_default_loopback_and_persistence(tmp_path):
    dep=Deployment(tmp_path/'deployment');dep.root.mkdir();(dep.root/'config').mkdir()
    config={'domain':'','port':18080}
    dep.render(config,Path('.'),'license-center-local:'+'a'*40,{'gateway_image':'caddy:2'})
    compose=json.loads(dep.compose_path.read_text())
    assert list(compose['services'])==['center']
    assert compose['services']['center']['ports']==['127.0.0.1:18080:8000']
    assert compose['services']['center']['environment']['LC_VAULT']=='/state/keys/vault.json'
    assert any('/state' in mount for mount in compose['services']['center']['volumes'])
    assert 'privileged' not in compose['services']['center']
