import json
import subprocess
from types import SimpleNamespace

import pytest

from scripts.ops import Deployment, OperationError, create_secrets, logs, run, write_json


def test_subprocess_failure_does_not_echo_untrusted_output(monkeypatch):
    monkeypatch.setattr(subprocess,'run',lambda *a,**k:SimpleNamespace(returncode=1,stdout='secret-example-do-not-log',stderr='secret-example-do-not-log'))
    with pytest.raises(OperationError) as result:run(['docker','something'])
    assert str(result.value)=='COMMAND_FAILED_DOCKER'
    assert 'secret-example' not in str(result.value)


def test_logs_only_emits_allowlisted_fields(capsys):
    output='\n'.join(['secret-example-do-not-log',json.dumps({'event':'request','method':'GET','route':'/health/ready','status':200,'ms':2.1,'Authorization':'secret-example-do-not-log'}),
                       json.dumps({'event':'request','method':'GET','route':'/path?token=secret-example-do-not-log','status':200,'ms':2.1})])
    dep=SimpleNamespace(dc=lambda *a,**k:SimpleNamespace(stdout=output))
    logs(dep)
    result=capsys.readouterr().out
    assert 'secret-example' not in result
    assert '/health/ready' in result
    assert 'Authorization' not in result


def test_random_secrets_are_distinct_and_outside_deployment(tmp_path):
    dep=Deployment(tmp_path/'deployment')
    config=create_secrets(dep,{'secret_dir':str(tmp_path/'protected')})
    values=[__import__('pathlib').Path(config[k]).read_text() for k in ['admin_password_file','backup_password_file','key_password_file']]
    assert len(set(values))==3
    assert all(len(v.strip())>=40 for v in values)
    with pytest.raises(OperationError):create_secrets(dep,{'secret_dir':str(tmp_path/'deployment/secrets')})
    with pytest.raises(OperationError):create_secrets(dep,{'secret_dir':str(tmp_path/'protected')})
