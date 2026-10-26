import json
import socket
from pathlib import Path, PurePosixPath

import pytest

from scripts.deploy import select
from scripts.native_ops import DEFAULT_PORT, check_port, config_file, unit_text
from scripts.ops import OperationError, write_json


def test_native_default_and_domain_does_not_request_web_ports(tmp_path):
    path = tmp_path/'settings.json'
    write_json(path, {'domain': 'license.example.com'})
    config = config_file(path)
    assert config['port'] == DEFAULT_PORT
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
        with pytest.raises(OperationError, match='REQUESTED_PORT_IN_USE_127.0.0.1_'+str(port)):
            check_port({**config, 'port': port})


def test_native_service_has_no_gateway_or_privileged_listener():
    text = unit_text(PurePosixPath('/opt/lc'), PurePosixPath('/opt/lc/runtimes/abc'), 'lc-abc', DEFAULT_PORT)
    assert 'LC_HOST=127.0.0.1' in text
    assert 'LC_PORT=43871' in text
    assert 'User=lc-abc' in text
    assert 'ProtectSystem=strict' in text
    assert 'ReadWritePaths=/opt/lc/state' in text
    assert 'docker' not in text.lower()
    with pytest.raises(OperationError):
        unit_text(Path('/opt/lc%bad'), Path('/opt/runtime'), 'lc-abc', DEFAULT_PORT)


def test_dispatch_preserves_existing_docker_and_rejects_in_place_backend_switch(tmp_path, monkeypatch):
    monkeypatch.delenv('LC_DEPLOY_MODE', raising=False)
    args = ['status', '--root', str(tmp_path)]
    assert select(args)[0] == 'native'
    write_json(tmp_path/'deployment.json', {'commit': 'example'})
    assert select(args)[0] == 'docker'
    with pytest.raises(ValueError):
        select([*args, '--mode', 'native'])
    write_json(tmp_path/'deployment.json', {'backend': 'native'})
    assert select(args)[0] == 'native'
