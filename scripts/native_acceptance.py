"""Real systemd acceptance on a disposable hosted Ubuntu VM. No Docker commands."""
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

import httpx

from center.security import totp
from scripts.native_ops import Native
from scripts.ops import commit_of, write_json
from sdk import LicenseClient


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.geteuid() != 0:
        raise SystemExit('DISPOSABLE_HOSTED_CI_ROOT_REQUIRED')
    source = Path(__file__).resolve().parents[1]
    checks, outputs = [], []
    with tempfile.TemporaryDirectory(prefix='lc-native-', dir='/opt') as temp:
        base = Path(temp)
        os.chmod(base, 0o755)
        root, target = base/'original', base/'restored'
        dep, restored = Native(root), Native(target)
        cfg = base/'install.json'
        # Fixed high ports are reserved only on the disposable VM.
        write_json(cfg, {'domain': '', 'port': 43871, 'secret_dir': str(base/'secrets')})
        def command(action, *args):
            entry_source = Path(dep.meta()['source']) if action == 'install' and dep.meta_path.exists() else source
            result = subprocess.run([sys.executable, str(entry_source/'scripts/deploy.py'), action,
                         '--mode', 'native', *map(str, args)], capture_output=True, text=True)
            outputs.append(result.stdout+result.stderr)
            if result.returncode:
                codes = []
                for line in result.stdout.splitlines():
                    try:
                        value = json.loads(line)
                        if isinstance(value, dict) and 'error' in value:
                            codes.append(value['error'])
                    except ValueError:
                        pass
                print(json.dumps({'failed': action, 'codes': codes}))
                raise RuntimeError('NATIVE_ACCEPTANCE_OPERATION_FAILED')
            return result.stdout
        client = None
        try:
            # Exercise the actual public pinned bootstrap, not a local install shortcut.
            initial = os.environ.get('LC_NATIVE_INITIAL_COMMIT', commit_of())
            bootstrap_bytes = urllib.request.urlopen('https://raw.githubusercontent.com/huang199800/license-center/'+initial+'/scripts/bootstrap.sh', timeout=30).read()
            assert hashlib.sha256(bootstrap_bytes).digest() == hashlib.sha256((source/'scripts/bootstrap.sh').read_bytes()).digest()
            bootstrap = base/'bootstrap.sh'
            bootstrap.write_bytes(bootstrap_bytes)
            result = subprocess.run(['bash', str(bootstrap), '--mode', 'native', '--ref', initial,
                '--commit', initial, '--root', str(root), '--config', str(cfg), '--non-interactive'],
                capture_output=True, text=True)
            outputs.append(result.stdout+result.stderr)
            if result.returncode:
                print(result.stdout)  # Installer exposes controlled error codes and public paths only.
                raise RuntimeError('NATIVE_PUBLIC_BOOTSTRAP_FAILED')
            checks.append('public_pinned_bootstrap_without_docker')
            config = dep.config()
            password = Path(config['admin_password_file']).read_text().strip()
            otp = json.loads((root/'exchange/admin-enrollment.json').read_text())['totp_secret']
            url = 'http://127.0.0.1:43871'
            login = httpx.post(url+'/v1/admin/login', json={'username': 'admin', 'password': password,
                           'otp': totp(otp, int(time.time())//30-1)})
            assert login.status_code == 200
            headers = {'Authorization': 'Bearer '+login.json()['access_token']}
            assert httpx.post(url+'/v1/admin/reauth', json={'otp': totp(otp)}, headers=headers).status_code == 200
            codes = httpx.post(url+'/v1/admin/codes', json={'plan': 'demo-month'}, headers=headers)
            assert codes.status_code == 200
            client = LicenseClient(url, 'demo', config['issuer'], httpx.get(url+'/v1/public-keys').json()['keys'],
                                   base/'client.json', allow_http=True).initialize()
            assert client.activate(codes.json()['delivery_once'][0]['code'], 'native-drill')['status'] == 'active'
            checks.append('admin_mfa_license_activation_signature')
            identity = (root/'state/keys/vault.json').read_bytes()
            command('install', '--root', root, '--config', cfg, '--non-interactive')
            assert identity == (root/'state/keys/vault.json').read_bytes()
            assert client.refresh()['status'] == 'active'
            command('restart', '--root', root)
            assert client.refresh()['status'] == 'active'
            checks.append('repeat_install_and_systemd_restart_persist')
            # Different pinned commit, same code/schema: validates real fetch, new venv and unit switch.
            next_commit = os.environ.get('LC_NATIVE_UPGRADE_COMMIT', commit_of())
            command('update', '--root', root, '--ref', next_commit, '--commit', next_commit)
            assert client.refresh()['status'] == 'active'
            assert dep.meta()['commit'] == next_commit
            checks.append('cross_commit_upgrade_preserves_license' if initial != next_commit else 'same_commit_redeploy_preserves_license')
            backup = base/'migration.lcb2'
            command('stop', '--root', root)
            command('backup', '--root', root, '--output', backup)
            recovery_cfg = base/'restore.json'
            write_json(recovery_cfg, {'port': 43872,
                'backup_password_file': config['backup_password_file'], 'key_password_file': config['key_password_file']})
            # Recovery must use the backup's exact source, including after a cross-commit update.
            recovery_source = Path(dep.meta()['source'])
            result = subprocess.run([sys.executable, str(recovery_source/'scripts/deploy.py'), 'restore',
                '--mode', 'native', '--root', str(target), '--config', str(recovery_cfg), '--bundle', str(backup),
                '--non-interactive', '--accept-stale-state'], capture_output=True, text=True)
            outputs.append(result.stdout+result.stderr)
            if result.returncode:
                print(result.stdout)
                raise RuntimeError('NATIVE_RESTORE_FAILED')
            client.close()
            client = LicenseClient('http://127.0.0.1:43872', 'demo', config['issuer'],
                httpx.get('http://127.0.0.1:43872/v1/public-keys').json()['keys'], base/'client.json', allow_http=True).initialize()
            assert client.refresh()['status'] == 'active'
            assert json.loads(identity) == json.loads((target/'state/keys/vault.json').read_bytes())
            checks.append('fresh_root_encrypted_restore_original_client_refresh')
            command('logs', '--root', target)
            combined = '\n'.join(outputs)
            for value in [password, otp, client.data['activation_secret'],
                          Path(config['backup_password_file']).read_text().strip(),
                          Path(config['key_password_file']).read_text().strip()]:
                assert value not in combined
            checks.append('install_upgrade_logs_no_secrets')
            command('uninstall', '--root', target)
            assert (target/'state/data/center.db').exists()
            assert (target/'state/keys/vault.json').exists()
            checks.append('uninstall_preserves_data_and_keys')
        finally:
            if client:
                client.close()
            for item in [dep, restored]:
                subprocess.run(['systemctl', 'disable', '--now', item.unit], capture_output=True)
                item.unit_path.unlink(missing_ok=True)
            subprocess.run(['systemctl', 'daemon-reload'], capture_output=True)
    print(json.dumps({'checks': checks, 'passed': len(checks), 'backend': 'native',
        'scope': 'real hosted Ubuntu systemd, isolated second directory; not two physical hosts'}))


if __name__ == '__main__':
    main()
